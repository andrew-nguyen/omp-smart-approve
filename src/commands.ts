/**
 * Operator commands: setup, status, rules, pending, review, apply-suggestion,
 * override, and the two bypass controls.
 *
 * Three invariants drive the shape of this module:
 *
 * 1. **Nothing here can widen the gate silently.** Every state change asks a
 *    human first — a confirmation for rules, a typed random challenge for an
 *    override or a bypass, and a second confirmation for a persistent allow.
 * 2. **A grant needs the literal call.** Authority to mint comes from the live
 *    in-memory broker, never from the durable record. When the arguments are
 *    gone, approval degrades to recorded intent and says so plainly.
 * 3. **Deny and expire never need raw arguments**, so a record stays fully
 *    actionable for its whole `pendingApprovalTtl` even after a restart.
 *
 * There is deliberately no configuration key and no environment variable that
 * disables the gate: `unguarded` is the only off switch, it is session-scoped,
 * and it leaves an audit trail.
 */

import path from "node:path";
import { grantAuthority, hasHumanChannel, heldCall, queueDepth } from "./broker.ts";
import {
	type ResolvedConfig,
	ruleSpecificity,
	type SmartApproveConfig,
	smartApproveConfigSchema,
	writableConfigPath,
} from "./config.ts";
import type { AuditEventType, GrantScope, PolicyRule, RuleKind, RuleSuggestion } from "./contracts.ts";
import { isExactTarget } from "./policy.ts";
import type { AuditAggregate, SmartApproveStore } from "./store.ts";
import {
	formatDuration,
	type ReviewInput,
	renderPendingList,
	renderReview,
	renderStatus,
	STATUS_KEY,
	type StatusInput,
	type UiHost,
	WIDGET_BYPASS,
} from "./ui.ts";

/** Everything an operator command changes is attributed to the person at the keyboard. */
const ACTOR = "human";

const AGGREGATE_WINDOW_MS = 24 * 60 * 60_000;

/** A persistent allow is long-lived, not eternal: policy drift should retire it. */
const PERSISTENT_GRANT_TTL_MS = 90 * 24 * 60 * 60_000;

export const SUBCOMMANDS: readonly string[] = [
	"setup",
	"status",
	"rules",
	"pending",
	"review",
	"apply-suggestion",
	"override",
	"unguarded",
	"guarded",
];

// ---------------------------------------------------------------------------
// Dependencies
// ---------------------------------------------------------------------------

export interface CommandDeps {
	resolved: ResolvedConfig;
	store: SmartApproveStore;
	ui: UiHost;
	now(): number;
	randomId(): string;
	/** Typed challenge string the human must retype for destructive operations. */
	randomChallenge(): string;
	/** Recompute the canonical hash from literal args; injected so commands never import policy internals directly. */
	recomputeHash(args: Readonly<Record<string, unknown>>): string;
	/** Session-scoped bypass state, owned by index.ts. */
	bypass: { active(): boolean; enable(reason: string): void; disable(): void };
	/**
	 * Model listing for `setup`. `list()` is OMP's authenticated-model set — the
	 * same one `--model` selection sees — so setup never offers a model the
	 * session cannot actually authenticate.
	 */
	models: {
		list(): { id: string; provider: string }[];
		current(): { id: string; provider: string } | undefined;
		family(m: { id: string; provider: string }): string;
	};
	/** Persist a config patch atomically. Returns the written path. */
	writeConfig(patch: Record<string, unknown>): Promise<string>;
}

export interface CommandResult {
	lines: string[];
}

// ---------------------------------------------------------------------------
// In-memory judge suggestions
// ---------------------------------------------------------------------------

/**
 * Judge suggestions are advisory and are never persisted, so they live here for
 * the process lifetime only. `apply-suggestion` therefore cannot resurrect a
 * proposal from a prior session — a restart means the judge must propose again.
 */
const SUGGESTIONS = new Map<string, RuleSuggestion>();
const MAX_SUGGESTIONS = 200;

export function recordSuggestion(auditId: string, suggestion: RuleSuggestion): void {
	SUGGESTIONS.set(auditId, suggestion);
	while (SUGGESTIONS.size > MAX_SUGGESTIONS) {
		const oldest = SUGGESTIONS.keys().next();
		if (oldest.done === true) break;
		SUGGESTIONS.delete(oldest.value);
	}
}

export function pendingSuggestion(auditId: string): RuleSuggestion | undefined {
	return SUGGESTIONS.get(auditId);
}

/** Dropped on session shutdown, and by tests between cases. */
export function clearSuggestions(): void {
	SUGGESTIONS.clear();
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/**
 * Operator actions that are not attached to a gated call still belong in the
 * append-only log, and `audit_events` has a foreign key to `audit_calls`. Open a
 * synthetic audit row for them so the trail is complete and referentially valid.
 */
function recordOperatorEvent(deps: CommandDeps, type: AuditEventType, operation: string, detail: string): string {
	const auditId = deps.randomId();
	const at = deps.now();
	const emptyHash = deps.recomputeHash({});
	deps.store.beginAudit({
		auditId,
		toolCallId: auditId,
		toolName: "smart-approve",
		cwd: deps.resolved.paths.cwd,
		operation,
		targetSummary: `operator command: ${operation}`,
		argumentsHash: emptyHash,
		canonicalHash: emptyHash,
		policyHash: deps.resolved.policyHash,
		sourceAgentId: ACTOR,
		sourceAgentKind: "main",
		retryFamilyKey: `operator:${operation}`,
		createdAt: at,
	});
	deps.store.appendEvent({ auditId, type, detail, actor: ACTOR, at });
	return auditId;
}

/** Posture for the kinds whose behavior does not depend on how complete the rule is. */
const RULE_POSTURE: Record<Exclude<RuleKind, "allow-exact">, string> = {
	"allow-pattern": "posture hint only — never skips the judge",
	"deny-exact": "exact deny — blocks before any model call",
	"deny-pattern": "patterned deny — blocks before any model call",
	posture: "posture hint only — never skips the judge",
};

/**
 * What this rule will actually do, derived from the same predicate
 * {@link matchExactAllow} applies — never from `kind` alone.
 *
 * An `allow-exact` qualifies to skip the judge only when it is exact AND pins
 * the literal call AND names an absolute working directory AND was written by a
 * human into the user-scope file. Labelling every `allow-exact` as a judge
 * bypass would tell an operator the gate is open on a rule that is in fact
 * advisory, which is precisely the misreading this command exists to prevent.
 *
 * Keep this list in step with `matchExactAllow`; it is the operator-facing half
 * of the same decision.
 */
export function rulePosture(rule: PolicyRule): string {
	if (rule.kind !== "allow-exact") return RULE_POSTURE[rule.kind];
	const missing: string[] = [];
	if (!isExactTarget(rule.target)) missing.push("target is a pattern");
	if (rule.argumentsHash === undefined) missing.push("no argumentsHash");
	if (rule.cwd === undefined) missing.push("no cwd");
	else if (!path.isAbsolute(rule.cwd)) missing.push("cwd is not absolute");
	if (rule.createdBy === "project") missing.push("project-scope file");
	return missing.length === 0
		? "exact allow — skips the judge for this precise call in this directory"
		: `advisory posture — still judged (${missing.join(", ")})`;
}

/** How `rules show` renders `cwd`, naming the reason a value cannot bind a location. */
function cwdField(rule: PolicyRule): string {
	if (rule.cwd === undefined) return "(absent — cannot skip the judge)";
	if (!path.isAbsolute(rule.cwd)) return `${rule.cwd} (relative — cannot skip the judge)`;
	return rule.cwd;
}

/**
 * Grant scopes an operator may pick, narrowest first. Labels are the select wire
 * format, so they are part of the contract.
 *
 * `ttlMs` is the single source of a scope's lifetime: the duration a human reads
 * in the dialog and the expiry the grant is minted with both come from it, so the
 * number on screen cannot drift from the number in the database.
 *
 * Scope chooses lifetime and nothing else. Every grant is single-use whatever the
 * scope, because the gate admits a call by *consuming* the grant.
 */
export const GRANT_SCOPE_OPTIONS: ReadonlyArray<{
	label: string;
	scope: GrantScope;
	ttlMs: (timeouts: SmartApproveConfig["timeouts"]) => number;
	/** Why the lifetime is what it is, in the operator's terms. */
	lifetime: string;
}> = [
	{
		label: "One time",
		scope: "one-time",
		ttlMs: timeouts => timeouts.brokerArgsTtlMs,
		lifetime: "lapses with the in-memory call",
	},
	{
		label: "This session",
		scope: "session",
		ttlMs: timeouts => timeouts.pendingApprovalTtlMs,
		lifetime: "lapses with the pending-approval TTL",
	},
	{
		label: "Persistent",
		scope: "persistent",
		ttlMs: () => PERSISTENT_GRANT_TTL_MS,
		lifetime: "survives restarts",
	},
];

/** Override actions. Labels are the select wire format, so they are part of the contract. */
export const OVERRIDE_DENY = "Deny";
export const OVERRIDE_EXPIRE = "Expire";
export const OVERRIDE_APPROVE = "Approve this exact call";

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export function createCommands(deps: CommandDeps): {
	run(argv: string): Promise<CommandResult>;
	subcommands: string[];
} {
	return {
		subcommands: [...SUBCOMMANDS],
		async run(argv: string): Promise<CommandResult> {
			const tokens = argv.trim().split(/\s+/).filter(Boolean);
			const [subcommand, ...rest] = tokens;
			switch (subcommand) {
				case undefined:
					return { lines: usage() };
				case "setup":
					return await setup(deps);
				case "status":
					return status(deps);
				case "rules":
					return await rules(deps, rest);
				case "pending":
					return pending(deps);
				case "review":
					return requireId(rest[0], "review", id => review(deps, id));
				case "apply-suggestion":
					return await requireId(rest[0], "apply-suggestion", id => applySuggestion(deps, id));
				case "override":
					return await requireId(rest[0], "override", id => override(deps, id));
				case "unguarded":
					return await unguarded(deps);
				case "guarded":
					return guarded(deps);
				default:
					return { lines: [`Unknown subcommand \`${subcommand}\`.`, ...usage()] };
			}
		},
	};
}

function usage(): string[] {
	return [
		"Usage: /smart-approve <subcommand>",
		"  setup                     configure an authorized judge model",
		"  status                    configuration, health, and recent activity",
		"  rules [list|show|revoke]  inspect and revoke deterministic rules",
		"  pending                   open escalations awaiting a human",
		"  review <audit-id>         one call's verdict, history, and options",
		"  apply-suggestion <id>     apply a judge-proposed rule after confirmation",
		"  override <audit-id>       approve, deny, or expire a blocked call",
		"  unguarded                 stop judging unattended calls, this session only",
		"  guarded                   resume judging immediately",
	];
}

function requireId<T>(id: string | undefined, name: string, run: (id: string) => T): T | CommandResult {
	if (id === undefined)
		return { lines: [`\`${name}\` needs an audit ID. Run \`/smart-approve pending\` to list them.`] };
	return run(id);
}

// ---------------------------------------------------------------------------
// setup
// ---------------------------------------------------------------------------

async function setup(deps: CommandDeps): Promise<CommandResult> {
	const models = deps.models.list();
	if (models.length === 0) {
		return {
			lines: [
				"SMART APPROVE SETUP",
				"",
				"No model in this session has configured authentication.",
				"Smart Approve never ships its own credentials, never reads a separate credential",
				"store, and never falls back to the primary session model.",
				"",
				"Authenticate a provider in OMP first, then run `/smart-approve setup` again.",
				"Nothing was written.",
			],
		};
	}

	const current = deps.models.current();
	const currentFamily = current === undefined ? undefined : deps.models.family(current);
	const contrasting =
		currentFamily === undefined ? undefined : models.find(model => deps.models.family(model) !== currentFamily);
	const recommended = contrasting ?? models[0];
	if (recommended === undefined) return { lines: ["No model available. Nothing was written."] };
	const specOf = (model: { id: string; provider: string }): string => `${model.provider}/${model.id}`;
	const recommendedSpec = specOf(recommended);
	const rest = models.filter(model => specOf(model) !== recommendedSpec);
	const options = [recommended, ...rest].map(model => ({
		label: specOf(model),
		description:
			specOf(model) === recommendedSpec
				? `family ${deps.models.family(model)} — recommended${
						contrasting === undefined ? "" : ": differs from the session model's family"
					}`
				: `family ${deps.models.family(model)}`,
	}));

	const previewPath = writableConfigPath(deps.resolved.paths);
	const budget = deps.resolved.budget;
	const timeouts = deps.resolved.config.timeouts;

	const preview: string[] = [
		"SMART APPROVE SETUP",
		"",
		`Authenticated models (${models.length}):`,
		...models.map(model => `  ${model.provider}/${model.id}  (family ${deps.models.family(model)})`),
		"",
		`Session model: ${current === undefined ? "(none)" : `${current.provider}/${current.id}`}${
			currentFamily === undefined ? "" : ` (family ${currentFamily})`
		}`,
		`Recommended judge: ${recommendedSpec}`,
		contrasting === undefined
			? "  No authorized model from a different family is available; this one shares the session family."
			: "  Chosen because its family differs from the session model, so one model's blind spot is not both.",
		"",
		`Config file: ${previewPath}`,
		"Timeout budget:",
		`  ${timeouts.attempts} attempt(s) x ${timeouts.modelTimeoutMs} ms + ${timeouts.cleanupMarginMs} ms cleanup` +
			` = ${budget.worstCaseJudgeSpendMs} ms worst case`,
		`  handler self-deadline ${budget.effectiveDeadlineMs} ms (OMP caps the handler at 30000 ms)`,
		`  dialog window ${budget.worstCaseDialogWindowMs}-${budget.bestCaseDialogWindowMs} ms` +
			(budget.fastPathStructurallyUnreachable ? " (too short to prompt; escalation is always asynchronous)" : ""),
	];

	// The picker is the consent step: an operator may authorize any authenticated
	// model, not just the recommended one. A cancel — or a label that was never
	// offered — is no consent to anything, so both land on the same no-write path.
	const chosenLabel = await deps.ui.select("Choose the judge model", options);
	const chosen = chosenLabel === undefined ? undefined : models.find(model => specOf(model) === chosenLabel);
	if (chosen === undefined) {
		return { lines: [...preview, "", "Cancelled. Nothing was written."] };
	}
	const spec = specOf(chosen);

	const confirmed = await deps.ui.confirm(
		"Smart Approve setup",
		`Write judge.authorizedModels = ["${spec}"] to ${previewPath}?`,
	);
	if (!confirmed) {
		return { lines: [...preview, "", `Selected judge: ${spec}`, "", "Cancelled. Nothing was written."] };
	}

	const written = await deps.writeConfig({ judge: { authorizedModels: [spec] } });
	return {
		lines: [
			...preview,
			"",
			`Selected judge: ${spec}`,
			"",
			`Wrote ${written}`,
			"Run `/smart-approve status` to confirm the gate is armed.",
		],
	};
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

function status(deps: CommandDeps): CommandResult {
	const now = deps.now();
	const authorized = deps.resolved.config.judge.authorizedModels;
	const available = new Set(deps.models.list().map(model => `${model.provider}/${model.id}`));
	const usable = authorized.filter(spec => available.has(spec));

	let detail: string;
	if (usable.length > 0) detail = `${usable.length} of ${authorized.length} authorized model(s) available with auth`;
	else if (authorized.length === 0) detail = "no judge model authorized — run `/smart-approve setup`";
	else detail = `authorized models are not available in this session: ${authorized.join(", ")}`;

	// Left undefined on failure, never defaulted to zero: `status` is where an
	// operator checks whether anything is waiting, and a fabricated zero there
	// reads as "all clear" at the exact moment nothing is known.
	let aggregate: AuditAggregate | undefined;
	let openPending: number | undefined;
	let healthy = true;
	let dbDetail: string | undefined;
	try {
		deps.store.expirePending(now);
		openPending = deps.store.listOpenPending(now).length;
		aggregate = deps.store.aggregate(now - AGGREGATE_WINDOW_MS, now);
	} catch (error) {
		healthy = false;
		dbDetail = error instanceof Error ? error.message : String(error);
	}

	const input: StatusInput = {
		resolved: deps.resolved,
		judge: {
			authorizedModels: authorized,
			...(usable[0] === undefined ? {} : { selected: usable[0] }),
			authHealthy: usable.length > 0,
			detail,
		},
		broker: { humanChannel: hasHumanChannel(), queueDepth: queueDepth() },
		mainUi: deps.ui.hasUI,
		bypassActive: deps.bypass.active(),
		database: {
			path: deps.resolved.databasePath,
			healthy,
			...(dbDetail === undefined ? {} : { detail: dbDetail }),
		},
		...(openPending === undefined ? {} : { openPending }),
		...(aggregate === undefined ? {} : { aggregate }),
		aggregateWindowMs: AGGREGATE_WINDOW_MS,
		now,
	};
	return { lines: renderStatus(input) };
}

// ---------------------------------------------------------------------------
// rules
// ---------------------------------------------------------------------------

async function rules(deps: CommandDeps, args: string[]): Promise<CommandResult> {
	const action = args[0] ?? "list";
	const stored = deps.store.listRules();
	const configured = deps.resolved.rules;

	if (action === "list") {
		const lines: string[] = ["SMART APPROVE RULES", ""];
		for (const group of [
			{ origin: "config", label: "From configuration", entries: configured },
			{ origin: "store", label: "Stored in the audit database", entries: stored },
		]) {
			lines.push(`${group.label} (${group.entries.length}):`);
			if (group.entries.length === 0) lines.push("  (none)");
			for (const rule of group.entries) {
				lines.push(
					`  ${rule.id}  [${rule.kind}]  ${group.origin}`,
					`    ${rule.toolName} -> ${rule.target}  (${rulePosture(rule)})`,
					`    specificity ${rule.specificity}, by ${rule.createdBy}: ${rule.reason}`,
				);
			}
			lines.push("");
		}
		lines.push(
			"An allow skips the judge only when it is exact AND pins the call with an",
			"argumentsHash AND names an absolute cwd AND comes from the user-scope",
			"configuration. Omit any one and it is advisory posture: the call is still",
			"judged. Use `rules show <id>` to see which condition is missing.",
		);
		return { lines };
	}

	if (action === "show") {
		const id = args[1];
		if (id === undefined) return { lines: ["`rules show` needs a rule ID."] };
		const rule = stored.find(r => r.id === id) ?? configured.find(r => r.id === id);
		if (rule === undefined) return { lines: [`No rule with ID ${id}.`] };
		return {
			lines: [
				`Rule ${rule.id}`,
				`  kind:        ${rule.kind}`,
				`  posture:     ${rulePosture(rule)}`,
				`  tool:        ${rule.toolName}`,
				`  target:      ${rule.target}${isExactTarget(rule.target) ? " (exact)" : " (pattern)"}`,
				`  argsHash:    ${rule.argumentsHash ?? "(absent — cannot skip the judge)"}`,
				`  cwd:         ${cwdField(rule)}`,
				`  operation:   ${rule.operation ?? "(any)"}`,
				`  risk:        ${rule.risk ?? "(any)"}`,
				`  sensitivity: ${rule.sensitivity ?? "(inherit)"}`,
				`  specificity: ${rule.specificity}`,
				`  created by:  ${rule.createdBy}${rule.createdBy === "project" ? " (project scope never skips the judge)" : ""}`,
				`  source:      ${rule.source ?? "(unknown)"}`,
				`  reason:      ${rule.reason}`,
			],
		};
	}

	if (action === "revoke") {
		const id = args[1];
		if (id === undefined) return { lines: ["`rules revoke` needs a rule ID."] };
		const rule = stored.find(r => r.id === id);
		if (rule === undefined) {
			const fromConfig = configured.find(r => r.id === id);
			return {
				lines:
					fromConfig === undefined
						? [`No stored rule with ID ${id}.`]
						: [
								`Rule ${id} comes from ${fromConfig.source ?? "configuration"} and cannot be revoked here.`,
								"Edit the configuration file to remove it.",
							],
			};
		}
		const confirmed = await deps.ui.confirm(
			"Revoke rule",
			`Revoke ${rule.kind} rule ${rule.id} (${rule.toolName} -> ${rule.target})?\n` +
				"Every outstanding allow grant is invalidated at the same time, in this and every\n" +
				"other working directory. Deny rules are untouched.",
		);
		if (!confirmed) return { lines: [`Cancelled. Rule ${id} is unchanged.`] };

		const removed = deps.store.revokeRule(id);
		// Grants bind to an exact call hash, not to a rule, so there is no way to
		// match them selectively. This is an explicit safety lever, so it clears
		// every grant everywhere rather than only this directory's: over-revoking
		// costs one re-approval, while leaving a grant live in another checkout
		// after the human revoked the rule they believed authorized it would not.
		// The automatic session-start sweep is cwd-scoped for the opposite reason.
		const invalidated = deps.store.revokeAllGrants(deps.now());
		const auditId = recordOperatorEvent(
			deps,
			"revoked",
			"rule-revoke",
			`revoked rule ${id} (${rule.kind} ${rule.toolName} -> ${rule.target}); invalidated ${invalidated} grant(s)`,
		);
		return {
			lines: [
				removed ? `Revoked rule ${id}.` : `Rule ${id} was already gone.`,
				`Invalidated ${invalidated} outstanding allow grant(s), across every working directory.`,
				"Deny rules are untouched and spent grants stay in the audit history.",
				`Audit ID: ${auditId}`,
			],
		};
	}

	return { lines: [`Unknown \`rules\` action \`${action}\`. Use list, show, or revoke.`] };
}

// ---------------------------------------------------------------------------
// pending
// ---------------------------------------------------------------------------

function pending(deps: CommandDeps): CommandResult {
	const now = deps.now();
	deps.store.expirePending(now);
	return { lines: renderPendingList(deps.store.listOpenPending(now), now) };
}

// ---------------------------------------------------------------------------
// review
// ---------------------------------------------------------------------------

function review(deps: CommandDeps, auditId: string): CommandResult {
	const now = deps.now();
	const committed = deps.store.getAudit(auditId);
	const escalation = deps.store.getPending(auditId);
	const events = deps.store.listEvents(auditId);
	if (committed === undefined && escalation === undefined && events.length === 0) {
		return { lines: [`No Smart Approve record for audit ID ${auditId}.`] };
	}

	const argumentsHash = escalation?.argumentsHash ?? committed?.argumentsHash ?? "";
	const authority = grantAuthority(auditId, argumentsHash, now, deps.recomputeHash);
	// The live broker is the only source of literal arguments anywhere in this module.
	const frozen = heldCall(auditId, now);
	const familyKey = committed?.retryFamilyKey;
	const suggestion = pendingSuggestion(auditId);

	const input: ReviewInput = {
		auditId,
		...(committed === undefined ? {} : { record: committed }),
		...(escalation === undefined ? {} : { pending: escalation }),
		events,
		...(familyKey === undefined ? {} : { retryFamilyKey: familyKey }),
		strikes: familyKey === undefined ? 0 : deps.store.getStrikes(familyKey),
		...(suggestion === undefined ? {} : { suggestion }),
		authority,
		...(frozen === undefined ? {} : { frozenCall: frozen }),
		now,
	};
	return { lines: renderReview(input) };
}

// ---------------------------------------------------------------------------
// apply-suggestion
// ---------------------------------------------------------------------------

async function applySuggestion(deps: CommandDeps, auditId: string): Promise<CommandResult> {
	const suggestion = pendingSuggestion(auditId);
	if (suggestion === undefined) {
		return {
			lines: [
				`No live judge suggestion for audit ID ${auditId}.`,
				"Suggestions are held in memory only and never persisted, so a restart clears them.",
			],
		};
	}

	// A model-proposed allow with any pattern operator is downgraded to posture.
	// Confirmation cannot promote it: the human is confirming a rule, not a bypass.
	const downgraded = suggestion.kind === "allow-exact" && !isExactTarget(suggestion.target);
	const kind: RuleKind = downgraded ? "allow-pattern" : suggestion.kind;
	const id = `suggested-${auditId}`;
	const reason = `judge suggestion from ${auditId}: ${suggestion.rationale}`;

	const parsed = smartApproveConfigSchema.safeParse({
		rules: [{ id, kind, tool: suggestion.toolName, target: suggestion.target, reason }],
	});
	if (!parsed.success) {
		return {
			lines: [
				`The suggested rule for ${auditId} does not validate and was not inserted.`,
				...parsed.error.issues.map(issue => `  ${issue.path.join(".") || "(root)"}: ${issue.message}`),
			],
		};
	}

	const specificity = ruleSpecificity({ kind, target: suggestion.target });
	const preview: string[] = [
		`Judge suggestion for ${auditId}`,
		`  proposed:    ${suggestion.kind} ${suggestion.toolName} -> ${suggestion.target}`,
		`  normalized:  ${kind} ${suggestion.toolName} -> ${suggestion.target}`,
		// Built from the same fields the rule would be inserted with, so a
		// judge-suggested allow honestly reads as advisory: a suggestion can never
		// carry an argumentsHash or a cwd, and therefore can never mint a bypass.
		`  posture:     ${rulePosture({
			id: suggestion.toolName,
			kind,
			toolName: suggestion.toolName,
			target: suggestion.target,
			reason: suggestion.rationale,
			createdBy: "human-override",
			specificity,
		})}`,
		`  specificity: ${specificity}`,
		`  rationale:   ${suggestion.rationale}`,
	];
	if (downgraded) {
		preview.push(
			"  NOTE: the model proposed an exact allow whose target contains a pattern operator.",
			"  It was downgraded to a posture hint and still cannot skip the judge.",
		);
	}

	const confirmed = await deps.ui.confirm("Apply judge suggestion", `${preview.join("\n")}\n\nInsert this rule?`);
	if (!confirmed) return { lines: [...preview, "", "Cancelled. No rule was inserted."] };

	const rule: PolicyRule = {
		id,
		kind,
		toolName: suggestion.toolName,
		target: suggestion.target,
		reason,
		createdBy: "human-override",
		specificity,
		source: `judge-suggestion:${auditId}`,
	};
	deps.store.putRule(rule);

	const linked = deps.store.getAudit(auditId) !== undefined || deps.store.getPending(auditId) !== undefined;
	if (linked) {
		deps.store.appendEvent({
			auditId,
			type: "overridden",
			detail: `applied judge suggestion as ${kind} rule ${id}`,
			actor: ACTOR,
			at: deps.now(),
		});
	} else {
		recordOperatorEvent(deps, "overridden", "apply-suggestion", `applied judge suggestion ${id} for ${auditId}`);
	}

	return { lines: [...preview, "", `Inserted rule ${id}.`] };
}

// ---------------------------------------------------------------------------
// override
// ---------------------------------------------------------------------------

async function override(deps: CommandDeps, auditId: string): Promise<CommandResult> {
	const now = deps.now();
	deps.store.expirePending(now);
	const record = deps.store.getPending(auditId);
	if (record === undefined) {
		return {
			lines: [
				`No Smart Approve escalation with audit ID ${auditId}.`,
				"Run `/smart-approve pending` to list records that are still open.",
			],
		};
	}
	if (record.state !== "awaiting-human" && record.state !== "approved-intent") {
		return {
			lines: [`Audit ${auditId} is already resolved (${record.state}). The original verdict is immutable.`],
		};
	}
	if (record.expiresAt <= now) {
		return { lines: [`Audit ${auditId} passed its pending-approval TTL and can no longer be actioned.`] };
	}

	const committed = deps.store.getAudit(auditId);
	const lines: string[] = [
		`OVERRIDE ${auditId}`,
		"",
		"Original verdict (append-only; nothing below rewrites it):",
		committed === undefined
			? `  ${record.state} — ${record.rationale}`
			: `  ${committed.decision} at stage ${committed.stage} — ${committed.rationale}`,
		`  risk:   ${record.risk}`,
		`  tool:   ${record.toolName} ${record.operation}`,
		`  target: ${record.targetSummary}`,
		`  agent:  ${record.sourceAgentId}`,
		"",
	];

	const action = await deps.ui.select(`Override ${auditId}`, [
		{ label: OVERRIDE_DENY, description: "Confirm the block. Available without the literal arguments." },
		{ label: OVERRIDE_EXPIRE, description: "Close the record with no decision." },
		{ label: OVERRIDE_APPROVE, description: "Approve this exact call." },
	]);
	if (action === undefined) {
		lines.push("Cancelled. Nothing changed.");
		return { lines };
	}

	const challenge = deps.randomChallenge();
	const typed = await deps.ui.input(`Type ${challenge} to confirm this override`, challenge);
	if (typed !== challenge) {
		deps.store.appendEvent({
			auditId,
			type: "blocked",
			detail: `override challenge failed for action "${action}"`,
			actor: ACTOR,
			at: now,
		});
		lines.push("Challenge did not match. Nothing changed.");
		return { lines };
	}

	if (action === OVERRIDE_DENY) {
		deps.store.updatePendingState(auditId, "denied", now);
		deps.store.appendEvent({ auditId, type: "denied", detail: "human denied via override", actor: ACTOR, at: now });
		lines.push("Denied. The block stands and the record is closed.");
		return { lines };
	}

	if (action === OVERRIDE_EXPIRE) {
		deps.store.updatePendingState(auditId, "expired", now);
		deps.store.appendEvent({ auditId, type: "expired", detail: "human expired the record", actor: ACTOR, at: now });
		lines.push("Expired. The record is closed and can no longer be approved.");
		return { lines };
	}

	const reasonInput = await deps.ui.input("Reason for this override", "why this exact call is safe");
	const reason = reasonInput === undefined || reasonInput.trim() === "" ? "(no reason given)" : reasonInput.trim();

	const authority = grantAuthority(auditId, record.argumentsHash, now, deps.recomputeHash);
	if (authority.kind === "intent-only") {
		deps.store.updatePendingState(auditId, "approved-intent", now);
		deps.store.appendEvent({
			auditId,
			type: "intent-recorded",
			detail: `intent to approve recorded (${authority.reason}); challenge ok; reason: ${reason}`,
			actor: ACTOR,
			at: now,
		});
		lines.push(
			"No grant was minted.",
			`The literal frozen arguments are gone: ${authority.reason}.`,
			"Recorded intent to approve only — nothing is authorized to run right now.",
			"The next materially identical call re-opens a live approval dialog with the real",
			"arguments. With no interactive main session it stays blocked.",
		);
		return { lines };
	}

	if (record.policyHash !== deps.resolved.policyHash) {
		lines.push(
			"Configuration or policy changed since this call was blocked, so no grant can be minted.",
			`  record policy: ${record.policyHash}`,
			`  current policy: ${deps.resolved.policyHash}`,
			"Re-run the call to get a fresh decision under the current policy.",
		);
		return { lines };
	}

	const timeouts = deps.resolved.config.timeouts;
	const scopeLabel = await deps.ui.select(
		`Grant scope for ${auditId}`,
		GRANT_SCOPE_OPTIONS.map(option => ({
			label: option.label,
			// Single use is not a property of the narrow scopes: the gate consumes
			// whichever grant admits a call, so scope only chooses the lifetime of a
			// grant nothing has used yet.
			description: `Single use; ${option.lifetime} (${formatDuration(option.ttlMs(timeouts))}).`,
		})),
	);
	const selected = GRANT_SCOPE_OPTIONS.find(option => option.label === scopeLabel);
	if (selected === undefined) {
		lines.push("No scope chosen. Nothing was granted.");
		return { lines };
	}

	if (selected.scope === "persistent") {
		const second = await deps.ui.confirm(
			"Persistent allow",
			`A persistent grant survives restarts and stays usable for ${formatDuration(selected.ttlMs(timeouts))}` +
				` unless something consumes it first. Confirm a persistent allow for ${auditId}?`,
		);
		if (!second) {
			lines.push("A persistent allow needs a second explicit confirmation. Nothing was granted.");
			return { lines };
		}
	}

	const expiresAt = now + selected.ttlMs(timeouts);

	deps.store.putGrant({
		id: deps.randomId(),
		auditId,
		argumentsHash: authority.frozenCall.argumentsHash,
		canonicalHash: record.canonicalHash,
		// The location the human approved from. Without it the grant would admit a
		// byte-identical call in any other checkout sharing this database.
		cwd: record.cwd || deps.resolved.paths.cwd,
		policyHash: deps.resolved.policyHash,
		scope: selected.scope,
		expiresAt,
		createdBy: ACTOR,
		reason,
	});
	deps.store.updatePendingState(auditId, "approved-granted", now);
	deps.store.appendEvent({
		auditId,
		type: "overridden",
		detail: `challenge ok; scope ${selected.scope}; reason: ${reason}`,
		actor: ACTOR,
		at: now,
	});
	deps.store.appendEvent({
		auditId,
		type: "granted",
		detail: `exact grant bound to call hash ${authority.frozenCall.argumentsHash}, expires ${new Date(expiresAt).toISOString()}`,
		actor: ACTOR,
		at: now,
	});

	lines.push(
		`Granted a ${selected.scope} allow bound to call hash ${authority.frozenCall.argumentsHash}.`,
		`Single use: the first matching call consumes it. Unused, it expires ${new Date(expiresAt).toISOString()}.`,
		"Any change to the arguments, the working directory, the configuration, or the policy invalidates it.",
		`Reason recorded: ${reason}`,
	);
	return { lines };
}

// ---------------------------------------------------------------------------
// bypass
// ---------------------------------------------------------------------------

async function unguarded(deps: CommandDeps): Promise<CommandResult> {
	const challenge = deps.randomChallenge();
	const typed = await deps.ui.input(`Type ${challenge} to stop judging unattended calls in this session`, challenge);
	if (typed !== challenge) {
		return {
			lines: [
				"Challenge did not match. Smart Approve stays on.",
				"There is no configuration key and no environment variable that disables it.",
			],
		};
	}

	const reasonInput = await deps.ui.input("Why are you turning judging off?", "reason");
	const reason = reasonInput === undefined || reasonInput.trim() === "" ? "(no reason given)" : reasonInput.trim();
	deps.bypass.enable(reason);

	deps.ui.setWidget(WIDGET_BYPASS, [
		"!! SMART APPROVE IS UNGUARDED !!",
		"Calls OMP would run unattended are no longer judged.",
		"Deny rules and protected targets still block.",
		`Reason: ${reason}`,
		"This applies to the current session only. Re-enable with `/smart-approve guarded`.",
	]);
	deps.ui.setStatus(STATUS_KEY, "UNGUARDED — calls OMP would run unattended are not judged");
	deps.ui.notify("Smart Approve is UNGUARDED for this session.", "error");

	const auditId = recordOperatorEvent(deps, "bypass-enabled", "bypass", `session bypass enabled; reason: ${reason}`);
	return {
		lines: [
			"Smart Approve is UNGUARDED for this session.",
			"Calls OMP would run unattended are no longer judged.",
			"Still enforced: deny rules, protected targets, and the pre-screen on calls OMP prompts about.",
			"The bypass ends when this session ends.",
			`Reason: ${reason}`,
			`Audit ID: ${auditId}`,
			"Re-enable immediately with `/smart-approve guarded`.",
		],
	};
}

function guarded(deps: CommandDeps): CommandResult {
	const wasActive = deps.bypass.active();
	deps.bypass.disable();
	deps.ui.setWidget(WIDGET_BYPASS, undefined);
	deps.ui.setStatus(STATUS_KEY, undefined);
	if (!wasActive) return { lines: ["Smart Approve was already guarded. Nothing changed."] };

	deps.ui.notify("Smart Approve is guarded again.", "info");
	const auditId = recordOperatorEvent(deps, "bypass-disabled", "bypass", "session bypass disabled");
	return {
		lines: ["Smart Approve is guarded again. Every scoped call is screened.", `Audit ID: ${auditId}`],
	};
}
