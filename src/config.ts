/**
 * Layered configuration, policy discovery, and the deadline invariant.
 *
 * Three rules govern this module:
 *
 * 1. **Unknown keys are rejected.** A misspelled security setting must not silently
 *    weaken the gate, so every object in the schema is `strict()`.
 * 2. **Invalid timing fails closed with the exact fields.** Timeouts are never
 *    clamped into validity — a config that cannot finish inside OMP's handler cap
 *    is an error the operator must fix, not something to paper over.
 * 3. **Only explicit local configuration can relax the default posture.** Project
 *    files may add restrictions; widening scope or sensitivity requires the user
 *    to have written it themselves.
 */

import { createHash } from "node:crypto";
import { existsSync, realpathSync } from "node:fs";
import path from "node:path";
import { z } from "zod";
import type { PolicyRule, SensitivityLevel } from "./contracts.ts";
import { RISK_CLASSES, SENSITIVITY_LEVELS, TAXONOMY_VERSION } from "./contracts.ts";

/** Bumped when the config shape changes incompatibly. Part of the policy hash. */
export const CONFIG_SCHEMA_VERSION = 1;

/** OMP hard-caps a tool_call handler here. Our budget must close strictly inside it. */
export const OMP_HANDLER_CAP_MS = 30_000;
/** Absolute ceiling for the self-deadline, leaving a margin under the host cap. */
export const MAX_SELF_DEADLINE_MS = 29_000;

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const sensitivitySchema = z.enum(SENSITIVITY_LEVELS);
const riskSchema = z.enum(RISK_CLASSES);

/**
 * One token of an `allow-command` prefix. Whitespace and shell metacharacters are
 * rejected at load time: argv tokens never contain either, so a rule spelled
 * `["git log"]` or `["git", "log; curl"]` could only ever be a mistake — and it
 * would be a silent one, since it can never match a parsed token.
 */
const commandTokenSchema = z
	.string()
	.min(1)
	.regex(/^[^\s;&|<>$`(){}[\]*?~!#\\'"]+$/, "must be one literal argv token with no shell metacharacters");

const ruleSchema = z
	.object({
		id: z.string().min(1),
		kind: z.enum(["allow-exact", "allow-command", "allow-pattern", "deny-exact", "deny-pattern", "posture"]),
		tool: z.string().min(1),
		/** Canonical target, or a glob/regex for pattern kinds. Unused by `allow-command`. */
		target: z.string().min(1).optional(),
		/**
		 * Literal argv prefix for an `allow-command` rule: `[git, log]` admits
		 * `git log --oneline -n 20` and nothing that is not a single plain command.
		 *
		 * This is the one allow that matches a family rather than a pinned call, so
		 * it carries its own screens (`src/policy.ts` `matchAllowCommand`) rather
		 * than a hash: composition, redirection, substitution, globbing, an
		 * environment prefix, a write/retarget/execute flag, a revision-path
		 * operand, or a credential-shaped operand each send the call to the judge.
		 */
		command: z.array(commandTokenSchema).min(1).optional(),
		operation: z.string().min(1).optional(),
		sensitivity: sensitivitySchema.optional(),
		risk: riskSchema.optional(),
		/**
		 * Pins an `allow-exact` rule to one literal call. Copy it from an audit row
		 * (`/smart-approve review <audit-id>`).
		 *
		 * Fact 33 disqualifies an allow with any omitted argument, and a rule naming
		 * only tool+target leaves the payload unspecified — a `write` rule naming a
		 * path alone would permit arbitrary content at that path. So an allow-exact
		 * rule skips the judge only with this hash; without it the rule is advisory
		 * posture and the call is still judged.
		 */
		argumentsHash: z
			.string()
			.regex(/^[0-9a-f]{64}$/, "must be a 64-character lowercase SHA-256 hex digest")
			.optional(),
		/**
		 * Working directory this `allow-exact` rule is bound to. Required for a rule
		 * to skip the judge.
		 *
		 * The arguments hash alone is location-blind: `bash {command: "scripts/x.sh"}`
		 * and `write {path: "src/a.ts"}` both hash identically in every checkout, so a
		 * user-scoped rule without this would authorize the call everywhere. Fact 30
		 * requires a persisted allow to carry working-directory identity; this is
		 * that identity. The same fact also names a repository identity, which is
		 * deliberately not built — see `docs/fact-coverage.md` deviation 5.
		 */
		cwd: z.string().min(1).optional(),
		reason: z.string().min(1).default("no reason given"),
	})
	.strict()
	.superRefine((rule, ctx) => {
		// The two shapes are mutually exclusive on purpose. A rule carrying both
		// would have to be matched two ways, and the narrower reading is the one an
		// operator would not expect.
		if (rule.kind === "allow-command") {
			if (rule.command === undefined) {
				ctx.addIssue({ code: "custom", path: ["command"], message: "allow-command requires a command prefix" });
			}
			if (rule.target !== undefined) {
				ctx.addIssue({ code: "custom", path: ["target"], message: "allow-command matches argv, not a target" });
			}
			// A hash pins one literal call; this kind exists precisely to admit a
			// family. Accepting both would silently ignore one of them.
			if (rule.argumentsHash !== undefined) {
				ctx.addIssue({
					code: "custom",
					path: ["argumentsHash"],
					message: "allow-command cannot pin an arguments hash; use allow-exact for one literal call",
				});
			}
			return;
		}
		if (rule.target === undefined) {
			ctx.addIssue({ code: "custom", path: ["target"], message: `${rule.kind} requires a target` });
		}
		if (rule.command !== undefined) {
			ctx.addIssue({ code: "custom", path: ["command"], message: "only allow-command accepts a command prefix" });
		}
	});

const judgeSchema = z
	.object({
		/**
		 * Explicit allowlist of `provider/model` specs. Empty means "not set up yet",
		 * which fails closed rather than picking something plausible.
		 */
		authorizedModels: z.array(z.string().min(1)).default([]),
		/** Prefer a model whose family differs from the primary session model. */
		preferContrastingFamily: z.boolean().default(true),
		/** Hard ceiling on judge output bytes. Larger output is a malformed verdict. */
		maxOutputBytes: z.number().int().positive().max(64_000).default(4_000),
		maxOutputTokens: z.number().int().positive().max(8_000).default(1_000),
	})
	.strict();

const scopeSchema = z
	.object({
		/** Tools always judged regardless of tier. */
		alwaysJudge: z.array(z.string().min(1)).default([]),
		/**
		 * Tools exempted from judgment. Only honored for tools that resolve to a
		 * purely local read; a listed write/exec tool is still judged.
		 */
		neverJudge: z.array(z.string().min(1)).default([]),
		/** Treat unknown custom/MCP tools as scoped. Disabling requires deliberate action. */
		judgeUnknownTools: z.boolean().default(true),
		/** Per-tool argument byte thresholds above which a silent allow is forbidden. */
		argumentSizeThresholds: z.record(z.string(), z.number().int().positive()).default({}),
		defaultArgumentSizeThreshold: z.number().int().positive().default(8_000),
	})
	.strict();

const sensitivityConfigSchema = z
	.object({
		fallback: sensitivitySchema.default("balanced"),
		byTool: z.record(z.string(), sensitivitySchema).default({}),
		byRisk: z.partialRecord(riskSchema, sensitivitySchema).default({}),
	})
	.strict();

const timeoutsSchema = z
	.object({
		/** Observability target for end-to-end judge time, including setup. */
		targetLatencyMs: z.number().int().positive().default(5_000),
		/** Hard per-attempt safety boundary. */
		modelTimeoutMs: z.number().int().positive().default(10_000),
		/** Total judge attempts. 2 means one retry. */
		attempts: z.number().int().min(1).max(3).default(2),
		/** Reserved for audit commit and teardown after the last attempt. */
		cleanupMarginMs: z.number().int().positive().default(1_000),
		/** Our own cap, strictly below OMP's 30s handler cap. */
		handlerSelfDeadlineMs: z.number().int().positive().default(28_000),
		/** Upper bound on the best-effort in-handler dialog. */
		dialogMaxMs: z.number().int().positive().default(20_000),
		/** Below this, a dialog is too short to read a literal call. Skip to async. */
		dialogFloorMs: z.number().int().positive().default(10_000),
		/** How long literal frozen arguments survive in memory. Gates grant minting. */
		brokerArgsTtlMs: z
			.number()
			.int()
			.positive()
			.default(10 * 60_000),
		/** How long an audit ID stays actionable. Gates review/override at all. */
		pendingApprovalTtlMs: z
			.number()
			.int()
			.positive()
			.default(24 * 60 * 60_000),
		/** How long a pending record suppresses loop-breaker strikes. */
		strikeExemptionWindowMs: z
			.number()
			.int()
			.positive()
			.default(10 * 60_000),
		/** Retries a pending record may absorb before strikes resume. */
		maxExemptAttempts: z.number().int().positive().default(10),
		/** How long a subagent waits for the main session before blocking. */
		subagentEscalationTimeoutMs: z.number().int().positive().default(15_000),
	})
	.strict();

const auditSchema = z
	.object({
		enabled: z.boolean().default(true),
		/** Append a compact redacted entry to session history per decision. */
		sessionEntries: z.boolean().default(true),
		/** Override the SQLite location. Defaults to <agentDir>/smart-approve/state.sqlite. */
		databasePath: z.string().min(1).optional(),
		busyTimeoutMs: z.number().int().positive().default(5_000),
	})
	.strict();

const uiSchema = z
	.object({
		/** Show a companion risk card alongside OMP's native prompt. */
		riskCardOnNativePrompt: z.boolean().default(true),
		/** Attempt the best-effort in-handler dialog when budget and TUI allow. */
		fastPathDialog: z.boolean().default(true),
	})
	.strict();

export const smartApproveConfigSchema = z
	.object({
		version: z.literal(CONFIG_SCHEMA_VERSION).default(CONFIG_SCHEMA_VERSION),
		judge: judgeSchema.prefault({}),
		scope: scopeSchema.prefault({}),
		sensitivity: sensitivityConfigSchema.prefault({}),
		rules: z.array(ruleSchema).default([]),
		audit: auditSchema.prefault({}),
		timeouts: timeoutsSchema.prefault({}),
		ui: uiSchema.prefault({}),
	})
	.strict();

export type SmartApproveConfig = z.infer<typeof smartApproveConfigSchema>;

/**
 * Deny floor that ships with the plugin.
 *
 * These cover the one thing no operator policy can be relied on to cover: an
 * action whose whole purpose is to run the next step outside this gate. They are
 * seeded as raw data before any file layer, so a user-scope file may redefine
 * one by ID (fact 37's explicit human override) while a project-scope file may
 * not.
 *
 * `tool: "*"` rather than `tool: "bash"` because command targets are extracted
 * from any `command` argument, whatever the tool is called (`extractTargets` in
 * `src/policy.ts`): an MCP server exposing `run({command})` produces byte-identical
 * targets and would otherwise walk straight through. The cost is that `matchDeny`
 * also tests `target.requested`, so a path literally named `--no-extensions`
 * false-blocks. That trade is the one this module already takes everywhere else —
 * a spurious deny is a human-overridable block on an absurd filename, a miss is a
 * silent gate removal — and these targets are flag-shaped or prefix-anchored, so
 * they cannot collide with a plausible path the way a bare word like `terraform`
 * would.
 */
export const BUILTIN_RULES: SmartApproveConfig["rules"] = [
	{
		id: "builtin:nested-agent-no-extensions",
		kind: "deny-exact",
		tool: "*",
		target: "--no-extensions",
		risk: "safety-tampering",
		reason: "Disables extension discovery, so Smart Approve does not load in the nested session.",
	},
	{
		id: "builtin:nested-agent-skip-permissions",
		kind: "deny-exact",
		tool: "*",
		target: "--dangerously-skip-permissions",
		risk: "safety-tampering",
		reason: "Runs a nested agent with its approval prompts disabled; that session is outside this gate.",
	},
	{
		id: "builtin:disable-env-assignment-omp",
		kind: "deny-pattern",
		tool: "*",
		target: "OMP_DISABLE_*=*",
		risk: "safety-tampering",
		reason: "Environment kill switch aimed at omp's extension loading.",
	},
	{
		id: "builtin:disable-env-assignment-pi",
		kind: "deny-pattern",
		tool: "*",
		target: "PI_DISABLE_*=*",
		risk: "safety-tampering",
		reason: "Environment kill switch aimed at omp's extension loading, PI_ prefix.",
	},
];

/**
 * Read-only command floor that ships with the plugin.
 *
 * Every scoped call otherwise costs a model round trip, and the overwhelmingly
 * common case is an agent orienting itself: `git status`, `git log`, `git diff`.
 * Judging those buys nothing — there is no verdict a judge can reach that these
 * commands could act on, because none of them can write, execute, or transmit —
 * while the cost is latency, spend, and a verdict that is a model opinion rather
 * than a fact. Worse, a per-call opinion is nondeterministic: verdicts are never
 * cached, so the same `git log` can be allowed twice and escalated the third time.
 *
 * These are prefixes, not patterns. `matchAllowCommand` (`src/policy.ts`) admits
 * one only after the command parses as a single literal command and every token
 * clears the write/retarget/execute screens, so the family is bounded by
 * construction rather than by a glob an injected agent could thread.
 *
 * `tool: "bash"` and not `"*"`: the screens reason about a shell command line, so
 * an MCP tool that happens to accept `{command}` is judged rather than assumed to
 * have shell semantics. Operators can add rules for their own tools.
 *
 * Deliberately absent: `cat`, `head`, `tail`, and friends. They read arbitrary
 * file content, which is the deterministic protected-path floor's business, and a
 * blanket allow would route around it for anything git-tracked or unusually named.
 */
export const BUILTIN_COMMAND_ALLOWS: SmartApproveConfig["rules"] = [
	{
		id: "builtin:git-status",
		kind: "allow-command",
		tool: "bash",
		command: ["git", "status"],
		reason: "Reports the working tree state; cannot write, execute, or transmit.",
	},
	{
		id: "builtin:git-log",
		kind: "allow-command",
		tool: "bash",
		command: ["git", "log"],
		reason: "Prints commit history; cannot write, execute, or transmit.",
	},
	{
		id: "builtin:git-diff",
		kind: "allow-command",
		tool: "bash",
		command: ["git", "diff"],
		reason: "Prints tracked-file differences; cannot write, execute, or transmit.",
	},
	{
		id: "builtin:git-show",
		kind: "allow-command",
		tool: "bash",
		command: ["git", "show"],
		reason: "Prints objects already in history; revision-path operands are screened out.",
	},
	{
		id: "builtin:git-branch",
		kind: "allow-command",
		tool: "bash",
		command: ["git", "branch"],
		reason: "Lists branches; the deleting and moving flags are screened out.",
	},
	{
		id: "builtin:git-rev-parse",
		kind: "allow-command",
		tool: "bash",
		command: ["git", "rev-parse"],
		reason: "Resolves a revision to a hash; produces no side effect.",
	},
	{
		id: "builtin:git-describe",
		kind: "allow-command",
		tool: "bash",
		command: ["git", "describe"],
		reason: "Names the nearest tag; produces no side effect.",
	},
	{
		id: "builtin:git-blame",
		kind: "allow-command",
		tool: "bash",
		command: ["git", "blame"],
		reason: "Attributes tracked lines to commits; produces no side effect.",
	},
	{
		id: "builtin:pwd",
		kind: "allow-command",
		tool: "bash",
		command: ["pwd"],
		reason: "Prints the working directory.",
	},
	{
		id: "builtin:ls",
		kind: "allow-command",
		tool: "bash",
		command: ["ls"],
		reason: "Lists directory entries; credential-shaped operands are screened out.",
	},
	{
		id: "builtin:wc",
		kind: "allow-command",
		tool: "bash",
		command: ["wc"],
		reason: "Counts lines, words, or bytes; credential-shaped operands are screened out.",
	},
];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class ConfigError extends Error {
	constructor(
		message: string,
		/** Exact offending field paths, so the operator does not have to guess. */
		readonly fields: string[],
		readonly sourcePath?: string,
	) {
		super(message);
		this.name = "ConfigError";
	}
}

const SETUP_HINT = "Run `/smart-approve setup` to configure an authorized judge model.";

// ---------------------------------------------------------------------------
// Deadline invariant
// ---------------------------------------------------------------------------

export interface DeadlineBudget {
	/** attempts × modelTimeout + cleanupMargin */
	worstCaseJudgeSpendMs: number;
	/** Budget left for a dialog if the judge consumes its entire allowance. */
	worstCaseDialogWindowMs: number;
	/** Budget left for a dialog if the judge returns instantly. */
	bestCaseDialogWindowMs: number;
	/** True when even an instant judge leaves too little time to present a dialog. */
	fastPathStructurallyUnreachable: boolean;
	effectiveDeadlineMs: number;
}

/**
 * Validate the timing budget and derive the dialog windows.
 *
 * Throws {@link ConfigError} naming the exact invalid fields. Never clamps: a
 * configuration that cannot complete inside OMP's cap is an operator error, and
 * silently shrinking it would hide a safety-relevant misconfiguration.
 */
export function computeDeadlineBudget(t: SmartApproveConfig["timeouts"]): DeadlineBudget {
	const fields: string[] = [];

	if (t.handlerSelfDeadlineMs > MAX_SELF_DEADLINE_MS) {
		fields.push(`timeouts.handlerSelfDeadlineMs (${t.handlerSelfDeadlineMs} > ${MAX_SELF_DEADLINE_MS})`);
	}
	if (t.dialogFloorMs > t.dialogMaxMs) {
		fields.push(`timeouts.dialogFloorMs (${t.dialogFloorMs} > timeouts.dialogMaxMs ${t.dialogMaxMs})`);
	}
	// The two TTLs are deliberately independent, but a broker TTL outliving the
	// durable record is incoherent: literal arguments would still be in memory for
	// a record no command can address.
	if (t.brokerArgsTtlMs > t.pendingApprovalTtlMs) {
		fields.push(
			`timeouts.brokerArgsTtlMs (${t.brokerArgsTtlMs} > timeouts.pendingApprovalTtlMs ${t.pendingApprovalTtlMs})`,
		);
	}
	if (t.strikeExemptionWindowMs > t.pendingApprovalTtlMs) {
		fields.push(
			`timeouts.strikeExemptionWindowMs (${t.strikeExemptionWindowMs} > timeouts.pendingApprovalTtlMs ${t.pendingApprovalTtlMs})`,
		);
	}

	const effectiveDeadlineMs = Math.min(t.handlerSelfDeadlineMs, MAX_SELF_DEADLINE_MS);
	const worstCaseJudgeSpendMs = t.attempts * t.modelTimeoutMs + t.cleanupMarginMs;

	if (worstCaseJudgeSpendMs > effectiveDeadlineMs) {
		fields.push(
			`timeouts.attempts × timeouts.modelTimeoutMs + timeouts.cleanupMarginMs ` +
				`(${t.attempts} × ${t.modelTimeoutMs} + ${t.cleanupMarginMs} = ${worstCaseJudgeSpendMs}) ` +
				`exceeds the ${effectiveDeadlineMs}ms handler budget`,
		);
	}

	if (fields.length > 0) {
		throw new ConfigError(
			`Smart Approve timing configuration cannot complete inside OMP's ${OMP_HANDLER_CAP_MS}ms handler cap.`,
			fields,
		);
	}

	const worstCaseDialogWindowMs = Math.max(0, Math.min(t.dialogMaxMs, effectiveDeadlineMs - worstCaseJudgeSpendMs));
	const bestCaseDialogWindowMs = Math.max(0, Math.min(t.dialogMaxMs, effectiveDeadlineMs - t.cleanupMarginMs));

	return {
		worstCaseJudgeSpendMs,
		worstCaseDialogWindowMs,
		bestCaseDialogWindowMs,
		// Worst-case below the floor is normal — that is why escalation is async by
		// default. Only a best case below the floor means the dialog can never run.
		fastPathStructurallyUnreachable: bestCaseDialogWindowMs < t.dialogFloorMs,
		effectiveDeadlineMs,
	};
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

export const CONFIG_FILENAME = "smart-approve.yml";
export const POLICY_FILENAME = "SMART_APPROVE.md";

export interface ConfigLayer {
	scope: "user" | "project";
	filePath: string;
	contentHash: string;
}

export interface PolicyDocument {
	filePath: string;
	scope: "user" | "project";
	content: string;
	contentHash: string;
}

export interface DiscoveryPaths {
	cwd: string;
	agentDir: string;
	home: string;
}

/** Ancestor chain from the filesystem root down to `cwd`, broadest first. */
function ancestorsBroadestFirst(cwd: string): string[] {
	const out: string[] = [];
	let current = path.resolve(cwd);
	for (;;) {
		out.push(current);
		const parent = path.dirname(current);
		if (parent === current) break;
		current = parent;
	}
	return out.reverse();
}

/**
 * Candidate config file locations in precedence order (lowest first).
 * Later entries override earlier ones.
 */
export function configCandidates(paths: DiscoveryPaths): Array<{ scope: "user" | "project"; filePath: string }> {
	return [
		{ scope: "user" as const, filePath: path.join(paths.agentDir, CONFIG_FILENAME) },
		{ scope: "project" as const, filePath: path.join(paths.cwd, ".omp", CONFIG_FILENAME) },
		{ scope: "project" as const, filePath: path.join(paths.cwd, CONFIG_FILENAME) },
	];
}

/**
 * The file `setup` writes to: the user-scope layer, never a project one. An
 * authorization for a judge model is a per-operator credential decision, so it
 * never lands in a file a repository can ship. Both the setup preview and the
 * writer read this, so the path an operator confirms is the path that changes.
 */
export function writableConfigPath(paths: DiscoveryPaths): string {
	return path.join(paths.agentDir, CONFIG_FILENAME);
}

/**
 * Candidate natural-language policy locations, broadest to most specific.
 * The judge sees them in this order, so a leaf project statement reads last.
 */
export function policyCandidates(paths: DiscoveryPaths): Array<{ scope: "user" | "project"; filePath: string }> {
	const out: Array<{ scope: "user" | "project"; filePath: string }> = [
		{ scope: "user", filePath: path.join(paths.agentDir, POLICY_FILENAME) },
	];
	for (const dir of ancestorsBroadestFirst(paths.cwd)) {
		// Skip the home directory itself: a stray policy file there would silently
		// apply to every unrelated project on the machine.
		if (dir === paths.home) continue;
		out.push({ scope: "project", filePath: path.join(dir, ".omp", POLICY_FILENAME) });
		out.push({ scope: "project", filePath: path.join(dir, POLICY_FILENAME) });
	}
	return out;
}

// ---------------------------------------------------------------------------
// Protected surfaces
// ---------------------------------------------------------------------------

/**
 * Files a write or edit must never touch without an explicit human override.
 *
 * Covers Smart Approve's own surfaces plus OMP's active safety-policy files: an
 * agent that can rewrite `settings.yml` can set `tools.approvalMode: yolo`, and
 * one that can rewrite `secrets.yml` can neutralize redaction.
 */
export function protectedTargets(paths: DiscoveryPaths, databasePath: string): string[] {
	const targets = new Set<string>();
	const add = (p: string) => {
		targets.add(path.resolve(p));
		// A symlink pointing at a protected file is the same file.
		try {
			if (existsSync(p)) targets.add(realpathSync(p));
		} catch {
			// Unreadable path: the resolved form above still protects the literal target.
		}
	};

	for (const candidate of configCandidates(paths)) add(candidate.filePath);
	for (const candidate of policyCandidates(paths)) add(candidate.filePath);

	add(databasePath);
	add(`${databasePath}-wal`);
	add(`${databasePath}-shm`);

	// OMP's own safety-relevant configuration.
	for (const name of ["settings.yml", "secrets.yml", "secret-placeholder.key"]) {
		add(path.join(paths.agentDir, name));
		add(path.join(paths.cwd, ".omp", name));
	}

	return [...targets].sort();
}

export function defaultDatabasePath(agentDir: string): string {
	return path.join(agentDir, "smart-approve", "state.sqlite");
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

export interface ResolvedConfig {
	readonly config: SmartApproveConfig;
	readonly budget: DeadlineBudget;
	readonly layers: readonly ConfigLayer[];
	readonly policyDocuments: readonly PolicyDocument[];
	readonly protectedTargets: readonly string[];
	readonly databasePath: string;
	readonly paths: DiscoveryPaths;
	/**
	 * Identity of everything that can change a decision's meaning. Every allow
	 * grant is bound to this; a policy edit invalidates outstanding grants.
	 */
	readonly policyHash: string;
	/** Human-readable precedence trace for `/smart-approve status`. */
	readonly trace: readonly string[];
	/** Non-fatal findings surfaced by `status` rather than failing the load. */
	readonly warnings: readonly string[];
	/** False until an authorized judge model is configured. Scoped calls fail closed. */
	readonly ready: boolean;
	readonly notReadyReason?: string;
	readonly rules: readonly PolicyRule[];
}

/** Deny wins at equal specificity; exact beats patterned; narrower beats broader. */
export function ruleSpecificity(rule: {
	kind: PolicyRule["kind"];
	target?: string | undefined;
	command?: readonly string[] | undefined;
	operation?: string | undefined;
	risk?: string | undefined;
}): number {
	let score = 0;
	if (rule.kind === "allow-exact" || rule.kind === "deny-exact") score += 400;
	// An argv prefix is literal, so it ranks with the exact kinds rather than the
	// patterned ones — but below `allow-exact`, which pins one whole call.
	else if (rule.kind === "allow-command") score += 300;
	else if (rule.kind === "deny-pattern" || rule.kind === "allow-pattern") score += 200;
	if (rule.operation) score += 40;
	if (rule.risk) score += 20;
	// A longer literal target is a narrower match. A longer argv prefix likewise:
	// `git log` is narrower than `git`.
	const literal = rule.command === undefined ? (rule.target ?? "") : rule.command.join(" ");
	score += Math.min(19, Math.floor(literal.length / 8));
	// Deny outranks allow at otherwise equal specificity.
	if (rule.kind === "deny-exact" || rule.kind === "deny-pattern") score += 1;
	return score;
}

function toPolicyRules(
	raw: SmartApproveConfig["rules"],
	createdBy: PolicyRule["createdBy"],
	source: string,
): PolicyRule[] {
	return raw.map(r => ({
		id: r.id,
		kind: r.kind,
		toolName: r.tool,
		// An `allow-command` rule matches argv, so it has no target of its own; the
		// joined prefix stands in for display, listing, and specificity.
		target: r.target ?? (r.command === undefined ? "" : r.command.join(" ")),
		...(r.command === undefined ? {} : { command: [...r.command] }),
		...(r.operation === undefined ? {} : { operation: r.operation }),
		...(r.sensitivity === undefined ? {} : { sensitivity: r.sensitivity }),
		...(r.risk === undefined ? {} : { risk: r.risk }),
		...(r.argumentsHash === undefined ? {} : { argumentsHash: r.argumentsHash }),
		...(r.cwd === undefined ? {} : { cwd: r.cwd }),
		reason: r.reason,
		createdBy,
		specificity: ruleSpecificity(r),
		source,
	}));
}

export interface LoadedLayerInput {
	scope: "user" | "project";
	filePath: string;
	/** Parsed YAML/JSON object, or `undefined` when the file is absent. */
	data: unknown;
	rawContent: string;
}

/** Section keys whose objects merge key-by-key instead of replacing wholesale. */
const MERGED_SECTION_SET = new Set(["judge", "scope", "sensitivity", "audit", "timeouts", "ui"]);

/** Record-valued fields inside a section that merge entry-by-entry. */
const MERGED_RECORDS: Record<string, readonly string[]> = {
	scope: ["argumentSizeThresholds"],
	sensitivity: ["byTool", "byRisk"],
};

/** Narrow an unknown to a plain object so property reads are actually checked. */
function asRecord(value: unknown): Record<string, unknown> | undefined {
	return typeof value === "object" && value !== null && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: undefined;
}

/**
 * Merge discovered layers into one immutable resolved configuration.
 *
 * Layers are merged as RAW data and parsed exactly once at the end. Parsing each
 * layer first would fill every absent field with a default, so a project file
 * that only sets `sensitivity` would silently reset the user's `timeouts` back to
 * stock — a config-shaped way to widen the deadline budget without saying so.
 *
 * `rules` accumulate across layers on top of `BUILTIN_RULES`. A user-scope file
 * may redefine any ID, including a builtin — only a human writes that file. A
 * project-scope file may add new IDs but may never redefine one from a broader
 * layer, so a cloned repository cannot drop a user-level or builtin deny.
 */
export function resolveConfig(
	layerInputs: readonly LoadedLayerInput[],
	policyDocs: readonly PolicyDocument[],
	paths: DiscoveryPaths,
): ResolvedConfig {
	const trace: string[] = ["builtin defaults"];
	const warnings: string[] = [];
	const layers: ConfigLayer[] = [];

	const merged: Record<string, unknown> = {};
	const rawRuleById = new Map<string, { rule: unknown; scope: "builtin" | "user" | "project"; source: string }>();
	for (const rule of [...BUILTIN_RULES, ...BUILTIN_COMMAND_ALLOWS]) {
		rawRuleById.set(rule.id, { rule, scope: "builtin", source: "builtin defaults" });
	}

	for (const input of layerInputs) {
		if (input.data === undefined) continue;
		// Validate the layer in isolation so the error names this exact file. The
		// parsed output is discarded: only the raw data feeds the merge.
		const parsed = smartApproveConfigSchema.safeParse(input.data);
		if (!parsed.success) {
			throw new ConfigError(
				`Invalid Smart Approve configuration in ${input.filePath}.`,
				parsed.error.issues.map(i => `${i.path.join(".") || "<root>"}: ${i.message}`),
				input.filePath,
			);
		}

		// The layer already passed the strict schema above, so it is an object with
		// known-shaped sections; `asRecord` only recovers the index signature the
		// compiler loses on `unknown`.
		const raw = asRecord(input.data) ?? {};
		for (const [key, value] of Object.entries(raw)) {
			if (key === "rules") continue;
			const previousSection = asRecord(merged[key]);
			const nextSection = asRecord(value);
			if (!MERGED_SECTION_SET.has(key) || !nextSection) {
				merged[key] = value;
				continue;
			}
			const section: Record<string, unknown> = { ...previousSection, ...nextSection };
			for (const recordKey of MERGED_RECORDS[key] ?? []) {
				const previousRecord = asRecord(previousSection?.[recordKey]);
				const nextRecord = asRecord(nextSection[recordKey]);
				if (previousRecord || nextRecord) {
					section[recordKey] = { ...previousRecord, ...nextRecord };
				}
			}
			merged[key] = section;
		}

		for (const rule of Array.isArray(raw.rules) ? raw.rules : []) {
			const id = asRecord(rule)?.id;
			if (typeof id !== "string") continue;
			const existing = rawRuleById.get(id);
			if (input.scope === "project" && existing !== undefined) {
				warnings.push(
					`${input.filePath} redefines rule "${id}" from ${existing.source}. A project-scope file may add rules ` +
						`but may not redefine one from a broader layer, so the original is kept.`,
				);
				continue;
			}
			rawRuleById.set(id, { rule, scope: input.scope, source: input.filePath });
		}

		layers.push({
			scope: input.scope,
			filePath: input.filePath,
			contentHash: createHash("sha256").update(input.rawContent, "utf8").digest("hex"),
		});
		trace.push(`${input.scope}: ${input.filePath}`);
	}

	const ruleById = new Map<string, PolicyRule>();
	for (const [id, entry] of rawRuleById) {
		const parsedRule = ruleSchema.safeParse(entry.rule);
		if (!parsedRule.success) {
			throw new ConfigError(
				`Invalid Smart Approve rule "${id}" in ${entry.source}.`,
				parsedRule.error.issues.map(i => `rules.${id}.${i.path.join(".")}: ${i.message}`),
				entry.source,
			);
		}
		const [rule] = toPolicyRules([parsedRule.data], entry.scope, entry.source);
		if (rule) ruleById.set(id, rule);
	}

	// A pinned allow that no longer skips the judge is a silent behaviour change
	// from the operator's point of view, so name the rule and the fix.
	for (const rule of ruleById.values()) {
		if (rule.kind !== "allow-exact" || rule.argumentsHash === undefined) continue;
		if (rule.createdBy === "project") {
			warnings.push(
				`Rule "${rule.id}" pins an exact call but comes from a project-scope file (${rule.source}); ` +
					`project-scope allows never skip the judge. Move it to the user-scope configuration to restore the bypass.`,
			);
		} else if (rule.cwd !== undefined && !path.isAbsolute(rule.cwd)) {
			warnings.push(
				`Rule "${rule.id}" pins an exact call but its cwd "${rule.cwd}" is not absolute; a relative cwd ` +
					`resolves to wherever omp is launched, so the rule never skips the judge. Use an absolute path.`,
			);
		}
	}

	// Re-parse the merged object so defaults fill in and the strict check runs once
	// more over the composite — a layer cannot introduce a key that only becomes
	// invalid in combination.
	const finalParsed = smartApproveConfigSchema.safeParse({ ...merged, rules: [] });
	if (!finalParsed.success) {
		throw new ConfigError(
			"Merged Smart Approve configuration is invalid.",
			finalParsed.error.issues.map(i => `${i.path.join(".") || "<root>"}: ${i.message}`),
		);
	}
	const config = finalParsed.data;

	const budget = computeDeadlineBudget(config.timeouts);
	if (budget.fastPathStructurallyUnreachable) {
		warnings.push(
			`The in-handler approval dialog can never run: even an instant judge leaves ` +
				`${budget.bestCaseDialogWindowMs}ms, below timeouts.dialogFloorMs (${config.timeouts.dialogFloorMs}). ` +
				`Every escalation will resolve asynchronously via /smart-approve review.`,
		);
	} else if (budget.worstCaseDialogWindowMs < config.timeouts.dialogFloorMs) {
		warnings.push(
			`A slow judge leaves ${budget.worstCaseDialogWindowMs}ms, below timeouts.dialogFloorMs ` +
				`(${config.timeouts.dialogFloorMs}); those escalations resolve asynchronously.`,
		);
	}

	if (config.scope.neverJudge.length > 0) {
		warnings.push(
			`scope.neverJudge exempts ${config.scope.neverJudge.length} tool(s); the exemption applies ` +
				`only to calls that resolve to a purely local read.`,
		);
	}

	const databasePath = config.audit.databasePath
		? path.resolve(config.audit.databasePath)
		: defaultDatabasePath(paths.agentDir);

	const targets = protectedTargets(paths, databasePath);
	const rules = [...ruleById.values()].sort((a, b) => b.specificity - a.specificity);

	const ready = config.judge.authorizedModels.length > 0;

	const policyHash = createHash("sha256")
		.update(
			JSON.stringify({
				schema: CONFIG_SCHEMA_VERSION,
				taxonomy: TAXONOMY_VERSION,
				config,
				rules: rules.map(r => [r.id, r.kind, r.toolName, r.target, r.operation ?? "", r.risk ?? ""]),
				policies: policyDocs.map(d => [d.filePath, d.contentHash]),
			}),
			"utf8",
		)
		.digest("hex");

	for (const doc of policyDocs) trace.push(`policy: ${doc.filePath}`);

	return Object.freeze({
		config,
		budget,
		layers,
		policyDocuments: policyDocs,
		protectedTargets: targets,
		databasePath,
		paths,
		policyHash,
		trace,
		warnings,
		ready,
		...(ready ? {} : { notReadyReason: `No authorized judge model configured. ${SETUP_HINT}` }),
		rules,
	});
}

/** Narrowest applicable sensitivity wins: risk override > tool override > fallback. */
export function effectiveSensitivity(config: SmartApproveConfig, toolName: string, risk?: string): SensitivityLevel {
	if (risk) {
		const byRisk = config.sensitivity.byRisk[risk as keyof typeof config.sensitivity.byRisk];
		if (byRisk) return byRisk;
	}
	const byTool = config.sensitivity.byTool[toolName];
	if (byTool) return byTool;
	return config.sensitivity.fallback;
}

/** Per-tool override, else the global default. */
export function argumentSizeThreshold(config: SmartApproveConfig, toolName: string): number {
	return config.scope.argumentSizeThresholds[toolName] ?? config.scope.defaultArgumentSizeThreshold;
}
