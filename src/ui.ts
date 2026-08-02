/**
 * Human-facing rendering and the one approval control Smart Approve owns.
 *
 * Two rules shape every function here:
 *
 * 1. **Approval requires the literal call.** The presenter renders the frozen
 *    tool name and the complete pending arguments verbatim. If the arguments
 *    cannot be rendered in full, the presenter refuses rather than asking a
 *    human to approve something they cannot see.
 * 2. **Absence is never assent.** OMP's headless UI context returns `undefined`
 *    from `select`/`input` and `false` from `confirm`. Every one of those paths
 *    maps to "no human answer", which the caller treats as a block.
 *
 * Literal arguments reach this module only from the in-memory broker. Nothing
 * here reads them from persistence, and nothing here claims to.
 */

import { type GrantAuthority, grantAuthority } from "./broker.ts";
import type { ResolvedConfig } from "./config.ts";
import type {
	AuditEvent,
	AuditRecord,
	EscalationRequest,
	FrozenCall,
	HumanDecision,
	PendingApproval,
	RuleSuggestion,
} from "./contracts.ts";
import { type RiskCard, summarizeTargets } from "./gate.ts";
import { hashArguments } from "./policy.ts";
import type { AuditAggregate } from "./store.ts";

// ---------------------------------------------------------------------------
// Keys and labels
// ---------------------------------------------------------------------------

/** Companion card next to OMP's native prompt. Never carries arguments. */
export const WIDGET_RISK_CARD = "smart-approve:risk";
/** Persistent unguarded-mode warning. */
export const WIDGET_BYPASS = "smart-approve:bypass";
/** Scrollable body of the full-call approval view, owned by the presenter. */
export const WIDGET_APPROVAL = "smart-approve:approval";
export const STATUS_KEY = "smart-approve";

/**
 * `ExtensionUIContext.select` returns the selected *label*, so these strings are
 * the wire format of a human decision. Deny is listed first and therefore holds
 * default focus.
 */
export const CHOICE_DENY = "Deny";
export const CHOICE_ALLOW_ONCE = "Allow once";

// ---------------------------------------------------------------------------
// Host port
// ---------------------------------------------------------------------------

/**
 * The slice of `ExtensionContext.ui` Smart Approve uses. Kept as its own port so
 * renderers and commands are testable without an OMP session, and so headless
 * behavior is a single explicit flag rather than a scattering of `undefined`
 * checks.
 */
export interface UiHost {
	hasUI: boolean;
	select(title: string, options: { label: string; description?: string }[]): Promise<string | undefined>;
	confirm(title: string, message: string): Promise<boolean>;
	input(title: string, placeholder?: string): Promise<string | undefined>;
	notify(message: string, type?: "info" | "warning" | "error"): void;
	setStatus(key: string, text: string | undefined): void;
	setWidget(key: string, lines: string[] | undefined): void;
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

function formatDuration(ms: number): string {
	if (ms <= 0) return "expired";
	const totalSeconds = Math.floor(ms / 1000);
	if (totalSeconds < 60) return `${totalSeconds}s`;
	const minutes = Math.floor(totalSeconds / 60);
	if (minutes < 60) return `${minutes}m ${String(totalSeconds % 60).padStart(2, "0")}s`;
	const hours = Math.floor(minutes / 60);
	return `${hours}h ${String(minutes % 60).padStart(2, "0")}m`;
}

type ArgumentRendering = { ok: true; lines: string[] } | { ok: false; reason: string };

/**
 * Pretty-print the complete literal arguments. Returns a failure instead of a
 * partial rendering: a human approving a call they can only partly see is
 * exactly the failure this dialog exists to prevent.
 */
function formatArguments(args: Readonly<Record<string, unknown>>): ArgumentRendering {
	let json: string | undefined;
	try {
		json = JSON.stringify(args, null, 2);
	} catch (error) {
		return { ok: false, reason: error instanceof Error ? error.message : String(error) };
	}
	if (typeof json !== "string") return { ok: false, reason: "arguments are not JSON-serializable" };
	return { ok: true, lines: json.split("\n") };
}

// ---------------------------------------------------------------------------
// Full-call approval view
// ---------------------------------------------------------------------------

/**
 * The scrollable body of the approval view. Exported so tests can assert the
 * literal rendering directly instead of inferring it from a dialog transcript.
 */
export function renderApprovalRequest(request: EscalationRequest, remainingMs: number): string[] {
	const lines: string[] = [
		"SMART APPROVE — human approval required",
		`Audit ID:     ${request.auditId}`,
		`Source agent: ${request.sourceAgentId} (${request.sourceAgentKind})`,
	];
	if (request.parentAgentId !== undefined) lines.push(`Parent agent: ${request.parentAgentId}`);
	lines.push(
		`Tool:         ${request.frozenCall.toolName}`,
		`Operation:    ${request.canonicalCall.operation}`,
		`Destination:  ${summarizeTargets(request.canonicalCall)}`,
		`Risk:         ${request.risk}`,
		`Judge:        ${request.rationale}`,
		`Call hash:    ${request.frozenCall.argumentsHash}`,
		`Expires in:   ${formatDuration(remainingMs)}`,
		"",
		"Literal arguments (complete, exactly as the agent wrote them):",
	);
	const rendered = formatArguments(request.frozenCall.rawArguments);
	lines.push(...(rendered.ok ? rendered.lines : [`<arguments cannot be rendered: ${rendered.reason}>`]));
	lines.push(
		"",
		"Deny is the default. Approve only this exact call — approval is single-use",
		"and bound to the call hash above.",
	);
	return lines;
}

/**
 * Build the `BrokerEndpoint.present` function for a session.
 *
 * The returned decision always carries the request's own nonce and arguments
 * hash, so a presenter cannot fabricate an approval for a different call: the
 * caller re-validates both against the broker before anything executes.
 */
export function createApprovalPresenter(
	ui: UiHost,
	now: () => number,
): (request: EscalationRequest, signal: AbortSignal) => Promise<HumanDecision | undefined> {
	return async (request, signal) => {
		if (!ui.hasUI || signal.aborted) return undefined;

		const remainingMs = request.expiresAt - now();
		if (remainingMs <= 0) return undefined;

		// Refuse before opening any dialog: an unrenderable call cannot be approved.
		if (!formatArguments(request.frozenCall.rawArguments).ok) {
			ui.notify(`Smart Approve cannot render call ${request.auditId} literally; it stays blocked.`, "error");
			return undefined;
		}

		ui.setWidget(WIDGET_APPROVAL, renderApprovalRequest(request, remainingMs));
		let choice: string | undefined;
		try {
			choice = await raceAbort(
				ui.select(
					`Smart Approve: ${request.frozenCall.toolName} from ${request.sourceAgentId} (${request.auditId})`,
					[
						{ label: CHOICE_DENY, description: "Block this call. Default." },
						{ label: CHOICE_ALLOW_ONCE, description: "Run this exact call once, then re-lock." },
					],
				),
				signal,
			);
		} finally {
			ui.setWidget(WIDGET_APPROVAL, undefined);
		}

		if (signal.aborted) return undefined;
		if (choice !== CHOICE_ALLOW_ONCE && choice !== CHOICE_DENY) return undefined;

		return {
			auditId: request.auditId,
			nonce: request.nonce,
			choice: choice === CHOICE_ALLOW_ONCE ? "allow-once" : "deny",
			argumentsHash: request.frozenCall.argumentsHash,
			decidedAt: now(),
		};
	};
}

/**
 * Resolve to `undefined` as soon as the handler's deadline controller fires, and
 * treat a dialog rejection the same way. Neither can become an approval.
 */
function raceAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T | undefined> {
	if (signal.aborted) return Promise.resolve(undefined);
	return new Promise<T | undefined>(resolve => {
		const onAbort = () => resolve(undefined);
		signal.addEventListener("abort", onAbort, { once: true });
		const settle = (value: T | undefined) => {
			signal.removeEventListener("abort", onAbort);
			resolve(value);
		};
		promise.then(settle, () => settle(undefined));
	});
}

// ---------------------------------------------------------------------------
// Native-prompt companion card
// ---------------------------------------------------------------------------

/**
 * Companion lines for a call OMP already prompts about. OMP's own dialog is the
 * sole approval control and already shows the literal call, so this card carries
 * only redacted judgment — never arguments.
 */
export function renderRiskCard(card: RiskCard): string[] {
	return [
		`SMART APPROVE pre-screen — risk: ${card.risk}`,
		`Tool:        ${card.toolName}`,
		`Destination: ${card.targetSummary}`,
		`Finding:     ${card.rationale}`,
		`Judge:       ${card.judgeAvailable ? "available" : "UNAVAILABLE — this call was not semantically screened"}`,
		`Audit ID:    ${card.auditId}`,
		"OMP's prompt below remains the only approval control.",
	];
}

// ---------------------------------------------------------------------------
// Pending list
// ---------------------------------------------------------------------------

/**
 * List durable open escalations. Mintability is asked of the live broker per
 * row, so after a restart every row honestly reads as intent-only.
 */
export function renderPendingList(pending: readonly PendingApproval[], now: number): string[] {
	if (pending.length === 0) {
		return ["No Smart Approve escalations are open."];
	}
	const lines: string[] = [`${pending.length} open Smart Approve escalation${pending.length === 1 ? "" : "s"}:`];
	for (const record of pending) {
		const authority = grantAuthority(record.auditId, record.argumentsHash, now, hashArguments);
		lines.push(
			"",
			`  ${record.auditId}  [${record.state}]`,
			`    tool:      ${record.toolName} ${record.operation}`,
			`    target:    ${record.targetSummary}`,
			`    risk:      ${record.risk}`,
			`    agent:     ${record.sourceAgentId}${
				record.parentAgentId === undefined ? "" : ` (parent ${record.parentAgentId})`
			}`,
			`    age:       ${formatDuration(now - record.createdAt)}`,
			`    ttl left:  ${formatDuration(record.expiresAt - now)}`,
			`    approval:  ${
				authority.kind === "mintable"
					? "can mint an exact grant"
					: `intent-only — literal arguments are gone (${authority.reason})`
			}`,
		);
	}
	lines.push("", "Inspect one with `/smart-approve review <audit-id>`.");
	return lines;
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

export interface StatusInput {
	resolved: ResolvedConfig;
	judge: {
		authorizedModels: readonly string[];
		selected?: string;
		authHealthy: boolean;
		detail: string;
	};
	broker: {
		humanChannel: boolean;
		queueDepth: number;
	};
	/** Whether *this* session can present a dialog at all. */
	mainUi: boolean;
	bypassActive: boolean;
	database: { path: string; healthy: boolean; detail?: string };
	openPending: number;
	aggregate: AuditAggregate;
	aggregateWindowMs: number;
	now: number;
}

export function renderStatus(input: StatusInput): string[] {
	const { resolved, judge, aggregate } = input;
	const config = resolved.config;
	const lines: string[] = ["SMART APPROVE STATUS", ""];

	if (input.bypassActive) {
		lines.push(
			"!! UNGUARDED — Smart Approve is disabled for this session by a human.",
			"   Run `/smart-approve guarded` to re-enable it.",
			"",
		);
	}

	lines.push(
		resolved.ready ? "Gate: armed" : `Gate: NOT READY — ${resolved.notReadyReason ?? "configuration incomplete"}`,
		`Policy hash: ${resolved.policyHash}`,
	);

	lines.push("", "Configuration layers (lowest precedence first):");
	if (resolved.layers.length === 0) lines.push("  (none — built-in defaults only)");
	for (const layer of resolved.layers)
		lines.push(`  ${layer.scope.padEnd(7)} ${layer.filePath}  ${layer.contentHash}`);

	lines.push("", "Policy documents:");
	if (resolved.policyDocuments.length === 0) lines.push("  (none)");
	for (const doc of resolved.policyDocuments)
		lines.push(`  ${doc.scope.padEnd(7)} ${doc.filePath}  ${doc.contentHash}`);

	lines.push(
		"",
		"Judge:",
		`  authorized: ${judge.authorizedModels.length === 0 ? "(none)" : judge.authorizedModels.join(", ")}`,
		`  selected:   ${judge.selected ?? "(none)"}`,
		`  auth:       ${judge.authHealthy ? "healthy" : "UNAVAILABLE"} — ${judge.detail}`,
	);

	lines.push(
		"",
		"Scope:",
		`  always judge:  ${config.scope.alwaysJudge.join(", ") || "(none)"}`,
		`  never judge:   ${config.scope.neverJudge.join(", ") || "(none)"}`,
		`  unknown tools: ${config.scope.judgeUnknownTools ? "judged" : "NOT judged"}`,
		`  arg threshold: ${config.scope.defaultArgumentSizeThreshold} bytes default`,
	);

	const byTool = Object.entries(config.sensitivity.byTool);
	const byRisk = Object.entries(config.sensitivity.byRisk);
	lines.push(
		"",
		"Sensitivity precedence (narrowest wins): risk override > tool override > fallback",
		`  fallback:      ${config.sensitivity.fallback}`,
		`  by tool:       ${byTool.map(([k, v]) => `${k}=${v}`).join(", ") || "(none)"}`,
		`  by risk:       ${byRisk.map(([k, v]) => `${k}=${v}`).join(", ") || "(none)"}`,
	);

	lines.push(
		"",
		"Deadlines:",
		`  handler self-deadline: ${resolved.budget.effectiveDeadlineMs} ms`,
		`  worst-case judge:      ${resolved.budget.worstCaseJudgeSpendMs} ms`,
		`  dialog window:         ${resolved.budget.worstCaseDialogWindowMs}–${resolved.budget.bestCaseDialogWindowMs} ms` +
			(resolved.budget.fastPathStructurallyUnreachable
				? "  (fast path unreachable — escalation is always async)"
				: ""),
		`  broker args TTL:       ${config.timeouts.brokerArgsTtlMs} ms`,
		`  pending approval TTL:  ${config.timeouts.pendingApprovalTtlMs} ms`,
	);

	lines.push(
		"",
		"Channels:",
		`  main approval UI: ${input.broker.humanChannel ? "live" : "ABSENT — escalations block instead of prompting"}`,
		`  this session UI:  ${input.mainUi ? "interactive" : "headless"}`,
		`  escalation queue: ${input.broker.queueDepth}`,
		`  bypass:           ${input.bypassActive ? "ACTIVE (session only)" : "off"}`,
	);

	lines.push(
		"",
		"Audit database:",
		`  path:   ${input.database.path}`,
		`  health: ${input.database.healthy ? "ok" : `FAILING — ${input.database.detail ?? "unknown error"}`}`,
	);

	lines.push(
		"",
		`Open pending approvals: ${input.openPending}` +
			(input.openPending > 0 ? "  — list them with `/smart-approve pending`" : ""),
	);

	lines.push(
		"",
		`Recent decisions (last ${formatDuration(input.aggregateWindowMs)}):`,
		`  total ${aggregate.total}  allow ${aggregate.allowed}  escalate ${aggregate.escalated}  block ${aggregate.blocked}`,
		`  avg latency ${Math.round(aggregate.avgLatencyMs)} ms  tokens ${aggregate.inputTokens} in / ${aggregate.outputTokens} out  cost $${aggregate.costUsd.toFixed(4)}`,
	);

	if (resolved.warnings.length > 0) {
		lines.push("", "Compatibility warnings:");
		for (const warning of resolved.warnings) lines.push(`  ! ${warning}`);
	}

	return lines;
}

// ---------------------------------------------------------------------------
// Review
// ---------------------------------------------------------------------------

export interface ReviewInput {
	auditId: string;
	record?: AuditRecord;
	pending?: PendingApproval;
	events: readonly AuditEvent[];
	retryFamilyKey?: string;
	strikes: number;
	suggestion?: RuleSuggestion;
	/** Asked of the live broker, never inferred from persistence. */
	authority: GrantAuthority;
	/** Present only while the in-memory broker still holds the frozen call. */
	frozenCall?: FrozenCall;
	now: number;
}

export function renderReview(input: ReviewInput): string[] {
	const lines: string[] = [`SMART APPROVE REVIEW — ${input.auditId}`, ""];

	const record = input.record;
	if (record === undefined) {
		lines.push("No committed verdict for this audit ID (the decision may still be in flight).");
	} else {
		lines.push(
			"Original verdict (immutable):",
			`  decision: ${record.decision} at stage ${record.stage}`,
			`  risk:     ${record.risk}`,
			`  reason:   ${record.rationale}`,
			`  tool:     ${record.toolName} ${record.operation}`,
			`  target:   ${record.targetSummary}`,
			`  agent:    ${record.sourceAgentId} (${record.sourceAgentKind})`,
			// Location matters to the decision: a grant minted here is bound to this
			// directory and will not admit the same call from anywhere else.
			`  cwd:      ${record.cwd || "(unknown — recorded before location tracking)"}`,
			`  hash:     ${record.argumentsHash}`,
			`  judge:    ${record.judgeModel ?? "(none)"}${record.judgeProvider === undefined ? "" : ` @ ${record.judgeProvider}`}`,
		);
	}

	const pending = input.pending;
	lines.push("");
	if (pending === undefined) {
		lines.push("No durable escalation record: this call was never escalated, or its record is gone.");
	} else {
		lines.push(
			"Escalation record:",
			`  state:    ${pending.state}`,
			`  opened:   ${formatDuration(input.now - pending.createdAt)} ago`,
			`  ttl left: ${formatDuration(pending.expiresAt - input.now)}`,
			`  cwd:      ${pending.cwd || "(unknown — recorded before location tracking)"}`,
			`  attempts absorbed under strike exemption: ${pending.exemptAttempts}`,
		);
	}

	lines.push("", "What this record currently supports:");
	if (input.authority.kind === "mintable") {
		lines.push(
			"  It can mint an exact grant. The literal frozen arguments are still in memory",
			"  and their recomputed hash matches the record, so `/smart-approve override` can",
			"  authorize this exact call.",
		);
	} else {
		lines.push(
			"  Intent-only — literal arguments are gone.",
			`  ${input.authority.reason}.`,
			"  `/smart-approve override` can still deny or expire it, and can record intent to",
			"  approve, but it cannot mint a grant. The next materially identical call re-opens a",
			"  live dialog with real arguments; headless, it stays blocked.",
		);
	}

	lines.push("", "Literal arguments:");
	if (input.frozenCall === undefined) {
		lines.push(
			"  Not available. Raw arguments live only in the in-memory broker and are never",
			"  persisted, so nothing here is reconstructed from the audit database.",
		);
	} else {
		const rendered = formatArguments(input.frozenCall.rawArguments);
		lines.push("  (from the live in-memory broker)");
		lines.push(...(rendered.ok ? rendered.lines.map(l => `  ${l}`) : [`  <cannot render: ${rendered.reason}>`]));
	}

	lines.push("", "History (append-only):");
	if (input.events.length === 0) lines.push("  (no events)");
	for (const event of input.events) {
		lines.push(`  ${new Date(event.at).toISOString()}  ${event.type.padEnd(16)} ${event.actor}: ${event.detail}`);
	}

	const humanEvents = input.events.filter(e => HUMAN_EVENT_TYPES[e.type] === true);
	lines.push("", "Human decisions:");
	if (humanEvents.length === 0) lines.push("  (none)");
	for (const event of humanEvents) lines.push(`  ${event.type} by ${event.actor}: ${event.detail}`);

	lines.push(
		"",
		`Retry family: ${input.retryFamilyKey ?? "(unknown)"} — ${input.strikes} strike${input.strikes === 1 ? "" : "s"}`,
	);

	lines.push("", "Judge rule suggestion:");
	if (input.suggestion === undefined) {
		lines.push("  (none held in memory)");
	} else {
		lines.push(
			`  ${input.suggestion.kind} ${input.suggestion.toolName} -> ${input.suggestion.target}`,
			`  ${input.suggestion.rationale}`,
			"  Non-binding. Apply with `/smart-approve apply-suggestion <audit-id>`.",
		);
	}

	return lines;
}

/** Event types a human authored. Fixed table, so a `Record` beats a runtime `Set`. */
const HUMAN_EVENT_TYPES: Partial<Record<AuditEvent["type"], true>> = {
	overridden: true,
	granted: true,
	denied: true,
	"intent-recorded": true,
	revoked: true,
	"bypass-enabled": true,
	"bypass-disabled": true,
};
