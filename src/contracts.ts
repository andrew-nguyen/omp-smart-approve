/**
 * Closed boundary types shared by every Smart Approve module.
 *
 * Two invariants are encoded here rather than documented elsewhere:
 *
 * 1. Raw arguments exist only on {@link GateRequest} and {@link FrozenCall}. Every
 *    persistence-facing type is a separate redacted/canonical DTO, so a caller
 *    cannot hand a {@link GateRequest} straight to the store. This is a structural
 *    barrier, NOT a type-level brand: nothing stops someone stringifying raw
 *    arguments into a `string` field, which is why `store.ts` also enforces a
 *    runtime guard (forbidden key names plus a credential-shape scan) and
 *    `test/audit-redaction.test.ts` byte-scans the database file.
 * 2. A verdict is a closed union. There is no "unknown" or "error" decision: every
 *    failure path is converted to `escalate` by the orchestrator, never to `allow`.
 */

/** Versioned taxonomy. Persisted in audit rows, so values are append-only. */
export const RISK_CLASSES = [
	"prompt-injection",
	"exfiltration",
	"destructive-action",
	"wrong-target",
	"policy-violation",
	"safety-tampering",
	"uncertain",
] as const;

export type RiskClass = (typeof RISK_CLASSES)[number];

/** Taxonomy revision embedded in the policy hash so grants die when it changes. */
export const TAXONOMY_VERSION = 1;

export type Decision = "allow" | "escalate" | "block";

/**
 * A rule the judge may propose. Never binding, never auto-applied.
 *
 * `allow` suggestions are structurally forbidden from containing pattern operators:
 * see `isExactSuggestion` in policy.ts. A patterned allow degrades to posture.
 */
export interface RuleSuggestion {
	kind: "allow-exact" | "deny-exact" | "deny-pattern" | "posture";
	toolName: string;
	/** Canonical target or pattern the rule applies to. */
	target: string;
	rationale: string;
}

export interface Verdict {
	decision: Decision;
	risk: RiskClass;
	rationale: string;
	suggestion?: RuleSuggestion;
}

// ---------------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------------

export type ToolTier = "read" | "write" | "exec";

/** Where a target string came from, and whether we could resolve it. */
export interface CallTarget {
	kind: "path" | "url" | "command" | "mcp" | "device" | "unknown";
	/** Exactly as the model wrote it. */
	requested: string;
	/**
	 * Normalized against cwd for paths, origin+pathname for URLs. `undefined` when
	 * the value is dynamic (contains a variable, a glob the tool will expand, or a
	 * shell substitution). An unresolved target can never match an exact grant.
	 */
	resolved?: string;
	/** True when `resolved` could not be computed. Forces judgment. */
	dynamic: boolean;
}

/**
 * Deterministic projection of a tool call used for hashing, rule matching, and
 * audit. Contains no raw argument values beyond extracted targets and the
 * operation verb.
 */
export interface CanonicalCall {
	toolName: string;
	/** Tool-specific verb: `write`, `edit`, `exec`, `fetch`, `search`, `call`, ... */
	operation: string;
	targets: CallTarget[];
	/** SHA-256 over the complete canonical JSON bytes. Never truncated. */
	argumentsHash: string;
	/** Nested `xd://` device name when this is an xdev dispatch. */
	device?: string;
}

/**
 * Local read with no external transmission skips the judge after deny checks.
 * Everything else — writes, execs, network egress, unknown tools — is judged.
 */
export type CallScope = "local-read" | "scoped";

/** Frozen literal call. Lives in memory only; never persisted, never serialized to disk. */
export interface FrozenCall {
	readonly toolName: string;
	readonly toolCallId: string;
	readonly rawArguments: Readonly<Record<string, unknown>>;
	readonly argumentsHash: string;
	readonly frozenAt: number;
}

export interface GateRequest {
	auditId: string;
	toolCallId: string;
	toolName: string;
	sourceAgentId: string;
	sourceAgentKind: "main" | "sub" | "advisor" | "unknown";
	parentAgentId?: string;
	canonicalCall: CanonicalCall;
	rawArguments: Readonly<Record<string, unknown>>;
	argumentsHash: string;
	cwd: string;
	receivedAt: number;
	/** Absolute epoch ms. One AbortController is rooted here. */
	deadlineAt: number;
}

// ---------------------------------------------------------------------------
// Host approval
// ---------------------------------------------------------------------------

/**
 * OMP's native approval decision for this exact call, reconstructed from public
 * live-session APIs.
 *
 * - `auto`  — OMP would run it with no human in the loop. Full gate applies.
 * - `prompt`— OMP will show its own dialog. Semantic pre-screen only, no second dialog.
 * - `deny`  — OMP refuses. Preserve the denial, skip judgment.
 * - `unsupported` — host state could not be proven. Fail closed.
 */
export type HostBranch = "auto" | "prompt" | "deny" | "unsupported";

export interface HostApproval {
	branch: HostBranch;
	/** OMP's own resolved policy, when it could be resolved. */
	policy?: "allow" | "deny" | "prompt";
	tier?: ToolTier;
	mode?: "always-ask" | "write" | "yolo";
	/** Human-readable justification, safe to show. Never contains arguments. */
	reason: string;
}

// ---------------------------------------------------------------------------
// Gate outcome
// ---------------------------------------------------------------------------

export type GateStage =
	| "protected-policy"
	| "deny-rule"
	| "host-deny"
	| "unsupported-host"
	| "exact-grant"
	| "exact-allow-rule"
	| "allow-command-rule"
	| "local-read"
	| "oversized-argument"
	| "sensitive-read"
	| "loop-breaker"
	| "judge"
	| "judge-failure"
	| "escalation"
	| "config-invalid"
	| "store-failure"
	| "bypass"
	| "internal-error";

export interface GateResult {
	auditId: string;
	decision: Decision;
	/** Which stage produced the terminal decision. Drives audit and messaging. */
	stage: GateStage;
	risk: RiskClass;
	/** Actionable, redacted. Returned to the model verbatim on block. */
	reason: string;
	/** Present when the result is a block the human can act on out-of-band. */
	pendingAuditId?: string;
}

// ---------------------------------------------------------------------------
// Judge
// ---------------------------------------------------------------------------

export type ProvenanceSource = "user" | "assistant" | "local" | "external-network" | "browser" | "mcp" | "subagent";

export interface ProvenanceEntry {
	source: ProvenanceSource;
	toolName: string;
	/** Redacted one-line summary. Never a raw result body. */
	summary: string;
	at: number;
	/** True when the content originated outside the user/assistant trust boundary. */
	untrusted: boolean;
}

/**
 * How closely the recorded rationale tracks the call being judged.
 *
 * The host prepares tool dispatch before it publishes the assistant message, so
 * "the agent's latest completed statement" and "why this call is happening" are
 * not the same thing. The judge is told which one it is looking at rather than
 * being left to assume.
 */
export type RationaleFreshness = "current-turn" | "previous-turn" | "none";

export interface JudgeInput {
	/** Most recent direct user request, redacted. */
	userIntent: string;
	/** Primary coding agent's stated rationale, redacted and unfenced. */
	agentRationale: string;
	/** Whether {@link agentRationale} belongs to the turn issuing this call. */
	rationaleFreshness: RationaleFreshness;
	/** True when the turn stated no prose and the text is its reasoning instead. */
	rationaleFromReasoning: boolean;
	toolName: string;
	operation: string;
	/** Secret-obfuscated, size-bounded view of the arguments. */
	argumentsView: string;
	targets: CallTarget[];
	sourceAgentId: string;
	recentActions: ProvenanceEntry[];
	/** Authoritative natural-language policy from SMART_APPROVE.md files. */
	policyDocuments: string[];
	/** Non-bypassing posture hints from wildcard allow rules. */
	postureHints: string[];
	sensitivity: SensitivityLevel;
	/**
	 * True when argument sampling omitted bytes that could change the target or
	 * action classification. The judge may then return only escalate or block.
	 */
	incompleteCriticalContext: boolean;
}

export type JudgeResult =
	| { ok: true; verdict: Verdict; metrics: JudgeMetrics }
	| { ok: false; failure: JudgeFailure; metrics: JudgeMetrics };

export type JudgeFailureKind =
	| "no-authorized-model"
	| "auth-unavailable"
	| "timeout"
	| "aborted"
	| "transport"
	| "malformed-output"
	| "output-too-large"
	| "deadline-exhausted"
	| "internal";

export interface JudgeFailure {
	kind: JudgeFailureKind;
	/** Redacted. Safe to show a human and to persist. */
	detail: string;
}

export interface JudgeMetrics {
	attempts: number;
	latencyMs: number;
	provider?: string;
	model?: string;
	inputTokens?: number;
	outputTokens?: number;
	costUsd?: number;
	/** True when latencyMs exceeded the configured target. Observability only. */
	overTarget: boolean;
}

// ---------------------------------------------------------------------------
// Sensitivity
// ---------------------------------------------------------------------------

export const SENSITIVITY_LEVELS = ["permissive", "balanced", "strict"] as const;
export type SensitivityLevel = (typeof SENSITIVITY_LEVELS)[number];

// ---------------------------------------------------------------------------
// Rules and grants
// ---------------------------------------------------------------------------

export type RuleKind = "allow-exact" | "allow-command" | "allow-pattern" | "deny-exact" | "deny-pattern" | "posture";

export interface PolicyRule {
	id: string;
	kind: RuleKind;
	toolName: string;
	/** Exact canonical target, or a glob/regex for pattern kinds. */
	target: string;
	operation?: string;
	/** For `posture` rules. */
	sensitivity?: SensitivityLevel;
	/** Only meaningful for risk-category overrides. */
	risk?: RiskClass;
	/**
	 * Pins an `allow-exact` rule to one literal call. Only a rule carrying this
	 * may skip the judge; without it the rule is posture only, because a rule that
	 * names tool and target still leaves every other argument unspecified.
	 */
	argumentsHash?: string;
	/** Working directory an `allow-exact` rule is bound to. Required to skip the judge. */
	cwd?: string;
	/**
	 * Literal argv prefix an `allow-command` rule matches, e.g. `["git", "log"]`.
	 *
	 * A prefix rather than a pattern on purpose: matching happens against parsed
	 * argv tokens, so there is no glob whose `*` could swallow `; curl evil`.
	 */
	command?: readonly string[];
	reason: string;
	createdBy: "user" | "project" | "human-override" | "builtin";
	/** Higher wins. Computed by `ruleSpecificity`. */
	specificity: number;
	source?: string;
}

export type GrantScope = "one-time" | "session" | "persistent";

export interface Grant {
	id: string;
	auditId: string;
	/** Binds the grant to the exact literal call. */
	argumentsHash: string;
	canonicalHash: string;
	/** Invalidates every allow grant when configuration or policy changes. */
	policyHash: string;
	/**
	 * Working directory the approved call ran in.
	 *
	 * Required, and checked on consumption. The audit database lives at the
	 * user-level agent directory and is shared by every project, and two checkouts
	 * with no project config resolve to the same `policyHash` — so without this a
	 * grant approved in one repository would admit a byte-identical call in
	 * another. That matters most for a persistent grant, which outlives the
	 * session that minted it.
	 */
	cwd: string;
	scope: GrantScope;
	expiresAt: number;
	consumedAt?: number;
	createdBy: string;
	reason: string;
}

// ---------------------------------------------------------------------------
// Pending approvals
// ---------------------------------------------------------------------------

export type PendingState = "awaiting-human" | "approved-intent" | "approved-granted" | "denied" | "expired";

/**
 * Durable, fully redacted escalation record. Holds no raw arguments, which is
 * precisely why it can outlive `brokerArgsTtl` and stay actionable for
 * `pendingApprovalTtl`.
 */
export interface PendingApproval {
	auditId: string;
	toolName: string;
	operation: string;
	/** Redacted target summary. */
	targetSummary: string;
	risk: RiskClass;
	rationale: string;
	argumentsHash: string;
	canonicalHash: string;
	policyHash: string;
	nonce: string;
	sourceAgentId: string;
	parentAgentId?: string;
	/** Working directory the call came from. Shown on review; binds any minted grant. */
	cwd: string;
	state: PendingState;
	createdAt: number;
	expiresAt: number;
	/** Attempts absorbed under strike exemption while awaiting a human. */
	exemptAttempts: number;
	/** Set once an `approved-intent` record spends its single re-open attempt. */
	reopenConsumedAt?: number;
	resolvedAt?: number;
}

// ---------------------------------------------------------------------------
// Human decisions
// ---------------------------------------------------------------------------

export interface HumanDecision {
	auditId: string;
	/** Must equal the request nonce exactly. Any mismatch is a block. */
	nonce: string;
	choice: "allow-once" | "deny";
	/** Recomputed from the literal frozen arguments at decision time. */
	argumentsHash: string;
	decidedAt: number;
}

export interface EscalationRequest {
	auditId: string;
	nonce: string;
	frozenCall: FrozenCall;
	canonicalCall: CanonicalCall;
	risk: RiskClass;
	rationale: string;
	sourceAgentId: string;
	sourceAgentKind: string;
	parentAgentId?: string;
	/** Absolute epoch ms the dialog must close by. */
	expiresAt: number;
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/**
 * The only shape the store accepts for a terminal decision. Every field is
 * already redacted; there is no path from {@link GateRequest} to this type that
 * does not go through the redactor.
 */
export interface AuditRecord {
	auditId: string;
	toolCallId: string;
	toolName: string;
	operation: string;
	targetSummary: string;
	argumentsHash: string;
	canonicalHash: string;
	policyHash: string;
	sourceAgentId: string;
	sourceAgentKind: string;
	parentAgentId?: string;
	/** Working directory the call came from. */
	cwd: string;
	decision: Decision;
	stage: GateStage;
	risk: RiskClass;
	rationale: string;
	matchedRuleId?: string;
	judgeModel?: string;
	judgeProvider?: string;
	judgeLatencyMs?: number;
	judgeAttempts?: number;
	inputTokens?: number;
	outputTokens?: number;
	costUsd?: number;
	retryFamilyKey: string;
	retryCount: number;
	createdAt: number;
}

export type AuditEventType =
	| "judged"
	| "escalated"
	| "blocked"
	| "allowed"
	| "overridden"
	| "expired"
	| "retried"
	| "revoked"
	| "granted"
	| "intent-recorded"
	| "denied"
	| "bypass-enabled"
	| "bypass-disabled"
	| "loop-broken";

export interface AuditEvent {
	auditId: string;
	type: AuditEventType;
	detail: string;
	actor: string;
	at: number;
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

/**
 * Everything the gate needs from the outside world. Tests and the smoke harness
 * inject these; the shipped default factory always constructs real ones.
 */
export interface GatePorts {
	classifyHostApproval(request: GateRequest): Promise<HostApproval>;
	judge(input: JudgeInput, signal: AbortSignal): Promise<JudgeResult>;
	/**
	 * Best-effort in-handler dialog. Returns `undefined` for no UI, cancellation,
	 * or timeout — all of which the orchestrator treats as "no human answer",
	 * never as approval.
	 */
	escalate(request: EscalationRequest, signal: AbortSignal): Promise<HumanDecision | undefined>;
	now(): number;
	randomNonce(): string;
	randomId(): string;
}
