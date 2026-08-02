/**
 * Durable, redacted state: audit calls, append-only audit events, rules,
 * grants, pending approvals, and retry families.
 *
 * Four rules govern this module:
 *
 * 1. **Audit is part of the safety transaction.** `commitAudit` is a synchronous
 *    durable write. Every failure propagates; the gate turns a store failure into
 *    escalate or block. Nothing here ever swallows a write error, because a
 *    swallowed error means an unaudited allow.
 * 2. **Nothing raw reaches the disk.** Callers hand over already-redacted values,
 *    and every write is additionally screened by {@link guardWrite} — a
 *    defense-in-depth backstop that rejects credential-shaped strings and any
 *    object carrying a raw-argument-bearing key.
 * 3. **Verdicts and events are append-only.** SQLite triggers, not convention,
 *    forbid rewriting a terminal verdict or mutating an audit event. An override
 *    is a new event linked to the original audit id.
 * 4. **Single-use means single-use.** Grant consumption and escalation re-open are
 *    one atomic conditional `UPDATE ... RETURNING` each, so two concurrent
 *    attempts produce exactly one winner regardless of process or connection.
 *
 * Referential ordering: `audit_events`, `grants`, and `pending_approvals` all
 * carry a foreign key to `audit_calls`, and foreign keys are enforced. Callers
 * must therefore call {@link SmartApproveStore.beginAudit} before recording any
 * event, grant, or escalation for that audit id.
 */

import { Database } from "bun:sqlite";
import { chmodSync, mkdirSync } from "node:fs";
import path from "node:path";
import type {
	AuditEvent,
	AuditEventType,
	AuditRecord,
	Decision,
	GateStage,
	Grant,
	GrantScope,
	PendingApproval,
	PendingState,
	PolicyRule,
	RiskClass,
	RuleKind,
	SensitivityLevel,
} from "./contracts.ts";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** A value or key reached the write path that must never be persisted. */
export class StoreRedactionError extends Error {
	readonly field: string;
	readonly shape: string;

	constructor(field: string, shape: string) {
		super(`smart-approve: refused to persist ${field} (${shape}); the value was not redacted`);
		this.name = "StoreRedactionError";
		this.field = field;
		this.shape = shape;
	}
}

/** The on-disk schema cannot be reconciled with this build. */
export class StoreMigrationError extends Error {
	constructor(message: string) {
		super(`smart-approve: ${message}`);
		this.name = "StoreMigrationError";
	}
}

/** A state machine transition was attempted from a terminal state. */
export class StoreStateError extends Error {
	constructor(message: string) {
		super(`smart-approve: ${message}`);
		this.name = "StoreStateError";
	}
}

// ---------------------------------------------------------------------------
// Serialization guard
// ---------------------------------------------------------------------------

/**
 * Keys whose values are, by construction, raw model input. Nothing carrying one
 * may be handed to the store — the caller must project it into hashes and a
 * redacted summary first.
 */
const FORBIDDEN_KEYS: Record<string, true> = {
	rawArguments: true,
	content: true,
	command: true,
	arguments: true,
};

/** Credential shapes the OMP obfuscator is expected to have already replaced. */
const CREDENTIAL_SHAPES: Record<string, RegExp> = {
	"private-key-header": /-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----/,
	"api-token": /\bsk-[A-Za-z0-9_-]{16,}/,
	"github-token": /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}/,
	"github-pat": /\bgithub_pat_[A-Za-z0-9_]{20,}/,
	"aws-access-key-id": /\bAKIA[0-9A-Z]{16}\b/,
	"base64url-jwt": /\beyJ[A-Za-z0-9_-]{20,}/,
};

const CREDENTIAL_ENTRIES = Object.entries(CREDENTIAL_SHAPES);

function guardValue(field: string, value: unknown): void {
	if (typeof value === "string") {
		for (const [shape, pattern] of CREDENTIAL_ENTRIES) {
			if (pattern.test(value)) {
				throw new StoreRedactionError(field, shape);
			}
		}
		return;
	}
	if (Array.isArray(value)) {
		for (let i = 0; i < value.length; i++) {
			guardValue(`${field}[${i}]`, value[i]);
		}
		return;
	}
	if (typeof value === "object" && value !== null) {
		guardWrite(field, value);
	}
}

/**
 * Screen an inbound record before any write. Rejects raw-argument-bearing keys
 * anywhere in the object graph and credential-shaped strings anywhere in it.
 *
 * This is a backstop, not the primary redactor: `src/context.ts` runs the OMP
 * obfuscator on the way in. Reaching a throw here means an upstream leak.
 */
export function guardWrite(source: string, record: object): void {
	// Own keys of any object are strings; every value stays `unknown` from here.
	const entries: Array<[string, unknown]> = Object.entries(record);
	for (const [key, value] of entries) {
		const field = `${source}.${key}`;
		if (FORBIDDEN_KEYS[key] === true) {
			throw new StoreRedactionError(field, "raw-argument key");
		}
		guardValue(field, value);
	}
}

// ---------------------------------------------------------------------------
// Session entry
// ---------------------------------------------------------------------------

/**
 * The only projection of a decision that may be appended to session history:
 * identifiers and taxonomy, never the call, the target, or the rationale.
 */
export function serializeSessionEntry(record: AuditRecord): string {
	return JSON.stringify({
		v: 1,
		auditId: record.auditId,
		decision: record.decision,
		stage: record.stage,
		risk: record.risk,
		retryFamilyKey: record.retryFamilyKey,
		retryCount: record.retryCount,
	});
}

// ---------------------------------------------------------------------------
// Migrations
// ---------------------------------------------------------------------------

export interface Migration {
	readonly version: number;
	/** Must be individually idempotent so a partially applied database heals. */
	readonly statements: readonly string[];
}

const MIGRATION_1: readonly string[] = [
	`CREATE TABLE IF NOT EXISTS audit_calls (
		audit_id TEXT PRIMARY KEY,
		tool_call_id TEXT NOT NULL,
		tool_name TEXT NOT NULL,
		operation TEXT NOT NULL,
		target_summary TEXT NOT NULL,
		arguments_hash TEXT NOT NULL,
		canonical_hash TEXT NOT NULL,
		policy_hash TEXT NOT NULL,
		source_agent_id TEXT NOT NULL,
		source_agent_kind TEXT NOT NULL,
		parent_agent_id TEXT,
		decision TEXT CHECK (decision IS NULL OR decision IN ('allow', 'escalate', 'block')),
		stage TEXT,
		risk TEXT,
		rationale TEXT,
		matched_rule_id TEXT,
		judge_model TEXT,
		judge_provider TEXT,
		judge_latency_ms INTEGER,
		judge_attempts INTEGER,
		input_tokens INTEGER,
		output_tokens INTEGER,
		cost_usd REAL,
		retry_family_key TEXT NOT NULL,
		retry_count INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL,
		committed_at INTEGER
	)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_calls_created ON audit_calls (created_at)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_calls_family ON audit_calls (retry_family_key)`,
	`CREATE TRIGGER IF NOT EXISTS audit_calls_verdict_immutable
		BEFORE UPDATE ON audit_calls
		WHEN OLD.decision IS NOT NULL
			AND (NEW.decision IS NOT OLD.decision
				OR NEW.stage IS NOT OLD.stage
				OR NEW.risk IS NOT OLD.risk
				OR NEW.rationale IS NOT OLD.rationale)
		BEGIN SELECT RAISE(ABORT, 'smart-approve: terminal verdict is immutable'); END`,
	`CREATE TABLE IF NOT EXISTS audit_events (
		event_id INTEGER PRIMARY KEY AUTOINCREMENT,
		audit_id TEXT NOT NULL REFERENCES audit_calls (audit_id),
		type TEXT NOT NULL,
		detail TEXT NOT NULL,
		actor TEXT NOT NULL,
		at INTEGER NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_events_audit ON audit_events (audit_id, event_id)`,
	`CREATE TRIGGER IF NOT EXISTS audit_events_no_update
		BEFORE UPDATE ON audit_events
		BEGIN SELECT RAISE(ABORT, 'smart-approve: audit_events is append-only'); END`,
	`CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
		BEFORE DELETE ON audit_events
		BEGIN SELECT RAISE(ABORT, 'smart-approve: audit_events is append-only'); END`,
	`CREATE TABLE IF NOT EXISTS rules (
		id TEXT PRIMARY KEY,
		kind TEXT NOT NULL,
		tool_name TEXT NOT NULL,
		target TEXT NOT NULL,
		operation TEXT,
		sensitivity TEXT,
		risk TEXT,
		reason TEXT NOT NULL,
		created_by TEXT NOT NULL,
		specificity INTEGER NOT NULL,
		source TEXT,
		created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000)
	)`,
	`CREATE TABLE IF NOT EXISTS grants (
		id TEXT PRIMARY KEY,
		audit_id TEXT NOT NULL REFERENCES audit_calls (audit_id),
		arguments_hash TEXT NOT NULL,
		canonical_hash TEXT NOT NULL,
		policy_hash TEXT NOT NULL,
		scope TEXT NOT NULL CHECK (scope IN ('one-time', 'session', 'persistent')),
		expires_at INTEGER NOT NULL,
		consumed_at INTEGER,
		created_by TEXT NOT NULL,
		reason TEXT NOT NULL,
		created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER) * 1000)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_grants_lookup ON grants (arguments_hash, policy_hash)`,
	`CREATE INDEX IF NOT EXISTS idx_grants_policy ON grants (policy_hash)`,
	`CREATE TABLE IF NOT EXISTS pending_approvals (
		audit_id TEXT PRIMARY KEY REFERENCES audit_calls (audit_id),
		tool_name TEXT NOT NULL,
		operation TEXT NOT NULL,
		target_summary TEXT NOT NULL,
		risk TEXT NOT NULL,
		rationale TEXT NOT NULL,
		arguments_hash TEXT NOT NULL,
		canonical_hash TEXT NOT NULL,
		policy_hash TEXT NOT NULL,
		nonce TEXT NOT NULL,
		source_agent_id TEXT NOT NULL,
		parent_agent_id TEXT,
		state TEXT NOT NULL CHECK (
			state IN ('awaiting-human', 'approved-intent', 'approved-granted', 'denied', 'expired')
		),
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		exempt_attempts INTEGER NOT NULL DEFAULT 0,
		reopen_consumed_at INTEGER,
		resolved_at INTEGER
	)`,
	`CREATE INDEX IF NOT EXISTS idx_pending_open ON pending_approvals (state, expires_at)`,
	`CREATE TABLE IF NOT EXISTS retry_families (
		family_key TEXT PRIMARY KEY,
		strikes INTEGER NOT NULL DEFAULT 0,
		first_audit_id TEXT NOT NULL,
		last_audit_id TEXT NOT NULL,
		first_at INTEGER NOT NULL,
		last_at INTEGER NOT NULL
	)`,
];

/**
 * Location identity for audit rows, pending approvals, and grants.
 *
 * The database lives at the user-level agent directory and is shared by every
 * project. Before this, a grant was keyed on (argumentsHash, policyHash) alone —
 * and two checkouts with no project config resolve to the same policyHash — so a
 * grant approved in one repository would admit a byte-identical call in another.
 *
 * The columns are nullable so an existing database upgrades in place. A legacy
 * grant therefore has `cwd IS NULL`, which no equality check can satisfy: it is
 * inert rather than portable, which is the fail-closed direction.
 */
const MIGRATION_2: readonly string[] = [
	"ALTER TABLE audit_calls ADD COLUMN cwd TEXT",
	"ALTER TABLE pending_approvals ADD COLUMN cwd TEXT",
	"ALTER TABLE grants ADD COLUMN cwd TEXT",
	// Without these a stored allow-exact loses the two fields that decide whether
	// it qualifies, and would read back as advisory no matter how it was written.
	"ALTER TABLE rules ADD COLUMN arguments_hash TEXT",
	"ALTER TABLE rules ADD COLUMN cwd TEXT",
	"CREATE INDEX IF NOT EXISTS idx_grants_location ON grants (arguments_hash, policy_hash, cwd)",
];

export const MIGRATIONS: readonly Migration[] = [
	{ version: 1, statements: MIGRATION_1 },
	{ version: 2, statements: MIGRATION_2 },
];

/** Highest migration this build knows how to apply. */
export const SCHEMA_VERSION: number = MIGRATIONS.at(-1)?.version ?? 0;

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/** The in-flight half of an audit row, written before the gate decides. */
export type AuditBegin = Pick<
	AuditRecord,
	| "auditId"
	| "toolCallId"
	| "toolName"
	| "operation"
	| "targetSummary"
	| "argumentsHash"
	| "canonicalHash"
	| "policyHash"
	| "sourceAgentId"
	| "sourceAgentKind"
	| "retryFamilyKey"
	| "cwd"
> & { parentAgentId?: string; createdAt: number };

export interface AuditAggregate {
	total: number;
	allowed: number;
	escalated: number;
	blocked: number;
	avgLatencyMs: number;
	inputTokens: number;
	outputTokens: number;
	costUsd: number;
}

export interface SmartApproveStore {
	/** Opens the audit row. Must precede every event, grant, and escalation for this id. */
	beginAudit(record: AuditBegin): void;
	/**
	 * Durably records the terminal verdict. A scoped call may not return allow
	 * until this returns. Throws — never swallows — on any write failure, and
	 * throws if it would change an already committed verdict.
	 */
	commitAudit(record: AuditRecord): void;
	appendEvent(event: AuditEvent): void;
	/** Committed records only; an audit that is still in flight reads as `undefined`. */
	getAudit(auditId: string): AuditRecord | undefined;
	listEvents(auditId: string): AuditEvent[];

	putGrant(grant: Grant): void;
	/**
	 * Atomic single-use consumption, for every scope. Returns the grant only if
	 * unconsumed, unexpired, location-matched, and policyHash-matched. The gate
	 * admits a call by consuming, so scope decides an unused grant's lifetime and
	 * never how many calls it can admit.
	 */
	consumeGrant(argumentsHash: string, policyHash: string, cwd: string, now: number): Grant | undefined;
	/** Read-only probe: is a grant live right now? Same predicate, no consumption. */
	findGrant(argumentsHash: string, policyHash: string, cwd: string, now: number): Grant | undefined;
	/**
	 * Purges every allow grant *not* bound to the supplied policy hash. Call it
	 * with the **current** hash after configuration or policy changes: any grant
	 * issued under a superseded policy dies. Deny rules live in `rules` and are
	 * deliberately untouched, so tightening policy never widens the gate.
	 */
	revokeGrantsForPolicy(policyHash: string, cwd: string, now: number): number;
	/**
	 * Drop every live grant in every working directory.
	 *
	 * Deliberately global, unlike {@link revokeGrantsForPolicy}. That one runs
	 * automatically on session start, where a global sweep would let one project
	 * delete another's grants on every launch. This one backs an explicit operator
	 * revoke: the human is pulling a safety lever, over-revoking costs one
	 * re-approval, and under-revoking would leave a grant live in another checkout
	 * after they revoked the rule they believed authorized it.
	 *
	 * Only LIVE grants are removed. A consumed grant records what actually ran and
	 * an expired one records what lapsed; both are audit history {@link listGrants}
	 * promises to keep, and neither can admit anything, so deleting them would
	 * destroy evidence to no security benefit. The returned count is therefore the
	 * number of grants that could still have admitted a call.
	 */
	revokeAllGrants(now: number): number;
	/** Every grant, live or spent, newest first, so the operator can audit history. */
	listGrants(): Grant[];

	putRule(rule: PolicyRule): void;
	listRules(): PolicyRule[];
	revokeRule(id: string): boolean;

	/** Creates or refreshes an open escalation. Refuses to reopen a resolved one. */
	putPending(pending: PendingApproval): void;
	getPending(auditId: string): PendingApproval | undefined;
	listOpenPending(now: number): PendingApproval[];
	updatePendingState(auditId: string, state: PendingState, at: number): boolean;
	incrementExemptAttempts(auditId: string): number;
	/**
	 * Single-use and time-bound: returns true only for the first call against an
	 * unspent `approved-intent` record whose `expiresAt` is still in the future.
	 * `at` is both the consumption stamp and the deadline check, so an approval
	 * that timed out fails closed even before {@link expirePending} runs.
	 */
	consumeReopen(auditId: string, at: number): boolean;
	/**
	 * Sweeps timed-out waits into `expired` and returns how many closed. Only
	 * `awaiting-human` records are swept: an `approved-intent` record carries a
	 * human decision worth keeping, and {@link listOpenPending} already hides it
	 * once its deadline passes.
	 */
	expirePending(now: number): number;

	/** Upserts the family and returns the new strike count. */
	recordStrike(familyKey: string, auditId: string, at: number): number;
	getStrikes(familyKey: string): number;
	clearFamily(familyKey: string): void;

	/** Committed decisions with `createdAt` inside `[sinceMs, now]` (absolute epoch ms). */
	aggregate(sinceMs: number, now: number): AuditAggregate;
	close(): void;
}

export interface OpenStoreOptions {
	/** SQLite lock wait before `SQLITE_BUSY`. Bounded so a stuck peer cannot hang a tool call. */
	busyTimeoutMs?: number;
	/** @internal Overridable only so the migration runner itself is testable. */
	migrations?: readonly Migration[];
}

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

/**
 * Column unions mirror the write path, which is the only producer of these
 * values. `decision`, `scope`, and `state` are additionally CHECK-constrained;
 * `risk`, `stage`, and `kind` are open taxonomies kept free of constraints so a
 * taxonomy bump does not require a schema migration.
 */
interface AuditRow {
	audit_id: string;
	tool_call_id: string;
	tool_name: string;
	operation: string;
	target_summary: string;
	arguments_hash: string;
	canonical_hash: string;
	policy_hash: string;
	source_agent_id: string;
	source_agent_kind: string;
	parent_agent_id: string | null;
	decision: Decision;
	stage: GateStage;
	risk: RiskClass;
	rationale: string;
	matched_rule_id: string | null;
	judge_model: string | null;
	judge_provider: string | null;
	judge_latency_ms: number | null;
	judge_attempts: number | null;
	input_tokens: number | null;
	output_tokens: number | null;
	cost_usd: number | null;
	retry_family_key: string;
	retry_count: number;
	created_at: number;
	/** Null only for rows written before migration 2. */
	cwd: string | null;
}

interface EventRow {
	audit_id: string;
	type: AuditEventType;
	detail: string;
	actor: string;
	at: number;
}

interface GrantRow {
	id: string;
	audit_id: string;
	arguments_hash: string;
	canonical_hash: string;
	policy_hash: string;
	scope: GrantScope;
	expires_at: number;
	consumed_at: number | null;
	created_by: string;
	reason: string;
	/** Null only for grants written before migration 2; such a grant can never match. */
	cwd: string | null;
}

interface RuleRow {
	id: string;
	kind: RuleKind;
	tool_name: string;
	target: string;
	arguments_hash: string | null;
	cwd: string | null;
	operation: string | null;
	sensitivity: SensitivityLevel | null;
	risk: RiskClass | null;
	reason: string;
	created_by: PolicyRule["createdBy"];
	specificity: number;
	source: string | null;
}

interface PendingRow {
	audit_id: string;
	tool_name: string;
	operation: string;
	target_summary: string;
	risk: RiskClass;
	rationale: string;
	arguments_hash: string;
	canonical_hash: string;
	policy_hash: string;
	nonce: string;
	source_agent_id: string;
	parent_agent_id: string | null;
	state: PendingState;
	created_at: number;
	expires_at: number;
	exempt_attempts: number;
	reopen_consumed_at: number | null;
	resolved_at: number | null;
	cwd: string | null;
}

// `exactOptionalPropertyTypes` forbids `{ key: undefined }`, so a NULL column
// must be spread away rather than assigned.

function toAudit(row: AuditRow): AuditRecord {
	return {
		auditId: row.audit_id,
		toolCallId: row.tool_call_id,
		toolName: row.tool_name,
		operation: row.operation,
		targetSummary: row.target_summary,
		argumentsHash: row.arguments_hash,
		canonicalHash: row.canonical_hash,
		policyHash: row.policy_hash,
		sourceAgentId: row.source_agent_id,
		sourceAgentKind: row.source_agent_kind,
		...(row.parent_agent_id === null ? {} : { parentAgentId: row.parent_agent_id }),
		decision: row.decision,
		stage: row.stage,
		risk: row.risk,
		rationale: row.rationale,
		...(row.matched_rule_id === null ? {} : { matchedRuleId: row.matched_rule_id }),
		...(row.judge_model === null ? {} : { judgeModel: row.judge_model }),
		...(row.judge_provider === null ? {} : { judgeProvider: row.judge_provider }),
		...(row.judge_latency_ms === null ? {} : { judgeLatencyMs: row.judge_latency_ms }),
		...(row.judge_attempts === null ? {} : { judgeAttempts: row.judge_attempts }),
		...(row.input_tokens === null ? {} : { inputTokens: row.input_tokens }),
		...(row.output_tokens === null ? {} : { outputTokens: row.output_tokens }),
		...(row.cost_usd === null ? {} : { costUsd: row.cost_usd }),
		cwd: row.cwd ?? "",
		retryFamilyKey: row.retry_family_key,
		retryCount: row.retry_count,
		createdAt: row.created_at,
	};
}

function toGrant(row: GrantRow): Grant {
	return {
		id: row.id,
		auditId: row.audit_id,
		argumentsHash: row.arguments_hash,
		canonicalHash: row.canonical_hash,
		policyHash: row.policy_hash,
		scope: row.scope,
		expiresAt: row.expires_at,
		...(row.consumed_at === null ? {} : { consumedAt: row.consumed_at }),
		cwd: row.cwd ?? "",
		createdBy: row.created_by,
		reason: row.reason,
	};
}

function toRule(row: RuleRow): PolicyRule {
	return {
		id: row.id,
		kind: row.kind,
		toolName: row.tool_name,
		target: row.target,
		...(row.arguments_hash === null ? {} : { argumentsHash: row.arguments_hash }),
		...(row.cwd === null ? {} : { cwd: row.cwd }),
		...(row.operation === null ? {} : { operation: row.operation }),
		...(row.sensitivity === null ? {} : { sensitivity: row.sensitivity }),
		...(row.risk === null ? {} : { risk: row.risk }),
		reason: row.reason,
		createdBy: row.created_by,
		specificity: row.specificity,
		...(row.source === null ? {} : { source: row.source }),
	};
}

function toPending(row: PendingRow): PendingApproval {
	return {
		auditId: row.audit_id,
		toolName: row.tool_name,
		operation: row.operation,
		targetSummary: row.target_summary,
		risk: row.risk,
		rationale: row.rationale,
		argumentsHash: row.arguments_hash,
		canonicalHash: row.canonical_hash,
		policyHash: row.policy_hash,
		nonce: row.nonce,
		sourceAgentId: row.source_agent_id,
		...(row.parent_agent_id === null ? {} : { parentAgentId: row.parent_agent_id }),
		state: row.state,
		createdAt: row.created_at,
		expiresAt: row.expires_at,
		cwd: row.cwd ?? "",
		exemptAttempts: row.exempt_attempts,
		...(row.reopen_consumed_at === null ? {} : { reopenConsumedAt: row.reopen_consumed_at }),
		...(row.resolved_at === null ? {} : { resolvedAt: row.resolved_at }),
	};
}

const AUDIT_COLUMNS = `audit_id, tool_call_id, tool_name, operation, target_summary, arguments_hash, canonical_hash,
	policy_hash, source_agent_id, source_agent_kind, parent_agent_id, decision, stage, risk, rationale,
	matched_rule_id, judge_model, judge_provider, judge_latency_ms, judge_attempts, input_tokens, output_tokens,
	cost_usd, retry_family_key, retry_count, created_at, cwd`;

const GRANT_COLUMNS = `id, audit_id, arguments_hash, canonical_hash, policy_hash, scope, expires_at, consumed_at,
	created_by, reason, cwd`;

const RULE_COLUMNS = `id, kind, tool_name, target, arguments_hash, cwd, operation, sensitivity, risk, reason,
	created_by, specificity, source`;

const PENDING_COLUMNS = `audit_id, tool_name, operation, target_summary, risk, rationale, arguments_hash,
	canonical_hash, policy_hash, nonce, source_agent_id, parent_agent_id, state, created_at, expires_at,
	exempt_attempts, reopen_consumed_at, resolved_at, cwd`;

/**
 * A grant that could still admit a call. Anything else is spent history: it can
 * authorize nothing, so revocation leaves it alone rather than erasing evidence.
 */
const LIVE_GRANT = "consumed_at IS NULL AND expires_at > ?";

/** States a record may still leave. Everything else is terminal and immutable. */
const OPEN_STATES = "('awaiting-human', 'approved-intent')";

/** Which states stamp `resolved_at`. Exhaustive by type, so a new state must decide. */
const IS_TERMINAL: Record<PendingState, boolean> = {
	"awaiting-human": false,
	"approved-intent": false,
	"approved-granted": true,
	denied: true,
	expired: true,
};

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

class SqliteStore implements SmartApproveStore {
	private readonly db: Database;
	private closed = false;

	constructor(db: Database) {
		this.db = db;
	}

	beginAudit(record: AuditBegin): void {
		guardWrite("beginAudit", record);
		this.db
			.query(
				`INSERT INTO audit_calls (audit_id, tool_call_id, tool_name, operation, target_summary,
					arguments_hash, canonical_hash, policy_hash, source_agent_id, source_agent_kind,
					parent_agent_id, retry_family_key, created_at, cwd)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (audit_id) DO NOTHING`,
			)
			.run(
				record.auditId,
				record.toolCallId,
				record.toolName,
				record.operation,
				record.targetSummary,
				record.argumentsHash,
				record.canonicalHash,
				record.policyHash,
				record.sourceAgentId,
				record.sourceAgentKind,
				record.parentAgentId ?? null,
				record.retryFamilyKey,
				record.createdAt,
				record.cwd,
			);
	}

	commitAudit(record: AuditRecord): void {
		guardWrite("commitAudit", record);
		this.db
			.query(
				`INSERT INTO audit_calls (${AUDIT_COLUMNS}, committed_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (audit_id) DO UPDATE SET
					decision = excluded.decision,
					stage = excluded.stage,
					risk = excluded.risk,
					rationale = excluded.rationale,
					target_summary = excluded.target_summary,
					matched_rule_id = excluded.matched_rule_id,
					judge_model = excluded.judge_model,
					judge_provider = excluded.judge_provider,
					judge_latency_ms = excluded.judge_latency_ms,
					judge_attempts = excluded.judge_attempts,
					input_tokens = excluded.input_tokens,
					output_tokens = excluded.output_tokens,
					cost_usd = excluded.cost_usd,
					retry_count = excluded.retry_count,
					committed_at = excluded.committed_at`,
			)
			.run(
				record.auditId,
				record.toolCallId,
				record.toolName,
				record.operation,
				record.targetSummary,
				record.argumentsHash,
				record.canonicalHash,
				record.policyHash,
				record.sourceAgentId,
				record.sourceAgentKind,
				record.parentAgentId ?? null,
				record.decision,
				record.stage,
				record.risk,
				record.rationale,
				record.matchedRuleId ?? null,
				record.judgeModel ?? null,
				record.judgeProvider ?? null,
				record.judgeLatencyMs ?? null,
				record.judgeAttempts ?? null,
				record.inputTokens ?? null,
				record.outputTokens ?? null,
				record.costUsd ?? null,
				record.retryFamilyKey,
				record.retryCount,
				record.createdAt,
				record.cwd,
				record.createdAt,
			);
	}

	appendEvent(event: AuditEvent): void {
		guardWrite("appendEvent", event);
		this.db
			.query(`INSERT INTO audit_events (audit_id, type, detail, actor, at) VALUES (?, ?, ?, ?, ?)`)
			.run(event.auditId, event.type, event.detail, event.actor, event.at);
	}

	getAudit(auditId: string): AuditRecord | undefined {
		const row = this.db
			.query<AuditRow, [string]>(
				`SELECT ${AUDIT_COLUMNS} FROM audit_calls WHERE audit_id = ? AND decision IS NOT NULL`,
			)
			.get(auditId);
		return row === null ? undefined : toAudit(row);
	}

	listEvents(auditId: string): AuditEvent[] {
		return this.db
			.query<EventRow, [string]>(
				`SELECT audit_id, type, detail, actor, at FROM audit_events WHERE audit_id = ? ORDER BY event_id ASC`,
			)
			.all(auditId)
			.map(row => ({ auditId: row.audit_id, type: row.type, detail: row.detail, actor: row.actor, at: row.at }));
	}

	putGrant(grant: Grant): void {
		guardWrite("putGrant", grant);
		this.db
			.query(
				`INSERT INTO grants (${GRANT_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (id) DO UPDATE SET
					expires_at = excluded.expires_at,
					consumed_at = excluded.consumed_at,
					reason = excluded.reason`,
			)
			.run(
				grant.id,
				grant.auditId,
				grant.argumentsHash,
				grant.canonicalHash,
				grant.policyHash,
				grant.scope,
				grant.expiresAt,
				grant.consumedAt ?? null,
				grant.createdBy,
				grant.reason,
				grant.cwd,
			);
	}

	/**
	 * Atomic single-use consumption, bound to the working directory the human
	 * approved from. A legacy row migrated in with `cwd IS NULL` never matches,
	 * so it is inert rather than portable.
	 */
	consumeGrant(argumentsHash: string, policyHash: string, cwd: string, now: number): Grant | undefined {
		const row = this.db
			.query<GrantRow, [number, string, string, string, number]>(
				`UPDATE grants SET consumed_at = ?
				WHERE id = (
					SELECT id FROM grants
					WHERE arguments_hash = ? AND policy_hash = ? AND cwd = ?
						AND consumed_at IS NULL AND expires_at > ?
					ORDER BY expires_at ASC
					LIMIT 1
				)
				RETURNING ${GRANT_COLUMNS}`,
			)
			.get(now, argumentsHash, policyHash, cwd, now);
		return row === null ? undefined : toGrant(row);
	}

	findGrant(argumentsHash: string, policyHash: string, cwd: string, now: number): Grant | undefined {
		const row = this.db
			.query<GrantRow, [string, string, string, number]>(
				`SELECT ${GRANT_COLUMNS} FROM grants
				WHERE arguments_hash = ? AND policy_hash = ? AND cwd = ?
					AND consumed_at IS NULL AND expires_at > ?
				ORDER BY expires_at DESC
				LIMIT 1`,
			)
			.get(argumentsHash, policyHash, cwd, now);
		return row === null ? undefined : toGrant(row);
	}

	/**
	 * Purge grants for THIS working directory that are bound to a superseded
	 * policy hash.
	 *
	 * Scoped to `cwd` deliberately. The database is shared across projects, so an
	 * unscoped sweep would let a policy edit in one repository delete grants a
	 * human minted in another — grants whose own policy never changed. Each
	 * project revokes its own stale grants when its next session starts.
	 */
	revokeGrantsForPolicy(policyHash: string, cwd: string, now: number): number {
		return this.db
			.query(`DELETE FROM grants WHERE cwd = ? AND policy_hash <> ? AND ${LIVE_GRANT}`)
			.run(cwd, policyHash, now).changes;
	}

	revokeAllGrants(now: number): number {
		return this.db.query(`DELETE FROM grants WHERE ${LIVE_GRANT}`).run(now).changes;
	}

	listGrants(): Grant[] {
		return this.db
			.query<GrantRow, []>(`SELECT ${GRANT_COLUMNS} FROM grants ORDER BY created_at DESC, rowid DESC`)
			.all()
			.map(toGrant);
	}

	putRule(rule: PolicyRule): void {
		guardWrite("putRule", rule);
		this.db
			.query(
				`INSERT INTO rules (${RULE_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (id) DO UPDATE SET
					kind = excluded.kind,
					tool_name = excluded.tool_name,
					target = excluded.target,
					arguments_hash = excluded.arguments_hash,
					cwd = excluded.cwd,
					operation = excluded.operation,
					sensitivity = excluded.sensitivity,
					risk = excluded.risk,
					reason = excluded.reason,
					created_by = excluded.created_by,
					specificity = excluded.specificity,
					source = excluded.source`,
			)
			.run(
				rule.id,
				rule.kind,
				rule.toolName,
				rule.target,
				rule.argumentsHash ?? null,
				rule.cwd ?? null,
				rule.operation ?? null,
				rule.sensitivity ?? null,
				rule.risk ?? null,
				rule.reason,
				rule.createdBy,
				rule.specificity,
				rule.source ?? null,
			);
	}

	listRules(): PolicyRule[] {
		return this.db
			.query<RuleRow, []>(`SELECT ${RULE_COLUMNS} FROM rules ORDER BY specificity DESC, id ASC`)
			.all()
			.map(toRule);
	}

	revokeRule(id: string): boolean {
		return this.db.query(`DELETE FROM rules WHERE id = ?`).run(id).changes > 0;
	}

	putPending(pending: PendingApproval): void {
		guardWrite("putPending", pending);
		const result = this.db
			.query(
				`INSERT INTO pending_approvals (${PENDING_COLUMNS})
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (audit_id) DO UPDATE SET
					risk = excluded.risk,
					rationale = excluded.rationale,
					target_summary = excluded.target_summary,
					nonce = excluded.nonce,
					state = excluded.state,
					expires_at = excluded.expires_at,
					exempt_attempts = excluded.exempt_attempts,
					reopen_consumed_at = excluded.reopen_consumed_at,
					resolved_at = excluded.resolved_at
				WHERE pending_approvals.state IN ${OPEN_STATES}`,
			)
			.run(
				pending.auditId,
				pending.toolName,
				pending.operation,
				pending.targetSummary,
				pending.risk,
				pending.rationale,
				pending.argumentsHash,
				pending.canonicalHash,
				pending.policyHash,
				pending.nonce,
				pending.sourceAgentId,
				pending.parentAgentId ?? null,
				pending.state,
				pending.createdAt,
				pending.expiresAt,
				pending.exemptAttempts,
				pending.reopenConsumedAt ?? null,
				pending.resolvedAt ?? null,
				pending.cwd,
			);
		if (result.changes === 0) {
			throw new StoreStateError(`escalation ${pending.auditId} is already resolved and cannot be reopened`);
		}
	}

	getPending(auditId: string): PendingApproval | undefined {
		const row = this.db
			.query<PendingRow, [string]>(`SELECT ${PENDING_COLUMNS} FROM pending_approvals WHERE audit_id = ?`)
			.get(auditId);
		return row === null ? undefined : toPending(row);
	}

	listOpenPending(now: number): PendingApproval[] {
		return this.db
			.query<PendingRow, [number]>(
				`SELECT ${PENDING_COLUMNS} FROM pending_approvals
				WHERE state IN ${OPEN_STATES} AND expires_at > ?
				ORDER BY created_at DESC, audit_id ASC`,
			)
			.all(now)
			.map(toPending);
	}

	updatePendingState(auditId: string, state: PendingState, at: number): boolean {
		const resolvedAt = IS_TERMINAL[state] ? at : null;
		return (
			this.db
				.query(
					`UPDATE pending_approvals SET state = ?, resolved_at = ?
					WHERE audit_id = ? AND state IN ${OPEN_STATES}`,
				)
				.run(state, resolvedAt, auditId).changes > 0
		);
	}

	incrementExemptAttempts(auditId: string): number {
		const row = this.db
			.query<{ exempt_attempts: number }, [string]>(
				`UPDATE pending_approvals SET exempt_attempts = exempt_attempts + 1
				WHERE audit_id = ?
				RETURNING exempt_attempts`,
			)
			.get(auditId);
		return row === null ? 0 : row.exempt_attempts;
	}

	consumeReopen(auditId: string, at: number): boolean {
		const row = this.db
			.query<{ audit_id: string }, [number, string, number]>(
				`UPDATE pending_approvals SET reopen_consumed_at = ?
				WHERE audit_id = ? AND state = 'approved-intent' AND reopen_consumed_at IS NULL AND expires_at > ?
				RETURNING audit_id`,
			)
			.get(at, auditId, at);
		return row !== null;
	}

	expirePending(now: number): number {
		return this.db
			.query(
				`UPDATE pending_approvals SET state = 'expired', resolved_at = ?
				WHERE state = 'awaiting-human' AND expires_at <= ?`,
			)
			.run(now, now).changes;
	}

	recordStrike(familyKey: string, auditId: string, at: number): number {
		const row = this.db
			.query<{ strikes: number }, [string, string, string, number, number]>(
				`INSERT INTO retry_families (family_key, strikes, first_audit_id, last_audit_id, first_at, last_at)
				VALUES (?, 1, ?, ?, ?, ?)
				ON CONFLICT (family_key) DO UPDATE SET
					strikes = retry_families.strikes + 1,
					last_audit_id = excluded.last_audit_id,
					last_at = excluded.last_at
				RETURNING strikes`,
			)
			.get(familyKey, auditId, auditId, at, at);
		return row === null ? 0 : row.strikes;
	}

	getStrikes(familyKey: string): number {
		const row = this.db
			.query<{ strikes: number }, [string]>(`SELECT strikes FROM retry_families WHERE family_key = ?`)
			.get(familyKey);
		return row === null ? 0 : row.strikes;
	}

	clearFamily(familyKey: string): void {
		this.db.query(`DELETE FROM retry_families WHERE family_key = ?`).run(familyKey);
	}

	aggregate(sinceMs: number, now: number): AuditAggregate {
		const row = this.db
			.query<AuditAggregate, [number, number]>(
				`SELECT
					COUNT(*) AS total,
					COALESCE(SUM(decision = 'allow'), 0) AS allowed,
					COALESCE(SUM(decision = 'escalate'), 0) AS escalated,
					COALESCE(SUM(decision = 'block'), 0) AS blocked,
					COALESCE(AVG(judge_latency_ms), 0) AS avgLatencyMs,
					COALESCE(SUM(input_tokens), 0) AS inputTokens,
					COALESCE(SUM(output_tokens), 0) AS outputTokens,
					COALESCE(SUM(cost_usd), 0) AS costUsd
				FROM audit_calls
				WHERE decision IS NOT NULL AND created_at >= ? AND created_at <= ?`,
			)
			.get(sinceMs, now);
		if (row === null) {
			return {
				total: 0,
				allowed: 0,
				escalated: 0,
				blocked: 0,
				avgLatencyMs: 0,
				inputTokens: 0,
				outputTokens: 0,
				costUsd: 0,
			};
		}
		return { ...row, avgLatencyMs: Math.round(row.avgLatencyMs) };
	}

	close(): void {
		if (this.closed) {
			return;
		}
		this.closed = true;
		try {
			// Fold the WAL back into the main file so a copied database is complete.
			this.db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
		} catch {
			// A checkpoint failure must not prevent releasing the handle.
		}
		this.db.close(false);
	}
}

// ---------------------------------------------------------------------------
// Open + migrate
// ---------------------------------------------------------------------------

function currentVersion(db: Database): number {
	const row = db.query<{ version: number }, []>(`SELECT version FROM schema_meta WHERE id = 1`).get();
	return row === null ? 0 : row.version;
}

/**
 * Run one migration statement, tolerating the single non-idempotent case SQLite
 * forces on us.
 *
 * `Migration.statements` are contractually individually idempotent so a partially
 * applied database heals on reopen, and every `CREATE` uses `IF NOT EXISTS`.
 * SQLite has no `ADD COLUMN IF NOT EXISTS`, so an already-applied column addition
 * raises "duplicate column name" — which means the statement's intended end state
 * already holds. Only that exact error, and only for `ADD COLUMN`, is swallowed.
 */
function execIdempotent(db: Database, statement: string): void {
	try {
		db.exec(statement);
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		const isAddColumn = /\bALTER\s+TABLE\b[\s\S]*\bADD\s+COLUMN\b/i.test(statement);
		if (isAddColumn && /duplicate column name/i.test(message)) return;
		throw error;
	}
}

function applyMigrations(db: Database, migrations: readonly Migration[]): void {
	db.exec(
		`CREATE TABLE IF NOT EXISTS schema_meta (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			version INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
	);
	const from = currentVersion(db);
	const target = migrations.at(-1)?.version ?? 0;
	if (from > target) {
		throw new StoreMigrationError(
			`database schema version ${from} is newer than this build supports (${target}); upgrade the plugin`,
		);
	}
	if (from === target) {
		return;
	}
	const pending = migrations.filter(migration => migration.version > from);
	// One transaction for the whole upgrade: a failure anywhere leaves the
	// database exactly as it was, including its recorded version.
	db.transaction(() => {
		for (const migration of pending) {
			for (const statement of migration.statements) {
				execIdempotent(db, statement);
			}
		}
		db.query(
			`INSERT INTO schema_meta (id, version, updated_at) VALUES (1, ?, ?)
			ON CONFLICT (id) DO UPDATE SET version = excluded.version, updated_at = excluded.updated_at`,
		).run(target, Date.now());
	})();
}

/**
 * Open (creating if needed) the owner-only state database and bring its schema
 * up to date. Every failure — unwritable directory, corrupt file, unknown future
 * schema — throws, because a gate without durable audit must not run.
 */
export function openStore(databasePath: string, options?: OpenStoreOptions): SmartApproveStore {
	const directory = path.dirname(databasePath);
	mkdirSync(directory, { recursive: true, mode: 0o700 });
	// `recursive` skips the mode for a directory that already existed.
	chmodSync(directory, 0o700);

	const db = new Database(databasePath, { create: true });
	try {
		chmodSync(databasePath, 0o600);
		db.exec("PRAGMA journal_mode = WAL");
		db.exec(`PRAGMA busy_timeout = ${Math.max(0, Math.trunc(options?.busyTimeoutMs ?? 5_000))}`);
		db.exec("PRAGMA foreign_keys = ON");
		applyMigrations(db, options?.migrations ?? MIGRATIONS);
	} catch (error) {
		db.close(false);
		throw error;
	}
	return new SqliteStore(db);
}
