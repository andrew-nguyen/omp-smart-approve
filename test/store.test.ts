import { Database } from "bun:sqlite";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { AuditRecord, EscalationContext, Grant, PendingApproval, PolicyRule } from "../src/contracts.ts";
import {
	type AuditBegin,
	MIGRATIONS,
	type Migration,
	type OpenStoreOptions,
	openStore,
	SCHEMA_VERSION,
	type SmartApproveStore,
	StoreMigrationError,
	StoreStateError,
	serializeSessionEntry,
} from "../src/store.ts";

let root: string;
let dbPath: string;
const opened: SmartApproveStore[] = [];

beforeEach(() => {
	root = mkdtempSync(path.join(os.tmpdir(), "smart-approve-store-"));
	dbPath = path.join(root, "state", "state.sqlite");
});

afterEach(() => {
	for (const store of opened) {
		store.close();
	}
	opened.length = 0;
	rmSync(root, { recursive: true, force: true });
});

function open(options?: OpenStoreOptions): SmartApproveStore {
	const store = openStore(dbPath, options);
	opened.push(store);
	return store;
}

/** Read the file directly, bypassing the store, to inspect what really landed. */
function inspect<T>(read: (db: Database) => T): T {
	const db = new Database(dbPath);
	try {
		return read(db);
	} finally {
		db.close(false);
	}
}

function tableNames(): string[] {
	return inspect(db =>
		db
			.query<{ name: string }, []>(`SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`)
			.all()
			.map(row => row.name),
	);
}

function schemaVersion(): number {
	return inspect(db => {
		const row = db
			.query<{ version: number }, []>(
				`SELECT version FROM schema_meta WHERE id = 1
				AND EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_meta')`,
			)
			.get();
		return row === null ? 0 : row.version;
	});
}

const T0 = 1_700_000_000_000;

function begun(auditId: string, overrides: Partial<AuditBegin> = {}): AuditBegin {
	const base: AuditBegin = {
		auditId,
		toolCallId: `call-${auditId}`,
		toolName: "write",
		operation: "write",
		targetSummary: "path:/repo/src/index.ts",
		argumentsHash: `args-${auditId}`,
		canonicalHash: `canon-${auditId}`,
		policyHash: "policy-1",
		sourceAgentId: "main",
		sourceAgentKind: "main",
		cwd: "/repo/project",
		retryFamilyKey: `family-${auditId}`,
		createdAt: T0,
	};
	return { ...base, ...overrides };
}

function committed(auditId: string, overrides: Partial<AuditRecord> = {}): AuditRecord {
	const base: AuditRecord = {
		...begun(auditId),
		decision: "allow",
		stage: "judge",
		risk: "uncertain",
		rationale: "Writes a source file inside the repository.",
		retryCount: 0,
	};
	return { ...base, ...overrides };
}

/** Every child table carries a foreign key to `audit_calls`, so open the audit first. */
function withAudit(store: SmartApproveStore, auditId: string): SmartApproveStore {
	store.beginAudit(begun(auditId));
	return store;
}

function grantFor(auditId: string, overrides: Partial<Grant> = {}): Grant {
	const base: Grant = {
		id: `grant-${auditId}`,
		auditId,
		argumentsHash: `args-${auditId}`,
		canonicalHash: `canon-${auditId}`,
		policyHash: "policy-1",
		cwd: "/repo/project",
		scope: "one-time",
		expiresAt: T0 + 60_000,
		createdBy: "human",
		reason: "Operator approved this exact call.",
	};
	return { ...base, ...overrides };
}

function pendingFor(auditId: string, overrides: Partial<PendingApproval> = {}): PendingApproval {
	const base: PendingApproval = {
		auditId,
		toolName: "bash",
		operation: "exec",
		targetSummary: "command:git push",
		risk: "destructive-action",
		rationale: "Pushes to a remote branch.",
		argumentsHash: `args-${auditId}`,
		canonicalHash: `canon-${auditId}`,
		policyHash: "policy-1",
		nonce: `nonce-${auditId}`,
		sourceAgentId: "sub-7",
		cwd: "/repo/project",
		state: "awaiting-human",
		createdAt: T0,
		expiresAt: T0 + 60_000,
		exemptAttempts: 0,
	};
	return { ...base, ...overrides };
}

const CONTEXT_FIXTURE: EscalationContext = {
	userIntent: "clean up the branch history",
	agentRationale: "force-pushing the rebased branch",
	rationaleFreshness: "current-turn",
	rationaleFromReasoning: true,
	flaggedBy: "judge",
};

function ruleFor(id: string, overrides: Partial<PolicyRule> = {}): PolicyRule {
	const base: PolicyRule = {
		id,
		kind: "deny-exact",
		toolName: "write",
		target: "/repo/.omp/smart-approve.yml",
		reason: "Protected policy file.",
		createdBy: "builtin",
		specificity: 100,
	};
	return { ...base, ...overrides };
}

describe("migration", () => {
	test("a fresh database is created at the current schema version with every table", () => {
		open();
		expect(schemaVersion()).toBe(SCHEMA_VERSION);
		expect(tableNames()).toEqual([
			"audit_calls",
			"audit_events",
			"grants",
			"pending_approvals",
			"retry_families",
			"rules",
			"schema_meta",
			"sqlite_sequence",
		]);
	});

	test("reopening an up-to-date database preserves rows and leaves the version alone", () => {
		const first = open();
		first.commitAudit(committed("a1"));
		first.close();

		const second = open();
		expect(second.getAudit("a1")?.decision).toBe("allow");
		expect(schemaVersion()).toBe(SCHEMA_VERSION);
	});

	test("an older recorded version replays migrations idempotently without losing data", () => {
		const first = open();
		first.commitAudit(committed("a1"));
		first.close();

		// Simulate a database written by a build that stopped before migration 1.
		inspect(db => db.exec(`UPDATE schema_meta SET version = 0`));
		expect(schemaVersion()).toBe(0);

		const upgraded = open();
		expect(schemaVersion()).toBe(SCHEMA_VERSION);
		expect(upgraded.getAudit("a1")?.decision).toBe("allow");
	});

	test("a database written by an older build gains the new migration's schema", () => {
		const next: Migration = {
			version: SCHEMA_VERSION + 1,
			statements: [`CREATE TABLE IF NOT EXISTS probe (id TEXT PRIMARY KEY)`],
		};
		const first = open();
		first.commitAudit(committed("a1"));
		first.close();
		expect(tableNames()).not.toContain("probe");

		const upgraded = open({ migrations: [...MIGRATIONS, next] });
		expect(schemaVersion()).toBe(SCHEMA_VERSION + 1);
		expect(tableNames()).toContain("probe");
		expect(upgraded.getAudit("a1")?.decision).toBe("allow");
	});

	test("a pending row written before context capture upgrades in place and reads as contextless", () => {
		const legacy = open({ migrations: MIGRATIONS.filter(migration => migration.version <= 2) });
		legacy.beginAudit(begun("a1"));
		legacy.close();
		// Written by that older build: the ctx_* columns do not exist yet.
		inspect(db =>
			db.exec(
				`INSERT INTO pending_approvals (audit_id, tool_name, operation, target_summary, risk, rationale,
					arguments_hash, canonical_hash, policy_hash, nonce, source_agent_id, state, created_at,
					expires_at, exempt_attempts, cwd)
				VALUES ('a1', 'bash', 'exec', 'command:git push', 'destructive-action', 'Pushes to a remote branch.',
					'args-a1', 'canon-a1', 'policy-1', 'nonce-a1', 'sub-7', 'awaiting-human', ${T0},
					${T0 + 60_000}, 0, '/repo/project')`,
			),
		);

		const upgraded = open();

		expect(schemaVersion()).toBe(SCHEMA_VERSION);
		expect(upgraded.getPending("a1")?.nonce).toBe("nonce-a1");
		expect(upgraded.getPending("a1")?.context).toBeUndefined();
		// And the upgraded database accepts context on the next escalation.
		upgraded.beginAudit(begun("a2"));
		upgraded.putPending(pendingFor("a2", { context: CONTEXT_FIXTURE }));
		expect(upgraded.getPending("a2")?.context).toEqual(CONTEXT_FIXTURE);
	});

	test("a database newer than the build refuses to open instead of guessing", () => {
		const next: Migration = {
			version: SCHEMA_VERSION + 1,
			statements: [`CREATE TABLE IF NOT EXISTS probe (id TEXT PRIMARY KEY)`],
		};
		open({ migrations: [...MIGRATIONS, next] }).close();

		expect(() => open()).toThrow(StoreMigrationError);
	});

	test("a failing migration rolls back completely, leaving no partial schema and no version", () => {
		const broken: Migration = {
			version: SCHEMA_VERSION + 1,
			statements: [`CREATE TABLE IF NOT EXISTS probe (id TEXT PRIMARY KEY)`, `THIS IS NOT SQL`],
		};

		expect(() => open({ migrations: [...MIGRATIONS, broken] })).toThrow();
		expect(tableNames()).toEqual(["schema_meta"]);
		expect(schemaVersion()).toBe(0);

		// The database is still usable by a build with a working migration set.
		const recovered = open();
		expect(schemaVersion()).toBe(SCHEMA_VERSION);
		recovered.commitAudit(committed("a1"));
		expect(recovered.getAudit("a1")?.decision).toBe("allow");
	});
});

describe("filesystem posture", () => {
	test("creates the missing state directory owner-only and the database owner-readable", () => {
		open();
		expect(statSync(path.dirname(dbPath)).mode & 0o777).toBe(0o700);
		expect(statSync(dbPath).mode & 0o777).toBe(0o600);
	});

	test("tightens a pre-existing world-readable state directory", () => {
		mkdirSync(path.dirname(dbPath), { recursive: true, mode: 0o755 });
		expect(statSync(path.dirname(dbPath)).mode & 0o777).toBe(0o755);

		open();
		expect(statSync(path.dirname(dbPath)).mode & 0o777).toBe(0o700);
	});
});

describe("concurrency", () => {
	test("a second connection sees committed writes from the first", () => {
		const writer = open();
		const reader = open();
		writer.commitAudit(committed("a1", { decision: "block", stage: "deny-rule" }));
		expect(reader.getAudit("a1")?.decision).toBe("block");

		reader.beginAudit(begun("a2"));
		reader.commitAudit(committed("a2", { decision: "escalate", stage: "escalation" }));
		expect(writer.getAudit("a2")?.decision).toBe("escalate");
	});

	test("a write blocked by another writer fails after the configured busy timeout, not forever", () => {
		open().close();
		const blocker = new Database(dbPath);
		blocker.exec("PRAGMA busy_timeout = 0");
		blocker.exec("BEGIN IMMEDIATE");
		try {
			const store = open({ busyTimeoutMs: 300 });
			const startedAt = performance.now();
			expect(() => store.commitAudit(committed("a1"))).toThrow();
			const elapsed = performance.now() - startedAt;
			expect(elapsed).toBeGreaterThanOrEqual(200);
			expect(elapsed).toBeLessThan(3_000);
		} finally {
			blocker.exec("ROLLBACK");
			blocker.close(false);
		}
	});
});

describe("audit records", () => {
	test("an in-flight audit is not readable as a decision until it commits", () => {
		const store = open();
		store.beginAudit(begun("a1"));
		expect(store.getAudit("a1")).toBeUndefined();

		store.commitAudit(committed("a1", { decision: "escalate", stage: "escalation" }));
		expect(store.getAudit("a1")?.decision).toBe("escalate");
	});

	test("committing keeps the timestamp recorded when the call was first seen", () => {
		const store = open();
		store.beginAudit(begun("a1", { createdAt: T0 }));
		store.commitAudit(committed("a1", { createdAt: T0 + 5_000 }));
		expect(store.getAudit("a1")?.createdAt).toBe(T0);
	});

	test("round-trips every optional field and omits the ones that were never set", () => {
		const store = open();
		const rich = committed("a1", {
			parentAgentId: "main",
			matchedRuleId: "rule-3",
			judgeModel: "some-model",
			judgeProvider: "some-provider",
			judgeLatencyMs: 812,
			judgeAttempts: 2,
			inputTokens: 1200,
			outputTokens: 64,
			costUsd: 0.0031,
			retryCount: 1,
		});
		store.commitAudit(rich);
		expect(store.getAudit("a1")).toEqual(rich);

		store.commitAudit(committed("a2"));
		const lean = store.getAudit("a2");
		expect(lean).toBeDefined();
		expect("judgeModel" in (lean ?? {})).toBe(false);
		expect("parentAgentId" in (lean ?? {})).toBe(false);
	});

	test("re-committing the identical verdict is idempotent", () => {
		const store = open();
		store.commitAudit(committed("a1"));
		expect(() => store.commitAudit(committed("a1"))).not.toThrow();
		expect(store.getAudit("a1")?.decision).toBe("allow");
	});

	test("a committed verdict cannot be rewritten, so an override cannot launder a block", () => {
		const store = open();
		store.commitAudit(committed("a1", { decision: "block", stage: "judge", rationale: "Destructive." }));

		expect(() =>
			store.commitAudit(committed("a1", { decision: "allow", stage: "judge", rationale: "Destructive." })),
		).toThrow();
		expect(store.getAudit("a1")?.decision).toBe("block");
	});

	test("a store failure propagates instead of letting an unaudited call proceed", () => {
		const store = open();
		store.close();
		expect(() => store.commitAudit(committed("a1"))).toThrow();
	});
});

describe("audit events", () => {
	test("events are returned in append order for their audit", () => {
		const store = withAudit(open(), "a1");
		store.appendEvent({ auditId: "a1", type: "judged", detail: "risk=uncertain", actor: "judge", at: T0 + 1 });
		store.appendEvent({ auditId: "a1", type: "blocked", detail: "stage=judge", actor: "gate", at: T0 + 2 });
		store.beginAudit(begun("a2"));
		store.appendEvent({ auditId: "a2", type: "allowed", detail: "stage=local-read", actor: "gate", at: T0 + 3 });

		expect(store.listEvents("a1").map(event => event.type)).toEqual(["judged", "blocked"]);
		expect(store.listEvents("a2").map(event => event.type)).toEqual(["allowed"]);
		expect(store.listEvents("missing")).toEqual([]);
	});

	test("an override is a new event and never rewrites the original verdict", () => {
		const store = open();
		store.commitAudit(committed("a1", { decision: "block", stage: "judge", rationale: "Exfiltration risk." }));
		store.appendEvent({ auditId: "a1", type: "overridden", detail: "human override", actor: "human", at: T0 + 10 });

		const record = store.getAudit("a1");
		expect(record?.decision).toBe("block");
		expect(record?.rationale).toBe("Exfiltration risk.");
		expect(store.listEvents("a1").map(event => event.type)).toEqual(["overridden"]);
	});

	test("recorded events cannot be updated or deleted, even directly in SQL", () => {
		const store = withAudit(open(), "a1");
		store.appendEvent({ auditId: "a1", type: "blocked", detail: "stage=judge", actor: "gate", at: T0 });
		store.close();

		expect(() => inspect(db => db.exec(`UPDATE audit_events SET detail = 'rewritten'`))).toThrow();
		expect(() => inspect(db => db.exec(`DELETE FROM audit_events`))).toThrow();

		const reopened = open();
		expect(reopened.listEvents("a1")[0]?.detail).toBe("stage=judge");
	});

	test("an event for an unknown audit is rejected rather than orphaned", () => {
		const store = open();
		expect(() =>
			store.appendEvent({ auditId: "ghost", type: "judged", detail: "", actor: "judge", at: T0 }),
		).toThrow();
	});
});

describe("grants", () => {
	test("a grant is found before consumption and consumed exactly once", () => {
		const store = withAudit(open(), "a1");
		store.putGrant(grantFor("a1"));

		expect(store.findGrant("args-a1", "policy-1", "/repo/project", T0)?.id).toBe("grant-a1");
		const consumed = store.consumeGrant("args-a1", "policy-1", "/repo/project", T0);
		expect(consumed?.id).toBe("grant-a1");
		expect(consumed?.consumedAt).toBe(T0);
		expect(store.consumeGrant("args-a1", "policy-1", "/repo/project", T0)).toBeUndefined();
		expect(store.findGrant("args-a1", "policy-1", "/repo/project", T0)).toBeUndefined();
	});

	test("two concurrent consumers of one grant produce exactly one winner", async () => {
		withAudit(open(), "a1").putGrant(grantFor("a1"));
		const first = open();
		const second = open();

		const results = await Promise.all([
			Promise.resolve().then(() => first.consumeGrant("args-a1", "policy-1", "/repo/project", T0)),
			Promise.resolve().then(() => second.consumeGrant("args-a1", "policy-1", "/repo/project", T0)),
		]);

		expect(results.filter(grant => grant !== undefined)).toHaveLength(1);
		expect(first.listGrants()[0]?.consumedAt).toBe(T0);
	});

	test("an expired grant is neither found nor consumable", () => {
		const store = withAudit(open(), "a1");
		store.putGrant(grantFor("a1", { expiresAt: T0 + 1_000 }));

		expect(store.findGrant("args-a1", "policy-1", "/repo/project", T0 + 1_000)).toBeUndefined();
		expect(store.consumeGrant("args-a1", "policy-1", "/repo/project", T0 + 1_001)).toBeUndefined();
		expect(store.consumeGrant("args-a1", "policy-1", "/repo/project", T0 + 999)?.id).toBe("grant-a1");
	});

	test("a grant issued under a different policy hash never matches", () => {
		const store = withAudit(open(), "a1");
		store.putGrant(grantFor("a1", { policyHash: "policy-0" }));

		expect(store.findGrant("args-a1", "policy-1", "/repo/project", T0)).toBeUndefined();
		expect(store.consumeGrant("args-a1", "policy-1", "/repo/project", T0)).toBeUndefined();
	});

	test("a policy change purges stale allow grants but leaves deny rules standing", () => {
		const store = open();
		store.beginAudit(begun("a1"));
		store.beginAudit(begun("a2"));
		store.putGrant(grantFor("a1", { policyHash: "policy-0" }));
		store.putGrant(grantFor("a2", { policyHash: "policy-1" }));
		store.putRule(ruleFor("deny-policy-file"));

		expect(store.revokeGrantsForPolicy("policy-1", "/repo/project", T0)).toBe(1);
		expect(store.listGrants().map(grant => grant.id)).toEqual(["grant-a2"]);
		expect(store.listRules().map(rule => rule.id)).toEqual(["deny-policy-file"]);
	});

	test("listGrants keeps spent grants visible for the operator", () => {
		const store = withAudit(open(), "a1");
		store.putGrant(grantFor("a1"));
		store.consumeGrant("args-a1", "policy-1", "/repo/project", T0 + 5);

		const listed = store.listGrants();
		expect(listed).toHaveLength(1);
		expect(listed[0]?.consumedAt).toBe(T0 + 5);
	});
});

describe("rules", () => {
	test("rules list most specific first and can be revoked by id", () => {
		const store = open();
		store.putRule(ruleFor("broad", { kind: "deny-pattern", target: "/repo/**", specificity: 10 }));
		store.putRule(ruleFor("narrow", { specificity: 90 }));

		expect(store.listRules().map(rule => rule.id)).toEqual(["narrow", "broad"]);
		expect(store.revokeRule("broad")).toBe(true);
		expect(store.revokeRule("broad")).toBe(false);
		expect(store.listRules().map(rule => rule.id)).toEqual(["narrow"]);
	});

	test("a rule round-trips its optional qualifiers and updates in place", () => {
		const store = open();
		const rule = ruleFor("posture-1", {
			kind: "posture",
			operation: "exec",
			sensitivity: "strict",
			risk: "destructive-action",
			source: "/repo/.omp/smart-approve.yml",
			createdBy: "project",
		});
		store.putRule(rule);
		expect(store.listRules()[0]).toEqual(rule);

		store.putRule(ruleFor("posture-1", { reason: "Tightened.", specificity: 5 }));
		expect(store.listRules()).toHaveLength(1);
		expect(store.listRules()[0]?.reason).toBe("Tightened.");
		expect("sensitivity" in (store.listRules()[0] ?? {})).toBe(false);
	});
});

describe("pending approvals", () => {
	test("runs the full escalation lifecycle and spends the re-open exactly once", () => {
		const store = withAudit(open(), "a1");
		store.putPending(pendingFor("a1"));
		expect(store.listOpenPending(T0).map(pending => pending.auditId)).toEqual(["a1"]);

		expect(store.updatePendingState("a1", "approved-intent", T0 + 10)).toBe(true);
		expect(store.getPending("a1")?.state).toBe("approved-intent");
		expect(store.getPending("a1")?.resolvedAt).toBeUndefined();

		expect(store.consumeReopen("a1", T0 + 11)).toBe(true);
		expect(store.consumeReopen("a1", T0 + 12)).toBe(false);
		expect(store.getPending("a1")?.reopenConsumedAt).toBe(T0 + 11);

		expect(store.updatePendingState("a1", "denied", T0 + 20)).toBe(true);
		expect(store.getPending("a1")?.resolvedAt).toBe(T0 + 20);
		expect(store.updatePendingState("a1", "approved-granted", T0 + 21)).toBe(false);
		expect(store.getPending("a1")?.state).toBe("denied");
		expect(store.listOpenPending(T0 + 21)).toEqual([]);
	});

	test("re-open is only available to a record a human actually approved", () => {
		const store = withAudit(open(), "a1");
		store.putPending(pendingFor("a1"));
		expect(store.consumeReopen("a1", T0 + 1)).toBe(false);
		expect(store.consumeReopen("missing", T0 + 1)).toBe(false);
	});

	test("a timed-out approved intent can no longer be re-opened, even before the sweep", () => {
		const store = withAudit(open(), "a1");
		store.putPending(pendingFor("a1", { expiresAt: T0 + 1_000 }));
		store.updatePendingState("a1", "approved-intent", T0 + 10);

		expect(store.consumeReopen("a1", T0 + 1_000)).toBe(false);
		expect(store.consumeReopen("a1", T0 + 5_000)).toBe(false);
		expect(store.getPending("a1")?.reopenConsumedAt).toBeUndefined();

		// The same record was still re-openable one millisecond before its deadline.
		expect(store.consumeReopen("a1", T0 + 999)).toBe(true);
	});

	test("expirePending closes only the timed-out waits and stamps them resolved", () => {
		const store = open();
		store.beginAudit(begun("a1"));
		store.beginAudit(begun("a2"));
		store.putPending(pendingFor("a1", { expiresAt: T0 + 1_000 }));
		store.putPending(pendingFor("a2", { expiresAt: T0 + 90_000 }));

		expect(store.expirePending(T0 + 5_000)).toBe(1);
		expect(store.expirePending(T0 + 5_000)).toBe(0);
		expect(store.getPending("a1")?.state).toBe("expired");
		expect(store.getPending("a1")?.resolvedAt).toBe(T0 + 5_000);
		expect(store.getPending("a2")?.state).toBe("awaiting-human");
	});

	test("listOpenPending hides timed-out records before the sweep runs and lists newest first", () => {
		const store = open();
		store.beginAudit(begun("old"));
		store.beginAudit(begun("new"));
		store.beginAudit(begun("stale"));
		store.putPending(pendingFor("old", { createdAt: T0, expiresAt: T0 + 90_000 }));
		store.putPending(pendingFor("new", { createdAt: T0 + 500, expiresAt: T0 + 90_000 }));
		store.putPending(pendingFor("stale", { createdAt: T0 + 900, expiresAt: T0 + 1_000 }));

		expect(store.listOpenPending(T0 + 5_000).map(pending => pending.auditId)).toEqual(["new", "old"]);
	});

	test("exempt attempts count retries absorbed while a human is deciding", () => {
		const store = withAudit(open(), "a1");
		store.putPending(pendingFor("a1"));

		expect(store.incrementExemptAttempts("a1")).toBe(1);
		expect(store.incrementExemptAttempts("a1")).toBe(2);
		expect(store.getPending("a1")?.exemptAttempts).toBe(2);
		expect(store.incrementExemptAttempts("missing")).toBe(0);
	});

	test("a resolved escalation cannot be reopened by writing over it", () => {
		const store = withAudit(open(), "a1");
		store.putPending(pendingFor("a1"));
		store.updatePendingState("a1", "denied", T0 + 5);

		expect(() => store.putPending(pendingFor("a1", { nonce: "fresh" }))).toThrow(StoreStateError);
		expect(store.getPending("a1")?.state).toBe("denied");
		expect(store.getPending("a1")?.nonce).toBe("nonce-a1");
	});

	test("re-escalating an open record refreshes its nonce and deadline", () => {
		const store = withAudit(open(), "a1");
		store.putPending(pendingFor("a1"));
		store.putPending(pendingFor("a1", { nonce: "fresh", expiresAt: T0 + 120_000 }));

		expect(store.getPending("a1")?.nonce).toBe("fresh");
		expect(store.getPending("a1")?.expiresAt).toBe(T0 + 120_000);
	});

	test("decision support round-trips through both read paths, and its absence stays absent", () => {
		const store = open();
		store.beginAudit(begun("with"));
		store.beginAudit(begun("without"));
		store.putPending(pendingFor("with", { context: CONTEXT_FIXTURE }));
		store.putPending(pendingFor("without"));

		expect(store.getPending("with")?.context).toEqual(CONTEXT_FIXTURE);
		expect(store.getPending("without")?.context).toBeUndefined();

		const listed = store.listOpenPending(T0);
		expect(listed.find(p => p.auditId === "with")?.context).toEqual(CONTEXT_FIXTURE);
		expect(listed.find(p => p.auditId === "without")?.context).toBeUndefined();
	});

	test("an empty intent survives as a finding rather than collapsing into absent context", () => {
		// An agent acting with nothing captured is itself decision-relevant, so the
		// empty string must read back as an empty channel, not as a missing record.
		const store = withAudit(open(), "a1");
		store.putPending(
			pendingFor("a1", {
				context: {
					userIntent: "",
					agentRationale: "",
					rationaleFreshness: "none",
					rationaleFromReasoning: false,
					flaggedBy: "loop-breaker",
				},
			}),
		);

		expect(store.getPending("a1")?.context).toEqual({
			userIntent: "",
			agentRationale: "",
			rationaleFreshness: "none",
			rationaleFromReasoning: false,
			flaggedBy: "loop-breaker",
		});
	});

	test("a row missing the stage hydrates as no context at all, never half filled", () => {
		const store = withAudit(open(), "a1");
		store.putPending(pendingFor("a1", { context: CONTEXT_FIXTURE }));
		inspect(db => db.exec("UPDATE pending_approvals SET ctx_flagged_by = NULL"));

		expect(store.getPending("a1")?.context).toBeUndefined();
	});

	test("re-escalating an open record refreshes its decision support too", () => {
		const store = withAudit(open(), "a1");
		store.putPending(pendingFor("a1", { context: CONTEXT_FIXTURE }));
		store.putPending(
			pendingFor("a1", { context: { ...CONTEXT_FIXTURE, flaggedBy: "judge-failure", userIntent: "ship it" } }),
		);

		expect(store.getPending("a1")?.context?.flaggedBy).toBe("judge-failure");
		expect(store.getPending("a1")?.context?.userIntent).toBe("ship it");
	});
});

describe("retry families", () => {
	test("strikes accumulate per family and reset only for the cleared one", () => {
		const store = open();
		store.beginAudit(begun("a1"));
		store.beginAudit(begun("a2"));

		expect(store.recordStrike("family-x", "a1", T0)).toBe(1);
		expect(store.recordStrike("family-x", "a2", T0 + 1)).toBe(2);
		expect(store.recordStrike("family-x", "a2", T0 + 2)).toBe(3);
		expect(store.recordStrike("family-y", "a1", T0 + 3)).toBe(1);

		expect(store.getStrikes("family-x")).toBe(3);
		store.clearFamily("family-x");
		expect(store.getStrikes("family-x")).toBe(0);
		expect(store.getStrikes("family-y")).toBe(1);
	});

	test("strike counts survive a reopen, so a restarted session keeps the loop breaker", () => {
		const first = open();
		first.beginAudit(begun("a1"));
		first.recordStrike("family-x", "a1", T0);
		first.recordStrike("family-x", "a1", T0 + 1);
		first.close();

		expect(open().getStrikes("family-x")).toBe(2);
	});
});

describe("aggregate", () => {
	test("summarizes committed decisions inside the window only", () => {
		const store = open();
		store.commitAudit(
			committed("a1", { createdAt: T0, judgeLatencyMs: 100, inputTokens: 10, outputTokens: 2, costUsd: 0.001 }),
		);
		store.commitAudit(
			committed("a2", {
				createdAt: T0 + 1_000,
				decision: "block",
				stage: "judge",
				judgeLatencyMs: 301,
				inputTokens: 20,
				outputTokens: 4,
				costUsd: 0.002,
			}),
		);
		store.commitAudit(
			committed("a3", { createdAt: T0 + 2_000, decision: "escalate", stage: "escalation", judgeLatencyMs: 200 }),
		);
		// Outside the window and therefore invisible.
		store.commitAudit(committed("a4", { createdAt: T0 - 10_000, judgeLatencyMs: 9_999 }));
		// Still in flight and therefore uncounted.
		store.beginAudit(begun("a5", { createdAt: T0 + 500 }));

		const summary = store.aggregate(T0, T0 + 5_000);
		expect(summary).toEqual({
			total: 3,
			allowed: 1,
			escalated: 1,
			blocked: 1,
			avgLatencyMs: 200,
			inputTokens: 30,
			outputTokens: 6,
			costUsd: 0.003,
		});
	});

	test("an empty window reports zeroes rather than nulls", () => {
		expect(open().aggregate(T0, T0 + 1_000)).toEqual({
			total: 0,
			allowed: 0,
			escalated: 0,
			blocked: 0,
			avgLatencyMs: 0,
			inputTokens: 0,
			outputTokens: 0,
			costUsd: 0,
		});
	});
});

describe("session entry", () => {
	test("carries identity and taxonomy but never the rationale or target", () => {
		const record = committed("a1", {
			decision: "block",
			stage: "judge",
			risk: "exfiltration",
			rationale: "Uploads /etc/passwd to an external host.",
			targetSummary: "url:https://evil.example/collect",
			retryCount: 2,
		});

		const entry = serializeSessionEntry(record);
		expect(JSON.parse(entry)).toEqual({
			v: 1,
			auditId: "a1",
			decision: "block",
			stage: "judge",
			risk: "exfiltration",
			retryFamilyKey: "family-a1",
			retryCount: 2,
		});
		expect(entry).not.toContain("etc/passwd");
		expect(entry).not.toContain("evil.example");
	});
});

describe("grants are bound to the working directory they were approved from", () => {
	// The audit database lives at the user-level agent directory and is shared by
	// every project. Two checkouts with no project config resolve to the same
	// policyHash, so without a cwd binding a grant approved in one repository
	// would admit a byte-identical call in another.
	const REPO_A = "/srv/checkout-a";
	const REPO_B = "/srv/checkout-b";

	function grantIn(cwd: string) {
		return grantFor("a1", { id: "grant-x", cwd, policyHash: "shared-policy", argumentsHash: "same-args" });
	}

	test("a grant is consumable from the directory it was approved in", () => {
		const store = open();
		store.beginAudit(begun("a1", { cwd: REPO_A }));
		store.putGrant(grantIn(REPO_A));
		expect(store.consumeGrant("same-args", "shared-policy", REPO_A, T0)?.id).toBe("grant-x");
	});

	test("the same grant is NOT consumable from another checkout sharing the policy hash", () => {
		const store = open();
		store.beginAudit(begun("a1", { cwd: REPO_A }));
		store.putGrant(grantIn(REPO_A));
		expect(store.consumeGrant("same-args", "shared-policy", REPO_B, T0)).toBeUndefined();
		// And it is still available where it belongs, so the block was not a consume.
		expect(store.consumeGrant("same-args", "shared-policy", REPO_A, T0)?.id).toBe("grant-x");
	});

	test("findGrant is location-bound too, so a peek cannot leak across projects", () => {
		const store = open();
		store.beginAudit(begun("a1", { cwd: REPO_A }));
		store.putGrant(grantIn(REPO_A));
		expect(store.findGrant("same-args", "shared-policy", REPO_B, T0)).toBeUndefined();
	});

	test("a legacy grant migrated in with no cwd is inert rather than portable", () => {
		const store = open();
		store.beginAudit(begun("a1", { cwd: REPO_A }));
		store.putGrant(grantIn(REPO_A));
		// Simulate a row written before migration 2.
		inspect(db => db.exec("UPDATE grants SET cwd = NULL"));
		expect(store.consumeGrant("same-args", "shared-policy", REPO_A, T0)).toBeUndefined();
		expect(store.consumeGrant("same-args", "shared-policy", "", T0)).toBeUndefined();
	});

	test("a policy change in one checkout does not purge another checkout's grants", () => {
		const store = open();
		store.beginAudit(begun("a1", { cwd: REPO_A }));
		store.beginAudit(begun("a2", { cwd: REPO_B }));
		store.putGrant(grantFor("a1", { id: "g-a", cwd: REPO_A, policyHash: "policy-old" }));
		store.putGrant(grantFor("a2", { id: "g-b", cwd: REPO_B, policyHash: "policy-old" }));

		// Repo A tightens its policy and sweeps on next session start.
		expect(store.revokeGrantsForPolicy("policy-new", REPO_A, T0)).toBe(1);

		const survivors = store.listGrants().map(g => g.id);
		expect(survivors).toEqual(["g-b"]);
	});
});
