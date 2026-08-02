import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { type BrokerEndpoint, heldCall, holdCall, registerEndpoint, resetBrokerForTests } from "../src/broker.ts";
import { type DiscoveryPaths, type ResolvedConfig, resolveConfig } from "../src/config.ts";
import type {
	EscalationRequest,
	GatePorts,
	GateRequest,
	HostApproval,
	HumanDecision,
	JudgeInput,
	JudgeResult,
	RiskClass,
	SensitivityLevel,
	Verdict,
} from "../src/contracts.ts";
import { Gate, LOOP_BREAK_THRESHOLD, type RiskCard } from "../src/gate.ts";
import { extractTargets, hashArguments, retryFamilyKey } from "../src/policy.ts";
import { openStore, type SmartApproveStore } from "../src/store.ts";

/** Working directory every fixture in this file is bound to. */
const CWD_FIXTURE = "/repo/project";

const CWD = "/repo/project";
const START = 1_700_000_000_000;

let dir: string;
let store: SmartApproveStore;
let clock: number;
let nonceCounter: number;
let idCounter: number;

function nextNonce(): number {
	nonceCounter += 1;
	return nonceCounter;
}

function nextId(): number {
	idCounter += 1;
	return idCounter;
}

beforeEach(() => {
	dir = mkdtempSync(path.join(tmpdir(), "sa-gate-"));
	store = openStore(path.join(dir, "state.sqlite"));
	clock = START;
	nonceCounter = 0;
	idCounter = 0;
	resetBrokerForTests();
});

afterEach(() => {
	store.close();
	rmSync(dir, { recursive: true, force: true });
	resetBrokerForTests();
});

const paths: DiscoveryPaths = { cwd: CWD, agentDir: "/home/dev/.omp/agent", home: "/home/dev" };

function config(overrides: Record<string, unknown> = {}): ResolvedConfig {
	return resolveConfig(
		[
			{
				scope: "user",
				filePath: "/u.yml",
				rawContent: "{}",
				data: { judge: { authorizedModels: ["anthropic/haiku"] }, ...overrides },
			},
		],
		[],
		paths,
	);
}

interface Harness {
	gate: Gate;
	judgeCalls: JudgeInput[];
	escalateCalls: EscalationRequest[];
	cards: RiskCard[];
}

function harness(options: {
	resolved?: ResolvedConfig;
	judge?: (input: JudgeInput, signal: AbortSignal) => Promise<JudgeResult>;
	escalate?: (req: EscalationRequest, signal: AbortSignal) => Promise<HumanDecision | undefined>;
	bypassActive?: () => boolean;
}): Harness {
	const judgeCalls: JudgeInput[] = [];
	const escalateCalls: EscalationRequest[] = [];
	const cards: RiskCard[] = [];
	const ports: GatePorts = {
		classifyHostApproval: async () => ({ branch: "auto", reason: "test" }),
		judge: async (input, signal) => {
			judgeCalls.push(input);
			return options.judge
				? await options.judge(input, signal)
				: {
						ok: true,
						verdict: { decision: "allow", risk: "uncertain", rationale: "fine" },
						metrics: { attempts: 1, latencyMs: 10, overTarget: false },
					};
		},
		escalate: async (req, signal) => {
			escalateCalls.push(req);
			return options.escalate ? await options.escalate(req, signal) : undefined;
		},
		now: () => clock,
		randomNonce: () => `nonce-${nextNonce()}`,
		randomId: () => `id-${nextId()}`,
	};
	const gate = new Gate({
		resolved: options.resolved ?? config(),
		store,
		ports,
		buildJudgeInput: (request, context) => stubJudgeInput(request, context.sensitivity),
		publishRiskCard: card => cards.push(card),
		...(options.bypassActive === undefined ? {} : { bypassActive: options.bypassActive }),
	});
	return { gate, judgeCalls, escalateCalls, cards };
}

function stubJudgeInput(request: GateRequest, sensitivity: SensitivityLevel): JudgeInput {
	return {
		userIntent: "do the thing",
		agentRationale: "because",
		toolName: request.toolName,
		operation: request.canonicalCall.operation,
		argumentsView: "{}",
		targets: [...request.canonicalCall.targets],
		sourceAgentId: request.sourceAgentId,
		recentActions: [],
		policyDocuments: [],
		postureHints: [],
		sensitivity,
		incompleteCriticalContext: false,
	};
}

let requestSeq = 0;

function makeRequest(options: {
	toolName?: string;
	args?: Record<string, unknown>;
	auditId?: string;
	sourceAgentId?: string;
	deadlineMs?: number;
}): GateRequest {
	const toolName = options.toolName ?? "write";
	const args = options.args ?? { path: "src/a.ts", content: "hello" };
	const extracted = extractTargets({ toolName, args, cwd: CWD });
	requestSeq += 1;
	return {
		auditId: options.auditId ?? `audit-${requestSeq}`,
		toolCallId: `call-${requestSeq}`,
		toolName,
		sourceAgentId: options.sourceAgentId ?? "Main",
		sourceAgentKind: "main",
		canonicalCall: {
			toolName,
			operation: extracted.operation,
			targets: extracted.targets,
			argumentsHash: hashArguments(args),
			...(extracted.device === undefined ? {} : { device: extracted.device }),
		},
		rawArguments: Object.freeze(args),
		argumentsHash: hashArguments(args),
		cwd: CWD,
		receivedAt: clock,
		deadlineAt: clock + (options.deadlineMs ?? 28_000),
	};
}

const AUTO: HostApproval = { branch: "auto", policy: "allow", tier: "write", mode: "yolo", reason: "auto" };
const PROMPT: HostApproval = {
	branch: "prompt",
	policy: "prompt",
	tier: "write",
	mode: "always-ask",
	reason: "prompt",
};
const DENY: HostApproval = { branch: "deny", policy: "deny", tier: "write", mode: "yolo", reason: "OMP denies" };
const UNSUPPORTED: HostApproval = { branch: "unsupported", reason: "no live session" };
const AUTO_READ: HostApproval = { branch: "auto", policy: "allow", tier: "read", mode: "yolo", reason: "auto" };

function verdict(decision: Verdict["decision"], risk: RiskClass = "uncertain"): JudgeResult {
	return {
		ok: true,
		verdict: { decision, risk, rationale: `judge says ${decision}` },
		metrics: { attempts: 1, latencyMs: 12, overTarget: false, provider: "anthropic", model: "haiku" },
	};
}

function mainEndpoint(present: BrokerEndpoint["present"]): void {
	registerEndpoint({ agentId: "Main", agentKind: "main", capability: "interactive", present });
}

// ---------------------------------------------------------------------------

describe("host branch semantics", () => {
	test("a host deny is preserved and never judged", async () => {
		const h = harness({});
		const result = await h.gate.evaluate(makeRequest({}), DENY);
		expect(result.decision).toBe("block");
		expect(result.stage).toBe("host-deny");
		expect(h.judgeCalls).toHaveLength(0);
	});

	test("an unsupported host blocks rather than guessing", async () => {
		const h = harness({});
		const result = await h.gate.evaluate(makeRequest({}), UNSUPPORTED);
		expect(result.decision).toBe("block");
		expect(result.stage).toBe("unsupported-host");
	});

	test("a safe local read skips the judge entirely", async () => {
		const h = harness({});
		const result = await h.gate.evaluate(makeRequest({ toolName: "read", args: { path: "src/a.ts" } }), AUTO_READ);
		expect(result.decision).toBe("allow");
		expect(result.stage).toBe("local-read");
		expect(h.judgeCalls).toHaveLength(0);
	});
});

describe("deterministic checks run before any model call", () => {
	test("a protected policy write blocks with no judge call, on the auto branch", async () => {
		const h = harness({});
		const request = makeRequest({ args: { path: ".omp/smart-approve.yml", content: "x" } });
		const result = await h.gate.evaluate(request, AUTO);
		expect(result.decision).toBe("block");
		expect(result.stage).toBe("protected-policy");
		expect(h.judgeCalls).toHaveLength(0);
	});

	test("a protected policy write also hard-blocks on the native prompt branch", async () => {
		const h = harness({});
		const request = makeRequest({ args: { path: ".omp/smart-approve.yml", content: "x" } });
		const result = await h.gate.evaluate(request, PROMPT);
		expect(result.decision).toBe("block");
		expect(result.stage).toBe("protected-policy");
		expect(h.cards).toHaveLength(0);
	});

	test("a deny rule blocks before the model even on a read", async () => {
		const resolved = config({
			rules: [{ id: "no-env", kind: "deny-pattern", tool: "read", target: "**/.env*", reason: "secrets" }],
		});
		const h = harness({ resolved });
		const result = await h.gate.evaluate(makeRequest({ toolName: "read", args: { path: ".env" } }), AUTO_READ);
		expect(result.decision).toBe("block");
		expect(result.stage).toBe("deny-rule");
		expect(h.judgeCalls).toHaveLength(0);
	});
});

describe("native prompt branch never opens a second dialog", () => {
	test("a judge allow falls through with no block and no escalation dialog", async () => {
		const h = harness({ judge: async () => verdict("allow") });
		const result = await h.gate.evaluate(makeRequest({}), PROMPT);
		expect(result.decision).toBe("allow");
		expect(h.escalateCalls).toHaveLength(0);
		expect(h.cards).toHaveLength(1);
	});

	test("a judge escalate falls through to OMP's own prompt, not a second dialog", async () => {
		const h = harness({ judge: async () => verdict("escalate") });
		const result = await h.gate.evaluate(makeRequest({}), PROMPT);
		expect(result.decision).toBe("allow");
		expect(h.escalateCalls).toHaveLength(0);
		expect(h.cards[0]?.rationale).toContain("escalate");
	});

	test("a judge block hard-blocks even though OMP would have prompted", async () => {
		const h = harness({ judge: async () => verdict("block", "destructive-action") });
		const result = await h.gate.evaluate(makeRequest({}), PROMPT);
		expect(result.decision).toBe("block");
		expect(h.escalateCalls).toHaveLength(0);
	});

	test("judge failure is shown in the card and still falls through to the native prompt", async () => {
		const h = harness({
			judge: async () => ({
				ok: false,
				failure: { kind: "timeout", detail: "judge timed out" },
				metrics: { attempts: 2, latencyMs: 20_000, overTarget: true },
			}),
		});
		const result = await h.gate.evaluate(makeRequest({}), PROMPT);
		expect(result.decision).toBe("allow");
		expect(h.cards[0]?.judgeAvailable).toBe(false);
		expect(h.cards[0]?.rationale).toContain("timeout");
	});

	test("an unconfigured plugin still falls through on the prompt branch", async () => {
		const h = harness({ resolved: resolveConfig([], [], paths) });
		const result = await h.gate.evaluate(makeRequest({}), PROMPT);
		expect(result.decision).toBe("allow");
		expect(h.cards[0]?.rationale).toContain("/smart-approve setup");
	});
});

describe("native auto branch", () => {
	test("a judge allow runs silently and is audited", async () => {
		const h = harness({ judge: async () => verdict("allow") });
		const request = makeRequest({});
		const result = await h.gate.evaluate(request, AUTO);
		expect(result.decision).toBe("allow");
		expect(store.getAudit(request.auditId)?.decision).toBe("allow");
	});

	test("a judge block returns an actionable reason carrying the audit ID", async () => {
		const h = harness({ judge: async () => verdict("block", "destructive-action") });
		const request = makeRequest({});
		const result = await h.gate.evaluate(request, AUTO);
		expect(result.decision).toBe("block");
		expect(result.reason).toContain(request.auditId);
		expect(result.reason).toContain("Do not retry");
	});

	test("an unconfigured plugin fails closed on the auto branch", async () => {
		const h = harness({ resolved: resolveConfig([], [], paths) });
		const result = await h.gate.evaluate(makeRequest({}), AUTO);
		expect(result.decision).toBe("block");
		expect(result.stage).toBe("config-invalid");
		expect(result.reason).toContain("/smart-approve setup");
	});

	test("a block reason never contains the raw arguments", async () => {
		const h = harness({ judge: async () => verdict("block") });
		const secret = "SUPER_SECRET_PAYLOAD_VALUE";
		const result = await h.gate.evaluate(makeRequest({ args: { path: "a.ts", content: secret } }), AUTO);
		expect(result.reason).not.toContain(secret);
	});
});

describe("every failure stage becomes escalation, never allow", () => {
	const failures = [
		{ kind: "timeout" as const, detail: "attempt exceeded 10000ms" },
		{ kind: "transport" as const, detail: "connection reset" },
		{ kind: "malformed-output" as const, detail: "not a JSON object" },
		{ kind: "no-authorized-model" as const, detail: "none configured" },
		{ kind: "auth-unavailable" as const, detail: "credentials disabled" },
		{ kind: "deadline-exhausted" as const, detail: "no budget left" },
		{ kind: "internal" as const, detail: "unexpected" },
	];

	for (const failure of failures) {
		test(`${failure.kind} ends as an audited pending block`, async () => {
			const h = harness({
				judge: async () => ({ ok: false, failure, metrics: { attempts: 1, latencyMs: 5, overTarget: false } }),
			});
			const request = makeRequest({});
			const result = await h.gate.evaluate(request, AUTO);
			expect(result.decision).toBe("block");
			expect(result.pendingAuditId).toBe(request.auditId);
			expect(store.getPending(request.auditId)?.state).toBe("awaiting-human");
		});
	}

	test("a judge that throws is contained and becomes a pending block", async () => {
		const h = harness({
			judge: async () => {
				throw new Error("judge exploded");
			},
		});
		const request = makeRequest({});
		const result = await h.gate.evaluate(request, AUTO);
		expect(result.decision).toBe("block");
		expect(store.getPending(request.auditId)).toBeDefined();
	});

	test("a store failure downgrades an allow to a block rather than running unaudited", async () => {
		const h = harness({ judge: async () => verdict("allow") });
		const request = makeRequest({});
		// Close the store so the terminal commit fails.
		store.close();
		const result = await h.gate.evaluate(request, AUTO);
		expect(result.decision).toBe("block");
		// Reopen for the afterEach teardown.
		store = openStore(path.join(dir, "state.sqlite"));
	});
});

describe("asynchronous escalation", () => {
	test("with no human channel it persists a pending record and blocks with the review command", async () => {
		const h = harness({ judge: async () => verdict("escalate") });
		const request = makeRequest({});
		const result = await h.gate.evaluate(request, AUTO);
		expect(result.decision).toBe("block");
		expect(result.reason).toContain(`/smart-approve review ${request.auditId}`);
		expect(h.escalateCalls).toHaveLength(0);
		const pending = store.getPending(request.auditId);
		expect(pending?.state).toBe("awaiting-human");
		expect(pending?.nonce).toBe("nonce-1");
	});

	test("a headless subagent escalation blocks and says no interactive session exists", async () => {
		const h = harness({ judge: async () => verdict("escalate") });
		const result = await h.gate.evaluate(makeRequest({ sourceAgentId: "Sub1" }), AUTO);
		expect(result.decision).toBe("block");
		expect(result.reason).toContain("No interactive main session");
	});

	test("the durable record holds no raw arguments", async () => {
		const h = harness({ judge: async () => verdict("escalate") });
		const request = makeRequest({ args: { path: "a.ts", content: "RAW_SECRET_BODY" } });
		await h.gate.evaluate(request, AUTO);
		const pending = store.getPending(request.auditId);
		expect(JSON.stringify(pending)).not.toContain("RAW_SECRET_BODY");
	});

	test("the literal arguments are held in the broker so a later approval can mint a grant", async () => {
		const h = harness({ judge: async () => verdict("escalate") });
		const request = makeRequest({});
		await h.gate.evaluate(request, AUTO);
		expect(heldCall(request.auditId, clock)?.argumentsHash).toBe(request.argumentsHash);
	});

	test("the fast path is skipped when the remaining budget is below the dialog floor", async () => {
		mainEndpoint(async () => undefined);
		const h = harness({ judge: async () => verdict("escalate") });
		// Only 5s of budget: below the 10s floor.
		const result = await h.gate.evaluate(makeRequest({ deadlineMs: 5_000 }), AUTO);
		expect(h.escalateCalls).toHaveLength(0);
		expect(result.decision).toBe("block");
	});

	test("the fast path runs when a live main TUI and enough budget exist", async () => {
		mainEndpoint(async () => undefined);
		const h = harness({ judge: async () => verdict("escalate") });
		await h.gate.evaluate(makeRequest({ deadlineMs: 28_000 }), AUTO);
		expect(h.escalateCalls).toHaveLength(1);
	});

	test("a dialog approval with a matching nonce allows and closes the record", async () => {
		mainEndpoint(async () => undefined);
		const h = harness({
			judge: async () => verdict("escalate"),
			escalate: async req => ({
				auditId: req.auditId,
				nonce: req.nonce,
				choice: "allow-once",
				argumentsHash: req.frozenCall.argumentsHash,
				decidedAt: clock,
			}),
		});
		const request = makeRequest({});
		const result = await h.gate.evaluate(request, AUTO);
		expect(result.decision).toBe("allow");
		expect(store.getPending(request.auditId)?.state).toBe("approved-granted");
	});

	test("a dialog approval with a wrong nonce is refused and falls through to a block", async () => {
		mainEndpoint(async () => undefined);
		const h = harness({
			judge: async () => verdict("escalate"),
			escalate: async req => ({
				auditId: req.auditId,
				nonce: "forged",
				choice: "allow-once",
				argumentsHash: req.frozenCall.argumentsHash,
				decidedAt: clock,
			}),
		});
		const request = makeRequest({});
		const result = await h.gate.evaluate(request, AUTO);
		expect(result.decision).toBe("block");
		expect(store.getPending(request.auditId)?.state).toBe("awaiting-human");
	});

	test("a dialog approval whose arguments hash disagrees is refused", async () => {
		mainEndpoint(async () => undefined);
		const h = harness({
			judge: async () => verdict("escalate"),
			escalate: async req => ({
				auditId: req.auditId,
				nonce: req.nonce,
				choice: "allow-once",
				argumentsHash: "b".repeat(64),
				decidedAt: clock,
			}),
		});
		expect((await h.gate.evaluate(makeRequest({}), AUTO)).decision).toBe("block");
	});

	test("a dialog deny blocks and records the denial", async () => {
		mainEndpoint(async () => undefined);
		const h = harness({
			judge: async () => verdict("escalate"),
			escalate: async req => ({
				auditId: req.auditId,
				nonce: req.nonce,
				choice: "deny",
				argumentsHash: req.frozenCall.argumentsHash,
				decidedAt: clock,
			}),
		});
		const request = makeRequest({});
		const result = await h.gate.evaluate(request, AUTO);
		expect(result.decision).toBe("block");
		expect(store.getPending(request.auditId)?.state).toBe("denied");
	});

	test("a dialog timeout falls through to the durable pending path, not a terminal deny", async () => {
		mainEndpoint(async () => undefined);
		const h = harness({ judge: async () => verdict("escalate"), escalate: async () => undefined });
		const request = makeRequest({});
		const result = await h.gate.evaluate(request, AUTO);
		expect(result.decision).toBe("block");
		expect(result.pendingAuditId).toBe(request.auditId);
		expect(store.getPending(request.auditId)?.state).toBe("awaiting-human");
	});
});

describe("exact grants and the loop breaker", () => {
	function familyFor(request: GateRequest): string {
		return retryFamilyKey({
			sourceAgentId: request.sourceAgentId,
			toolName: request.toolName,
			operation: request.canonicalCall.operation,
			targets: request.canonicalCall.targets,
			risk: "uncertain",
		});
	}

	test("an exact grant admits the call without calling the judge", async () => {
		const resolved = config();
		const h = harness({ resolved });
		const request = makeRequest({});
		store.beginAudit({
			auditId: "prior",
			toolCallId: "prior-call",
			toolName: request.toolName,
			operation: request.canonicalCall.operation,
			targetSummary: "t",
			argumentsHash: request.argumentsHash,
			canonicalHash: "c",
			policyHash: resolved.policyHash,
			sourceAgentId: "Main",
			sourceAgentKind: "main",
			cwd: CWD_FIXTURE,
			retryFamilyKey: "",
			createdAt: clock,
		});
		store.putGrant({
			id: "g1",
			auditId: "prior",
			argumentsHash: request.argumentsHash,
			canonicalHash: "c",
			policyHash: resolved.policyHash,
			cwd: CWD_FIXTURE,
			scope: "one-time",
			expiresAt: clock + 60_000,
			createdBy: "human",
			reason: "override",
		});
		const result = await h.gate.evaluate(request, AUTO);
		expect(result.decision).toBe("allow");
		expect(result.stage).toBe("exact-grant");
		expect(h.judgeCalls).toHaveLength(0);
	});

	test("a grant bound to a superseded policy hash does not admit the call", async () => {
		const resolved = config();
		const h = harness({ resolved });
		const request = makeRequest({});
		store.beginAudit({
			auditId: "prior",
			toolCallId: "p",
			toolName: request.toolName,
			operation: request.canonicalCall.operation,
			targetSummary: "t",
			argumentsHash: request.argumentsHash,
			canonicalHash: "c",
			policyHash: "stale",
			sourceAgentId: "Main",
			sourceAgentKind: "main",
			cwd: CWD_FIXTURE,
			retryFamilyKey: "",
			createdAt: clock,
		});
		store.putGrant({
			id: "g1",
			auditId: "prior",
			argumentsHash: request.argumentsHash,
			canonicalHash: "c",
			policyHash: "stale",
			cwd: CWD_FIXTURE,
			scope: "one-time",
			expiresAt: clock + 60_000,
			createdBy: "human",
			reason: "override",
		});
		const result = await h.gate.evaluate(request, AUTO);
		expect(result.stage).not.toBe("exact-grant");
	});

	test("a one-time grant is consumed exactly once", async () => {
		const resolved = config();
		const h = harness({ resolved, judge: async () => verdict("block") });
		const first = makeRequest({});
		store.beginAudit({
			auditId: "prior",
			toolCallId: "p",
			toolName: first.toolName,
			operation: first.canonicalCall.operation,
			targetSummary: "t",
			argumentsHash: first.argumentsHash,
			canonicalHash: "c",
			policyHash: resolved.policyHash,
			sourceAgentId: "Main",
			sourceAgentKind: "main",
			cwd: CWD_FIXTURE,
			retryFamilyKey: "",
			createdAt: clock,
		});
		store.putGrant({
			id: "g1",
			auditId: "prior",
			argumentsHash: first.argumentsHash,
			canonicalHash: "c",
			policyHash: resolved.policyHash,
			cwd: CWD_FIXTURE,
			scope: "one-time",
			expiresAt: clock + 60_000,
			createdBy: "human",
			reason: "override",
		});
		expect((await h.gate.evaluate(first, AUTO)).stage).toBe("exact-grant");
		const second = makeRequest({});
		expect((await h.gate.evaluate(second, AUTO)).stage).not.toBe("exact-grant");
	});

	test("grant matching runs before the loop breaker, so an approved retry is not struck", async () => {
		const resolved = config();
		const h = harness({ resolved, judge: async () => verdict("block") });
		const request = makeRequest({});
		const family = familyFor(request);
		// Three prior strikes: the loop breaker would otherwise fire.
		for (let i = 0; i < LOOP_BREAK_THRESHOLD; i += 1) store.recordStrike(family, `s${i}`, clock);
		store.beginAudit({
			auditId: "prior",
			toolCallId: "p",
			toolName: request.toolName,
			operation: request.canonicalCall.operation,
			targetSummary: "t",
			argumentsHash: request.argumentsHash,
			canonicalHash: "c",
			policyHash: resolved.policyHash,
			sourceAgentId: "Main",
			sourceAgentKind: "main",
			cwd: CWD_FIXTURE,
			retryFamilyKey: family,
			createdAt: clock,
		});
		store.putGrant({
			id: "g1",
			auditId: "prior",
			argumentsHash: request.argumentsHash,
			canonicalHash: "c",
			policyHash: resolved.policyHash,
			cwd: CWD_FIXTURE,
			scope: "one-time",
			expiresAt: clock + 60_000,
			createdBy: "human",
			reason: "override",
		});
		const result = await h.gate.evaluate(request, AUTO);
		expect(result.decision).toBe("allow");
		expect(result.stage).toBe("exact-grant");
		// The family closed, so the next identical call starts clean.
		expect(store.getStrikes(family)).toBe(0);
	});

	test("three blocked attempts trip the loop breaker on the fourth", async () => {
		const h = harness({ judge: async () => verdict("block", "destructive-action") });
		let last = await h.gate.evaluate(makeRequest({}), AUTO);
		for (let i = 0; i < LOOP_BREAK_THRESHOLD; i += 1) {
			last = await h.gate.evaluate(makeRequest({}), AUTO);
		}
		expect(last.decision).toBe("block");
		expect(last.stage).toBe("loop-breaker");
		expect(last.reason).toContain("retry loop");
	});

	test("the loop breaker opens a durable record a human can act on", async () => {
		const h = harness({ judge: async () => verdict("block") });
		let tripped: string | undefined;
		for (let i = 0; i < LOOP_BREAK_THRESHOLD + 1; i += 1) {
			const result = await h.gate.evaluate(makeRequest({}), AUTO);
			if (result.stage === "loop-breaker") tripped = result.pendingAuditId;
		}
		expect(tripped).toBeDefined();
		expect(store.getPending(tripped ?? "")?.state).toBe("awaiting-human");
	});

	test("once a record is open, further retries reuse it instead of re-judging", async () => {
		const h = harness({ judge: async () => verdict("block") });
		for (let i = 0; i < LOOP_BREAK_THRESHOLD + 1; i += 1) await h.gate.evaluate(makeRequest({}), AUTO);
		const before = h.judgeCalls.length;
		const result = await h.gate.evaluate(makeRequest({}), AUTO);
		expect(result.decision).toBe("block");
		expect(result.reason).toContain("already reviewing this exact call");
		// No further model spend while a human deliberates over the same call.
		expect(h.judgeCalls.length).toBe(before);
	});

	test("a semantically different retry starts a new family and is not struck", async () => {
		const h = harness({ judge: async () => verdict("block") });
		for (let i = 0; i < LOOP_BREAK_THRESHOLD + 1; i += 1) await h.gate.evaluate(makeRequest({}), AUTO);
		const different = await h.gate.evaluate(makeRequest({ args: { path: "src/other.ts", content: "x" } }), AUTO);
		expect(different.stage).toBe("judge");
	});
});

describe("strike exemption is bounded independently of record actionability", () => {
	test("strikes are suppressed while a record is awaiting-human inside both bounds", async () => {
		const h = harness({ judge: async () => verdict("escalate") });
		const first = makeRequest({});
		await h.gate.evaluate(first, AUTO);
		const family = retryFamilyKey({
			sourceAgentId: first.sourceAgentId,
			toolName: first.toolName,
			operation: first.canonicalCall.operation,
			targets: first.canonicalCall.targets,
			risk: "uncertain",
		});
		const before = store.getStrikes(family);
		await h.gate.evaluate(makeRequest({}), AUTO);
		expect(store.getStrikes(family)).toBe(before);
	});

	test("strikes resume once the exemption window elapses, even though the audit ID stays actionable", async () => {
		const resolved = config({ timeouts: { strikeExemptionWindowMs: 1_000 } });
		// The first call escalates, which is what opens the durable record; later
		// calls are hard blocks so their strikes are observable.
		let firstCall = true;
		const h = harness({
			resolved,
			judge: async () => {
				const result = firstCall ? verdict("escalate") : verdict("block");
				firstCall = false;
				return result;
			},
		});
		const first = makeRequest({});
		await h.gate.evaluate(first, AUTO);
		expect(store.getPending(first.auditId)?.state).toBe("awaiting-human");

		const family = retryFamilyKey({
			sourceAgentId: first.sourceAgentId,
			toolName: first.toolName,
			operation: first.canonicalCall.operation,
			targets: first.canonicalCall.targets,
			risk: "uncertain",
		});

		// Inside the window the retry is exempt and reuses the open record.
		const exempt = await h.gate.evaluate(makeRequest({}), AUTO);
		expect(exempt.reason).toContain("already reviewing this exact call");
		expect(store.getStrikes(family)).toBe(0);

		// Past the window, exemption ends: strikes resume and the loop breaker fires.
		clock += 5_000;
		for (let i = 0; i < LOOP_BREAK_THRESHOLD; i += 1) await h.gate.evaluate(makeRequest({}), AUTO);
		expect(store.getStrikes(family)).toBeGreaterThanOrEqual(LOOP_BREAK_THRESHOLD);

		// The record stays reviewable for the rest of pendingApprovalTtl regardless.
		expect(store.getPending(first.auditId)).toBeDefined();
	});

	test("strikes resume after maxExemptAttempts is exhausted", async () => {
		const resolved = config({ timeouts: { maxExemptAttempts: 2 } });
		const h = harness({ resolved, judge: async () => verdict("escalate") });
		const first = makeRequest({});
		await h.gate.evaluate(first, AUTO);
		const pending = store.getPending(first.auditId);
		expect(pending?.state).toBe("awaiting-human");
		for (let i = 0; i < 5; i += 1) await h.gate.evaluate(makeRequest({}), AUTO);
		expect(store.getPending(first.auditId)?.exemptAttempts).toBeLessThanOrEqual(2);
	});

	test("an approved-intent record absorbs exactly one re-open attempt and no more", async () => {
		const h = harness({ judge: async () => verdict("block") });
		const first = makeRequest({});
		await h.gate.evaluate(first, AUTO);
		// Simulate a human recording intent-to-approve out-of-band.
		store.putPending({
			auditId: first.auditId,
			toolName: first.toolName,
			operation: first.canonicalCall.operation,
			targetSummary: "t",
			risk: "uncertain",
			rationale: "r",
			argumentsHash: first.argumentsHash,
			canonicalHash: "c",
			policyHash: config().policyHash,
			nonce: "n",
			sourceAgentId: "Main",
			cwd: CWD_FIXTURE,
			state: "approved-intent",
			createdAt: clock,
			expiresAt: clock + 60_000,
			exemptAttempts: 0,
		});
		expect(store.consumeReopen(first.auditId, clock)).toBe(true);
		expect(store.consumeReopen(first.auditId, clock)).toBe(false);
	});
});

describe("session bypass", () => {
	test("an active bypass allows without judging, and is audited", async () => {
		const h = harness({ bypassActive: () => true, judge: async () => verdict("block") });
		const request = makeRequest({});
		const result = await h.gate.evaluate(request, AUTO);
		expect(result.decision).toBe("allow");
		expect(result.stage).toBe("bypass");
		expect(h.judgeCalls).toHaveLength(0);
		expect(store.listEvents(request.auditId).some(e => e.detail.includes("unguarded"))).toBe(true);
	});

	test("a bypass does not defeat the deterministic protected-policy floor", async () => {
		const h = harness({ bypassActive: () => true });
		const result = await h.gate.evaluate(
			makeRequest({ args: { path: ".omp/smart-approve.yml", content: "x" } }),
			AUTO,
		);
		expect(result.decision).toBe("block");
		expect(result.stage).toBe("protected-policy");
	});

	test("a bypass does not defeat a deny rule", async () => {
		const resolved = config({
			rules: [{ id: "no-rm", kind: "deny-pattern", tool: "bash", target: "rm", reason: "destructive" }],
		});
		const h = harness({ resolved, bypassActive: () => true });
		const result = await h.gate.evaluate(makeRequest({ toolName: "bash", args: { command: "rm -rf /" } }), {
			branch: "auto",
			policy: "allow",
			tier: "exec",
			mode: "yolo",
			reason: "auto",
		});
		expect(result.decision).toBe("block");
	});
});

describe("audit durability", () => {
	test("an allowed call has a committed terminal audit row before it returns", async () => {
		const h = harness({ judge: async () => verdict("allow") });
		const request = makeRequest({});
		await h.gate.evaluate(request, AUTO);
		const record = store.getAudit(request.auditId);
		expect(record?.decision).toBe("allow");
		expect(record?.argumentsHash).toBe(request.argumentsHash);
	});

	test("the audit row records the judge model and latency", async () => {
		const h = harness({ judge: async () => verdict("allow") });
		const request = makeRequest({});
		await h.gate.evaluate(request, AUTO);
		const record = store.getAudit(request.auditId);
		expect(record?.judgeModel).toBe("haiku");
		expect(record?.judgeLatencyMs).toBe(12);
	});

	test("no raw argument value reaches the audit row", async () => {
		const h = harness({ judge: async () => verdict("allow") });
		const request = makeRequest({ args: { path: "a.ts", content: "PLAINTEXT_BODY_XYZ" } });
		await h.gate.evaluate(request, AUTO);
		expect(JSON.stringify(store.getAudit(request.auditId))).not.toContain("PLAINTEXT_BODY_XYZ");
	});
});

describe("exception containment", () => {
	test("a store that throws on beginAudit still produces a fail-closed block, not a crash", async () => {
		const h = harness({ judge: async () => verdict("allow") });
		store.close();
		const result = await h.gate.evaluate(makeRequest({}), AUTO);
		expect(result.decision).toBe("block");
		expect(["internal-error", "store-failure"]).toContain(result.stage);
		store = openStore(path.join(dir, "state.sqlite"));
	});

	test("the emergency reason carries no raw data", async () => {
		const h = harness({ judge: async () => verdict("allow") });
		store.close();
		const secret = "EMERGENCY_SECRET_VALUE";
		const result = await h.gate.evaluate(makeRequest({ args: { path: "a.ts", content: secret } }), AUTO);
		expect(result.reason).not.toContain(secret);
		store = openStore(path.join(dir, "state.sqlite"));
	});
});

describe("broker interaction", () => {
	test("a held call from a previous escalation does not authorize a different call", async () => {
		const other = makeRequest({ args: { path: "other.ts", content: "x" } });
		holdCall({
			auditId: "unrelated",
			nonce: "n",
			frozenCall: {
				toolName: other.toolName,
				toolCallId: other.toolCallId,
				rawArguments: other.rawArguments,
				argumentsHash: other.argumentsHash,
				frozenAt: clock,
			},
			expiresAt: clock + 60_000,
		});
		const h = harness({ judge: async () => verdict("escalate") });
		const result = await h.gate.evaluate(makeRequest({}), AUTO);
		expect(result.decision).toBe("block");
	});
});

describe("exact allow rule end to end", () => {
	test("a rule pinned to the exact arguments hash skips the judge", async () => {
		const args = { path: "src/a.ts", content: "hello" };
		const resolved = config({
			rules: [
				{
					id: "pinned",
					kind: "allow-exact",
					tool: "write",
					target: path.join(CWD, "src/a.ts"),
					argumentsHash: hashArguments(args),
					cwd: CWD,
					reason: "reviewed and pinned",
				},
			],
		});
		const h = harness({ resolved, judge: async () => verdict("block") });
		const result = await h.gate.evaluate(makeRequest({ args }), AUTO);
		expect(result.decision).toBe("allow");
		expect(result.stage).toBe("exact-allow-rule");
		expect(h.judgeCalls).toHaveLength(0);
	});

	test("the same path with different content is still judged", async () => {
		const resolved = config({
			rules: [
				{
					id: "pinned",
					kind: "allow-exact",
					tool: "write",
					target: path.join(CWD, "src/a.ts"),
					argumentsHash: hashArguments({ path: "src/a.ts", content: "hello" }),
					reason: "reviewed and pinned",
				},
			],
		});
		const h = harness({ resolved, judge: async () => verdict("block") });
		const result = await h.gate.evaluate(makeRequest({ args: { path: "src/a.ts", content: "EVIL" } }), AUTO);
		expect(result.decision).toBe("block");
		expect(h.judgeCalls).toHaveLength(1);
	});

	test("an unpinned allow-exact rule does not skip the judge", async () => {
		const resolved = config({
			rules: [
				{
					id: "loose",
					kind: "allow-exact",
					tool: "write",
					target: path.join(CWD, "src/a.ts"),
					reason: "loose",
				},
			],
		});
		const h = harness({ resolved, judge: async () => verdict("block") });
		const result = await h.gate.evaluate(makeRequest({}), AUTO);
		expect(result.decision).toBe("block");
		expect(h.judgeCalls).toHaveLength(1);
	});

	test("a deterministic deny still beats a pinned exact allow", async () => {
		const args = { path: ".env", content: "x" };
		const resolved = config({
			rules: [
				{ id: "no-env", kind: "deny-pattern", tool: "write", target: "**/.env*", reason: "secrets" },
				{
					id: "pinned",
					kind: "allow-exact",
					tool: "write",
					target: path.join(CWD, ".env"),
					argumentsHash: hashArguments(args),
					reason: "pinned",
				},
			],
		});
		const h = harness({ resolved });
		const result = await h.gate.evaluate(makeRequest({ args }), AUTO);
		expect(result.decision).toBe("block");
		expect(result.stage).toBe("deny-rule");
	});
});

describe("per-risk sensitivity tightens once a risk class exists", () => {
	const permissiveWithStrictExfil = () =>
		config({ sensitivity: { fallback: "permissive", byRisk: { exfiltration: "strict" } } });

	test("a strict per-risk override turns an allow into an escalation for a permissive tool", async () => {
		const h = harness({
			resolved: permissiveWithStrictExfil(),
			judge: async () => verdict("allow", "exfiltration"),
		});
		const request = makeRequest({});
		const result = await h.gate.evaluate(request, AUTO);
		expect(result.decision).toBe("block");
		expect(result.pendingAuditId).toBe(request.auditId);
		expect(store.getPending(request.auditId)?.rationale).toContain("strict sensitivity for exfiltration");
	});

	test("the judge is given the tool-level posture, since no risk class exists yet", async () => {
		const h = harness({
			resolved: permissiveWithStrictExfil(),
			judge: async () => verdict("allow", "exfiltration"),
		});
		await h.gate.evaluate(makeRequest({}), AUTO);
		expect(h.judgeCalls[0]?.sensitivity).toBe("permissive");
	});

	test("a risk class without a stricter override is unaffected", async () => {
		const h = harness({
			resolved: permissiveWithStrictExfil(),
			judge: async () => verdict("allow", "wrong-target"),
		});
		expect((await h.gate.evaluate(makeRequest({}), AUTO)).decision).toBe("allow");
	});

	test("tightening is one-directional: a permissive per-risk override cannot rescue a block", async () => {
		const resolved = config({
			sensitivity: { fallback: "strict", byRisk: { "destructive-action": "permissive" } },
		});
		const h = harness({ resolved, judge: async () => verdict("block", "destructive-action") });
		expect((await h.gate.evaluate(makeRequest({}), AUTO)).decision).toBe("block");
	});

	test("tightening is one-directional: a permissive per-risk override cannot rescue an escalation", async () => {
		const resolved = config({
			sensitivity: { fallback: "strict", byRisk: { "destructive-action": "permissive" } },
		});
		const h = harness({ resolved, judge: async () => verdict("escalate", "destructive-action") });
		expect((await h.gate.evaluate(makeRequest({}), AUTO)).decision).toBe("block");
	});

	test("no sensitivity setting overrides a deterministic deny", async () => {
		const resolved = config({
			sensitivity: { fallback: "permissive", byRisk: { "destructive-action": "permissive" } },
			rules: [{ id: "no-rm", kind: "deny-pattern", tool: "bash", target: "rm", reason: "destructive" }],
		});
		const h = harness({ resolved });
		const result = await h.gate.evaluate(makeRequest({ toolName: "bash", args: { command: "rm -rf /" } }), {
			branch: "auto",
			policy: "allow",
			tier: "exec",
			mode: "yolo",
			reason: "auto",
		});
		expect(result.decision).toBe("block");
		expect(result.stage).toBe("deny-rule");
	});

	test("a per-tool override still applies when no risk override matches", async () => {
		const resolved = config({ sensitivity: { fallback: "permissive", byTool: { write: "strict" } } });
		const h = harness({ resolved, judge: async () => verdict("allow") });
		await h.gate.evaluate(makeRequest({}), AUTO);
		expect(h.judgeCalls[0]?.sensitivity).toBe("strict");
	});
});

describe("a pinned allow is bound to its working directory", () => {
	const args = { path: "src/a.ts", content: "hello" };

	test("a rule pinned to another cwd does not skip the judge here", async () => {
		const resolved = config({
			rules: [
				{
					id: "elsewhere",
					kind: "allow-exact",
					tool: "write",
					target: path.join(CWD, "src/a.ts"),
					argumentsHash: hashArguments(args),
					cwd: "/some/other/checkout",
					reason: "pinned in a different repo",
				},
			],
		});
		const h = harness({ resolved, judge: async () => verdict("block") });
		const result = await h.gate.evaluate(makeRequest({ args }), AUTO);
		expect(result.decision).toBe("block");
		expect(h.judgeCalls).toHaveLength(1);
	});

	test("a rule with no cwd is advisory only and still reaches the judge", async () => {
		const resolved = config({
			rules: [
				{
					id: "unbound",
					kind: "allow-exact",
					tool: "write",
					target: path.join(CWD, "src/a.ts"),
					argumentsHash: hashArguments(args),
					reason: "no location binding",
				},
			],
		});
		const h = harness({ resolved, judge: async () => verdict("block") });
		expect((await h.gate.evaluate(makeRequest({ args }), AUTO)).decision).toBe("block");
		expect(h.judgeCalls).toHaveLength(1);
	});
});
