/**
 * Deadline behavior under a fake clock.
 *
 * OMP hard-caps a `tool_call` handler at 30 seconds and converts an overrun into
 * an ambiguous host error rather than a safety decision. These tests prove the
 * worst-case configured path always finishes strictly inside that cap, and that
 * every way of running out of time ends in a block rather than an allow.
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { heldCall, registerEndpoint, resetBrokerForTests } from "../src/broker.ts";
import {
	computeDeadlineBudget,
	type DiscoveryPaths,
	MAX_SELF_DEADLINE_MS,
	OMP_HANDLER_CAP_MS,
	type ResolvedConfig,
	resolveConfig,
	smartApproveConfigSchema,
} from "../src/config.ts";
import type {
	EscalationRequest,
	GatePorts,
	GateRequest,
	HostApproval,
	HumanDecision,
	JudgeResult,
} from "../src/contracts.ts";
import { Gate } from "../src/gate.ts";
import { extractTargets, hashArguments } from "../src/policy.ts";
import { openStore, type SmartApproveStore } from "../src/store.ts";

const CWD = "/repo/project";
const START = 1_700_000_000_000;
const paths: DiscoveryPaths = { cwd: CWD, agentDir: "/home/dev/.omp/agent", home: "/home/dev" };

let dir: string;
let store: SmartApproveStore;
let clock: number;

beforeEach(() => {
	dir = mkdtempSync(path.join(tmpdir(), "sa-deadline-"));
	store = openStore(path.join(dir, "state.sqlite"));
	clock = START;
	resetBrokerForTests();
});

afterEach(() => {
	store.close();
	rmSync(dir, { recursive: true, force: true });
	resetBrokerForTests();
});

function config(timeouts: Record<string, number> = {}): ResolvedConfig {
	return resolveConfig(
		[
			{
				scope: "user",
				filePath: "/u.yml",
				rawContent: "{}",
				data: { judge: { authorizedModels: ["anthropic/haiku"] }, timeouts },
			},
		],
		[],
		paths,
	);
}

function makeRequest(deadlineMs: number): GateRequest {
	const args = { path: "src/a.ts", content: "hello" };
	const extracted = extractTargets({ toolName: "write", args, cwd: CWD });
	return {
		auditId: `audit-${Math.random().toString(36).slice(2)}`,
		toolCallId: "call-1",
		toolName: "write",
		sourceAgentId: "Main",
		sourceAgentKind: "main",
		canonicalCall: {
			toolName: "write",
			operation: extracted.operation,
			targets: extracted.targets,
			argumentsHash: hashArguments(args),
		},
		rawArguments: Object.freeze(args),
		argumentsHash: hashArguments(args),
		cwd: CWD,
		receivedAt: clock,
		deadlineAt: clock + deadlineMs,
	};
}

const AUTO: HostApproval = { branch: "auto", policy: "allow", tier: "write", mode: "yolo", reason: "auto" };

function gateWith(options: {
	resolved: ResolvedConfig;
	judge: () => Promise<JudgeResult>;
	escalate?: (req: EscalationRequest, signal: AbortSignal) => Promise<HumanDecision | undefined>;
}): Gate {
	const ports: GatePorts = {
		classifyHostApproval: async () => AUTO,
		judge: async () => await options.judge(),
		escalate: async (req, signal) => (options.escalate ? await options.escalate(req, signal) : undefined),
		now: () => clock,
		randomNonce: () => "nonce-1",
		randomId: () => "id-1",
	};
	return new Gate({
		resolved: options.resolved,
		store,
		ports,
		buildJudgeInput: request => ({
			userIntent: "u",
			agentRationale: "a",
			rationaleFreshness: "current-turn",
			rationaleFromReasoning: false,
			toolName: request.toolName,
			operation: request.canonicalCall.operation,
			argumentsView: "{}",
			targets: [...request.canonicalCall.targets],
			omittedTargets: 0,
			sourceAgentId: request.sourceAgentId,
			recentActions: [],
			policyDocuments: [],
			postureHints: [],
			sensitivity: "balanced",
			incompleteCriticalContext: false,
		}),
		buildEscalationContext: () => ({
			userIntent: "u",
			agentRationale: "a",
			rationaleFreshness: "current-turn",
			rationaleFromReasoning: false,
		}),
	});
}

describe("the configured budget provably fits inside OMP's handler cap", () => {
	test("the default worst case leaves headroom under the 30s cap", () => {
		const defaults = smartApproveConfigSchema.parse({});
		const budget = computeDeadlineBudget(defaults.timeouts);
		expect(budget.worstCaseJudgeSpendMs).toBeLessThan(budget.effectiveDeadlineMs);
		expect(budget.effectiveDeadlineMs).toBeLessThan(OMP_HANDLER_CAP_MS);
	});

	test("the self-deadline can never be configured up to the host cap", () => {
		expect(MAX_SELF_DEADLINE_MS).toBeLessThan(OMP_HANDLER_CAP_MS);
		expect(() =>
			computeDeadlineBudget({
				...smartApproveConfigSchema.parse({}).timeouts,
				handlerSelfDeadlineMs: OMP_HANDLER_CAP_MS,
			}),
		).toThrow();
	});

	test("the worst case including a full dialog still finishes before the host cap", () => {
		const defaults = smartApproveConfigSchema.parse({});
		const budget = computeDeadlineBudget(defaults.timeouts);
		// Judge spends everything, then whatever dialog window is left is consumed.
		const total = budget.worstCaseJudgeSpendMs + budget.worstCaseDialogWindowMs;
		expect(total).toBeLessThanOrEqual(budget.effectiveDeadlineMs);
		expect(total).toBeLessThan(OMP_HANDLER_CAP_MS);
	});

	test("every accepted timeout configuration keeps judge spend inside the deadline", () => {
		const combinations = [
			{ attempts: 1, modelTimeoutMs: 10_000 },
			{ attempts: 2, modelTimeoutMs: 10_000 },
			{ attempts: 2, modelTimeoutMs: 13_000 },
			{ attempts: 3, modelTimeoutMs: 9_000 },
			{ attempts: 1, modelTimeoutMs: 27_000 },
		];
		const base = smartApproveConfigSchema.parse({}).timeouts;
		for (const combo of combinations) {
			const budget = computeDeadlineBudget({ ...base, ...combo });
			expect(budget.worstCaseJudgeSpendMs).toBeLessThanOrEqual(budget.effectiveDeadlineMs);
			expect(budget.worstCaseJudgeSpendMs).toBeLessThan(OMP_HANDLER_CAP_MS);
		}
	});
});

describe("running out of time blocks, never allows", () => {
	test("a judge that consumes the entire budget ends as a pending block", async () => {
		const resolved = config();
		const gate = gateWith({
			resolved,
			judge: async () => {
				clock += 21_000;
				return {
					ok: false,
					failure: { kind: "timeout", detail: "attempt exceeded 10000ms" },
					metrics: { attempts: 2, latencyMs: 21_000, overTarget: true },
				};
			},
		});
		const request = makeRequest(28_000);
		const result = await gate.evaluate(request, AUTO);
		expect(result.decision).toBe("block");
		expect(clock - request.receivedAt).toBeLessThan(OMP_HANDLER_CAP_MS);
	});

	test("an exhausted budget skips the fast-path dialog entirely", async () => {
		let presented = false;
		registerEndpoint({
			agentId: "Main",
			agentKind: "main",
			capability: "interactive",
			present: async () => {
				presented = true;
				return undefined;
			},
		});
		const gate = gateWith({
			resolved: config(),
			judge: async () => {
				// Burn everything but the cleanup margin.
				clock += 27_500;
				return {
					ok: true,
					verdict: { decision: "escalate", risk: "uncertain", rationale: "needs a human" },
					metrics: { attempts: 2, latencyMs: 27_500, overTarget: true },
				};
			},
			escalate: async () => {
				presented = true;
				return undefined;
			},
		});
		const result = await gate.evaluate(makeRequest(28_000), AUTO);
		expect(presented).toBe(false);
		expect(result.decision).toBe("block");
	});

	test("a dialog is offered only when the remaining window clears the floor", async () => {
		registerEndpoint({
			agentId: "Main",
			agentKind: "main",
			capability: "interactive",
			present: async () => undefined,
		});
		let presented = 0;
		const gate = gateWith({
			resolved: config(),
			judge: async () => {
				clock += 1_000;
				return {
					ok: true,
					verdict: { decision: "escalate", risk: "uncertain", rationale: "needs a human" },
					metrics: { attempts: 1, latencyMs: 1_000, overTarget: false },
				};
			},
			escalate: async () => {
				presented += 1;
				return undefined;
			},
		});
		await gate.evaluate(makeRequest(28_000), AUTO);
		expect(presented).toBe(1);
	});

	test("an already-expired deadline still produces an audited block, not a crash", async () => {
		const gate = gateWith({
			resolved: config(),
			judge: async () => ({
				ok: false,
				failure: { kind: "deadline-exhausted", detail: "no budget remained" },
				metrics: { attempts: 0, latencyMs: 0, overTarget: false },
			}),
		});
		const request = makeRequest(0);
		const result = await gate.evaluate(request, AUTO);
		expect(result.decision).toBe("block");
		expect(store.getPending(request.auditId)?.state).toBe("awaiting-human");
	});

	test("the durable pending record outlives the handler budget by design", async () => {
		const resolved = config();
		const gate = gateWith({
			resolved,
			judge: async () => ({
				ok: true,
				verdict: { decision: "escalate", risk: "uncertain", rationale: "needs a human" },
				metrics: { attempts: 1, latencyMs: 10, overTarget: false },
			}),
		});
		const request = makeRequest(28_000);
		await gate.evaluate(request, AUTO);
		const pending = store.getPending(request.auditId);
		// 24h by default: far beyond any handler budget.
		expect((pending?.expiresAt ?? 0) - clock).toBeGreaterThan(OMP_HANDLER_CAP_MS * 100);
		// And it is still actionable long after the handler would have died.
		clock += 60 * 60_000;
		expect(store.listOpenPending(clock).some(p => p.auditId === request.auditId)).toBe(true);
	});
});

describe("the two clocks are independent", () => {
	test("literal arguments expire long before the record stops being actionable", async () => {
		const resolved = config({ brokerArgsTtlMs: 60_000, pendingApprovalTtlMs: 24 * 60 * 60_000 });
		const gate = gateWith({
			resolved,
			judge: async () => ({
				ok: true,
				verdict: { decision: "escalate", risk: "uncertain", rationale: "needs a human" },
				metrics: { attempts: 1, latencyMs: 10, overTarget: false },
			}),
		});
		const request = makeRequest(28_000);
		await gate.evaluate(request, AUTO);

		expect(heldCall(request.auditId, clock)).toBeDefined();

		// Past the broker TTL: the bytes are gone.
		clock += 120_000;
		expect(heldCall(request.auditId, clock)).toBeUndefined();

		// But the durable record is still open and reviewable, which is exactly the
		// restart case the intent-to-approve path exists to serve.
		expect(store.listOpenPending(clock).some(p => p.auditId === request.auditId)).toBe(true);
	});
});
