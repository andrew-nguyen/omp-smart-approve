import { afterEach, describe, expect, test } from "bun:test";
import {
	type BrokerEndpoint,
	bindDecision,
	evictExpired,
	grantAuthority,
	hasHumanChannel,
	heldCall,
	holdCall,
	humanEndpoint,
	listEndpoints,
	notifyHuman,
	presentToHuman,
	queueDepth,
	registerEndpoint,
	releaseCall,
	resetBrokerForTests,
	unregisterEndpoint,
} from "../src/broker.ts";
import type { EscalationRequest, FrozenCall, HumanDecision } from "../src/contracts.ts";
import { hashArguments } from "../src/policy.ts";

afterEach(() => resetBrokerForTests());

const NOW = 1_000_000;

function frozen(args: Record<string, unknown> = { path: "a.ts", content: "hello" }): FrozenCall {
	return {
		toolName: "write",
		toolCallId: "call-1",
		rawArguments: Object.freeze(args),
		argumentsHash: hashArguments(args),
		frozenAt: NOW,
	};
}

function request(overrides: Partial<EscalationRequest> = {}): EscalationRequest {
	const call = overrides.frozenCall ?? frozen();
	return {
		auditId: "audit-1",
		nonce: "nonce-1",
		frozenCall: call,
		canonicalCall: { toolName: "write", operation: "write", targets: [], argumentsHash: call.argumentsHash },
		risk: "uncertain",
		rationale: "needs a human",
		context: {
			userIntent: "clean up the branch history",
			agentRationale: "force-pushing the rebased branch",
			rationaleFreshness: "current-turn",
			rationaleFromReasoning: false,
			flaggedBy: "judge",
		},
		sourceAgentId: "Main",
		sourceAgentKind: "main",
		expiresAt: NOW + 20_000,
		...overrides,
	};
}

function endpoint(overrides: Partial<BrokerEndpoint> = {}): BrokerEndpoint {
	return {
		agentId: "Main",
		agentKind: "main",
		capability: "interactive",
		present: async () => undefined,
		...overrides,
	};
}

/**
 * These two tests deliberately exercise a module-loading boundary, which is the
 * named exception to the static-import rule: OMP gives a subagent the discovered
 * extension path and Bun may resolve it through a distinct cache-busted URL, so a
 * second module instance is exactly the condition the symbol broker exists to
 * survive. A static import would resolve to the same instance and prove nothing.
 */
describe("process-global identity", () => {
	test("a separately imported module sees the same broker", async () => {
		registerEndpoint(endpoint());
		const second = await import(`../src/broker.ts?cacheBust=${Date.now()}`);
		expect(second.listEndpoints()).toHaveLength(1);
		expect(second.humanEndpoint()?.agentId).toBe("Main");
	});

	test("registration from a second import is visible to the first", async () => {
		const second = await import(`../src/broker.ts?cacheBust=${Date.now()}-b`);
		second.registerEndpoint({
			agentId: "Sub1",
			agentKind: "sub",
			capability: "headless",
			present: async () => undefined,
		});
		expect(listEndpoints().map(e => e.agentId)).toContain("Sub1");
	});
});

describe("main election", () => {
	test("elects the interactive main agent", () => {
		registerEndpoint(endpoint({ agentId: "Sub1", agentKind: "sub" }));
		registerEndpoint(endpoint({ agentId: "Main", agentKind: "main" }));
		expect(humanEndpoint()?.agentId).toBe("Main");
	});

	test("a subagent is never elected, even when it claims an interactive UI", () => {
		registerEndpoint(endpoint({ agentId: "Sub1", agentKind: "sub", capability: "interactive" }));
		expect(humanEndpoint()).toBeUndefined();
		expect(hasHumanChannel()).toBe(false);
	});

	test("a headless main is not a human channel", () => {
		registerEndpoint(endpoint({ capability: "headless" }));
		expect(hasHumanChannel()).toBe(false);
	});

	test("unregistering removes the channel", () => {
		registerEndpoint(endpoint());
		expect(hasHumanChannel()).toBe(true);
		unregisterEndpoint("Main");
		expect(hasHumanChannel()).toBe(false);
	});
});

describe("out-of-band notification", () => {
	test("reaches the interactive main session", () => {
		const heard: string[] = [];
		registerEndpoint(endpoint({ notifyPending: line => heard.push(line) }));

		expect(notifyHuman("Smart Approve held a bash call.")).toBe(true);
		expect(heard).toEqual(["Smart Approve held a bash call."]);
	});

	test("a subagent escalation reaches the main session, not the subagent", () => {
		const sub: string[] = [];
		const main: string[] = [];
		registerEndpoint(endpoint({ agentId: "Sub1", agentKind: "sub", notifyPending: line => sub.push(line) }));
		registerEndpoint(endpoint({ agentId: "Main", notifyPending: line => main.push(line) }));

		expect(notifyHuman("held")).toBe(true);
		expect(main).toEqual(["held"]);
		expect(sub).toEqual([]);
	});

	test("no-ops with no human channel and with a headless main", () => {
		expect(notifyHuman("held")).toBe(false);

		const heard: string[] = [];
		registerEndpoint(endpoint({ capability: "headless", notifyPending: line => heard.push(line) }));
		expect(notifyHuman("held")).toBe(false);
		expect(heard).toEqual([]);
	});

	test("an endpoint with no notify channel reports that nobody heard", () => {
		registerEndpoint(endpoint());
		expect(notifyHuman("held")).toBe(false);
	});

	test("a throwing notify is swallowed, because a status line cannot change a verdict", () => {
		registerEndpoint(
			endpoint({
				notifyPending: () => {
					throw new Error("the TUI is gone");
				},
			}),
		);

		expect(notifyHuman("held")).toBe(false);
	});
});

describe("held literal arguments", () => {
	test("a held call is retrievable before its TTL", () => {
		holdCall({ auditId: "a1", nonce: "n", frozenCall: frozen(), expiresAt: NOW + 1000 });
		expect(heldCall("a1", NOW)?.toolName).toBe("write");
	});

	test("a held call is gone after its TTL", () => {
		holdCall({ auditId: "a1", nonce: "n", frozenCall: frozen(), expiresAt: NOW + 1000 });
		expect(heldCall("a1", NOW + 1001)).toBeUndefined();
	});

	test("eviction drops only expired entries", () => {
		holdCall({ auditId: "old", nonce: "n", frozenCall: frozen(), expiresAt: NOW + 100 });
		holdCall({ auditId: "new", nonce: "n", frozenCall: frozen(), expiresAt: NOW + 10_000 });
		expect(evictExpired(NOW + 200)).toBe(1);
		expect(heldCall("new", NOW + 200)).toBeDefined();
	});

	test("releasing drops the literal bytes immediately", () => {
		holdCall({ auditId: "a1", nonce: "n", frozenCall: frozen(), expiresAt: NOW + 10_000 });
		releaseCall("a1");
		expect(heldCall("a1", NOW)).toBeUndefined();
	});

	test("the hold table is bounded, evicting the soonest-expiring entry", () => {
		for (let i = 0; i < 5; i += 1) {
			holdCall({
				auditId: `a${i}`,
				nonce: "n",
				frozenCall: frozen(),
				expiresAt: NOW + 100 * (i + 1),
				maxHeld: 3,
			});
		}
		const survivors = ["a0", "a1", "a2", "a3", "a4"].filter(id => heldCall(id, NOW) !== undefined);
		expect(survivors.length).toBeLessThanOrEqual(3);
		// The newest (longest-lived) entry survived.
		expect(heldCall("a4", NOW)).toBeDefined();
	});
});

describe("grant authority requires the literal call", () => {
	const call = frozen();

	test("mintable while the exact bytes are held and hash matches", () => {
		holdCall({ auditId: "a1", nonce: "n", frozenCall: call, expiresAt: NOW + 10_000 });
		const authority = grantAuthority("a1", call.argumentsHash, NOW, hashArguments);
		expect(authority.kind).toBe("mintable");
	});

	test("intent-only once the bytes are evicted, never a grant", () => {
		const authority = grantAuthority("gone", call.argumentsHash, NOW, hashArguments);
		expect(authority.kind).toBe("intent-only");
		expect(authority.kind === "intent-only" && authority.reason).toContain("no longer in memory");
	});

	test("intent-only after the broker TTL, even though the audit ID stays actionable", () => {
		holdCall({ auditId: "a1", nonce: "n", frozenCall: call, expiresAt: NOW + 100 });
		const authority = grantAuthority("a1", call.argumentsHash, NOW + 200, hashArguments);
		expect(authority.kind).toBe("intent-only");
		expect(authority.kind === "intent-only" && authority.reason).toContain("broker TTL");
	});

	test("refuses to mint when the recomputed hash disagrees with the audit record", () => {
		holdCall({ auditId: "a1", nonce: "n", frozenCall: call, expiresAt: NOW + 10_000 });
		const authority = grantAuthority("a1", "a".repeat(64), NOW, hashArguments);
		expect(authority.kind).toBe("intent-only");
		expect(authority.kind === "intent-only" && authority.reason).toContain("no longer hash to the value");
	});

	test("recomputes from the held bytes rather than trusting the stored hash", () => {
		// A tampered FrozenCall whose declared hash does not match its own arguments
		// must not be mintable against that declared hash.
		const tampered: FrozenCall = { ...frozen({ path: "evil.ts" }), argumentsHash: call.argumentsHash };
		holdCall({ auditId: "a1", nonce: "n", frozenCall: tampered, expiresAt: NOW + 10_000 });
		expect(grantAuthority("a1", call.argumentsHash, NOW, hashArguments).kind).toBe("intent-only");
	});
});

describe("decision binding", () => {
	const call = frozen();

	function decision(overrides: Partial<HumanDecision> = {}): HumanDecision {
		return {
			auditId: "a1",
			nonce: "n1",
			choice: "allow-once",
			argumentsHash: call.argumentsHash,
			decidedAt: NOW,
			...overrides,
		};
	}

	test("binds a matching decision exactly once", () => {
		holdCall({ auditId: "a1", nonce: "n1", frozenCall: call, expiresAt: NOW + 10_000 });
		expect(bindDecision(decision(), NOW).ok).toBe(true);
		const second = bindDecision(decision(), NOW);
		expect(second.ok).toBe(false);
		expect(second.ok === false && second.reason).toContain("already used");
	});

	test("rejects a nonce mismatch", () => {
		holdCall({ auditId: "a1", nonce: "n1", frozenCall: call, expiresAt: NOW + 10_000 });
		const out = bindDecision(decision({ nonce: "wrong" }), NOW);
		expect(out.ok).toBe(false);
		expect(out.ok === false && out.reason).toContain("nonce mismatch");
	});

	test("rejects a decision whose arguments hash changed under the dialog", () => {
		holdCall({ auditId: "a1", nonce: "n1", frozenCall: call, expiresAt: NOW + 10_000 });
		const out = bindDecision(decision({ argumentsHash: "b".repeat(64) }), NOW);
		expect(out.ok).toBe(false);
		expect(out.ok === false && out.reason).toContain("arguments changed");
	});

	test("rejects a late answer after the window closed", () => {
		holdCall({ auditId: "a1", nonce: "n1", frozenCall: call, expiresAt: NOW + 100 });
		const out = bindDecision(decision({ decidedAt: NOW + 500 }), NOW + 500);
		expect(out.ok).toBe(false);
		expect(out.ok === false && out.reason).toContain("expired");
	});

	test("rejects a decision for an unknown audit ID", () => {
		expect(bindDecision(decision({ auditId: "ghost" }), NOW).ok).toBe(false);
	});

	test("a deny is bound with the same rigor as an allow", () => {
		holdCall({ auditId: "a1", nonce: "n1", frozenCall: call, expiresAt: NOW + 10_000 });
		expect(bindDecision(decision({ choice: "deny", nonce: "wrong" }), NOW).ok).toBe(false);
	});
});

describe("presentation routing", () => {
	test("returns undefined with no human channel, never an approval", async () => {
		const out = await presentToHuman({ request: request(), signal: new AbortController().signal });
		expect(out).toBeUndefined();
	});

	test("returns undefined when only a headless main exists", async () => {
		registerEndpoint(endpoint({ capability: "headless" }));
		expect(await presentToHuman({ request: request(), signal: new AbortController().signal })).toBeUndefined();
	});

	test("routes a subagent escalation to the interactive main", async () => {
		let seen: EscalationRequest | undefined;
		registerEndpoint(endpoint({ agentId: "Sub1", agentKind: "sub", capability: "headless" }));
		registerEndpoint(
			endpoint({
				present: async req => {
					seen = req;
					return {
						auditId: req.auditId,
						nonce: req.nonce,
						choice: "allow-once",
						argumentsHash: req.frozenCall.argumentsHash,
						decidedAt: NOW,
					};
				},
			}),
		);
		const req = request({ sourceAgentId: "Sub1", sourceAgentKind: "sub" });
		const out = await presentToHuman({ request: req, signal: new AbortController().signal });
		expect(out?.choice).toBe("allow-once");
		// The main endpoint saw the literal frozen call, not a paraphrase.
		expect(seen?.frozenCall.rawArguments).toEqual(req.frozenCall.rawArguments);
	});

	test("an aborted handler never presents a dialog", async () => {
		let presented = false;
		registerEndpoint(
			endpoint({
				present: async () => {
					presented = true;
					return undefined;
				},
			}),
		);
		const controller = new AbortController();
		controller.abort();
		expect(await presentToHuman({ request: request(), signal: controller.signal })).toBeUndefined();
		expect(presented).toBe(false);
	});

	test("a throwing dialog yields undefined rather than propagating as an allow", async () => {
		registerEndpoint(
			endpoint({
				present: async () => {
					throw new Error("tui exploded");
				},
			}),
		);
		expect(await presentToHuman({ request: request(), signal: new AbortController().signal })).toBeUndefined();
	});

	test("presentations serialize FIFO rather than overlapping", async () => {
		const order: string[] = [];
		// Each presentation blocks on a deferred this test resolves explicitly, so
		// overlap is detected by construction rather than by racing a wall clock.
		const gates = new Map<string, () => void>();
		let active = 0;
		let maxActive = 0;
		registerEndpoint(
			endpoint({
				present: async req => {
					active += 1;
					maxActive = Math.max(maxActive, active);
					order.push(req.auditId);
					await new Promise<void>(resolve => gates.set(req.auditId, resolve));
					active -= 1;
					return undefined;
				},
			}),
		);

		const all = Promise.all(
			["a1", "a2", "a3"].map(auditId =>
				presentToHuman({ request: request({ auditId }), signal: new AbortController().signal }),
			),
		);

		// Release them one at a time; the next only starts once the previous returns.
		// Spinning the microtask queue is deterministic here: `presentToHuman` chains
		// on an already-resolved promise, so a bounded flush always reaches the gate.
		for (const auditId of ["a1", "a2", "a3"]) {
			for (let spin = 0; spin < 100 && !gates.has(auditId); spin += 1) await Promise.resolve();
			gates.get(auditId)?.();
		}
		await all;

		expect(maxActive).toBe(1);
		expect(order).toEqual(["a1", "a2", "a3"]);
	});

	test("a full queue blocks rather than dropping the serialization guarantee", async () => {
		let release: (() => void) | undefined;
		registerEndpoint(
			endpoint({
				present: async () => {
					await new Promise<void>(resolve => {
						release = resolve;
					});
					return undefined;
				},
			}),
		);
		const inflight = presentToHuman({
			request: request({ auditId: "a1" }),
			signal: new AbortController().signal,
			maxQueued: 1,
		});
		const rejected = await presentToHuman({
			request: request({ auditId: "a2" }),
			signal: new AbortController().signal,
			maxQueued: 1,
		});
		expect(rejected).toBeUndefined();
		release?.();
		await inflight;
		expect(queueDepth()).toBe(0);
	});

	test("an already-consumed audit ID does not open a second dialog", async () => {
		const call = frozen();
		holdCall({ auditId: "a1", nonce: "n1", frozenCall: call, expiresAt: NOW + 10_000 });
		bindDecision(
			{ auditId: "a1", nonce: "n1", choice: "allow-once", argumentsHash: call.argumentsHash, decidedAt: NOW },
			NOW,
		);
		let presented = false;
		registerEndpoint(
			endpoint({
				present: async () => {
					presented = true;
					return undefined;
				},
			}),
		);
		expect(
			await presentToHuman({ request: request({ auditId: "a1" }), signal: new AbortController().signal }),
		).toBeUndefined();
		expect(presented).toBe(false);
	});

	test("one failing presentation does not wedge the queue for the next", async () => {
		let calls = 0;
		registerEndpoint(
			endpoint({
				present: async req => {
					calls += 1;
					if (req.auditId === "a1") throw new Error("boom");
					return {
						auditId: req.auditId,
						nonce: req.nonce,
						choice: "deny",
						argumentsHash: req.frozenCall.argumentsHash,
						decidedAt: NOW,
					};
				},
			}),
		);
		await presentToHuman({ request: request({ auditId: "a1" }), signal: new AbortController().signal });
		const second = await presentToHuman({
			request: request({ auditId: "a2" }),
			signal: new AbortController().signal,
		});
		expect(calls).toBe(2);
		expect(second?.choice).toBe("deny");
	});
});
