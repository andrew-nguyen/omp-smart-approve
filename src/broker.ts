/**
 * Process-global escalation broker.
 *
 * Subagents run their own extension instances in the same process, and Bun may
 * import the extension through distinct cache-busted module URLs. Module-local
 * singleton identity is therefore not reliable, so the broker lives under a
 * versioned `Symbol.for(...)` on `globalThis`.
 *
 * ## The authority rule
 *
 * Minting an allow grant requires the **literal frozen arguments** to still be
 * present here, with a canonical hash recomputed from them that matches the
 * hash the audit record was opened under. That is the whole point of this
 * module: an approval means "a human looked at exactly these bytes and said
 * yes". Once the bytes are evicted, approval degrades to recorded intent —
 * never a grant. Deny and expire stay available without them, because refusing
 * something you cannot see is always safe.
 *
 * ## Two clocks, deliberately independent
 *
 * `brokerArgsTtl` governs the in-memory literal arguments here. `pendingApprovalTtl`
 * governs the durable redacted record in SQLite. The durable record holds no raw
 * arguments, so it stays actionable long after the bytes are gone — expiring them
 * together would make the intent-to-approve path unreachable in exactly the
 * restart case it exists to serve.
 */

import type { EscalationRequest, FrozenCall, HumanDecision } from "./contracts.ts";

const BROKER_KEY = Symbol.for("omp-smart-approve.broker.v1");

export type UiCapability = "interactive" | "headless";

export interface BrokerEndpoint {
	agentId: string;
	agentKind: "main" | "sub" | "advisor" | "unknown";
	parentAgentId?: string;
	capability: UiCapability;
	/**
	 * Present a frozen call to a human and return their decision.
	 * Returns `undefined` for no UI, cancellation, or timeout — never approval.
	 */
	present(request: EscalationRequest, signal: AbortSignal): Promise<HumanDecision | undefined>;
	/**
	 * Deliver one line to the human, without asking for a decision. Optional: an
	 * endpoint that cannot reach a person simply omits it.
	 */
	notifyPending?(line: string): void;
}

/** A pending escalation whose literal arguments are still available. */
interface HeldCall {
	auditId: string;
	nonce: string;
	frozenCall: FrozenCall;
	expiresAt: number;
	/** Set once a decision has been bound, so a nonce can never be reused. */
	consumed: boolean;
}

interface BrokerState {
	endpoints: Map<string, BrokerEndpoint>;
	held: Map<string, HeldCall>;
	/** FIFO serialization of dialog presentation. */
	queue: Promise<unknown>;
	pendingCount: number;
}

interface GlobalWithBroker {
	[BROKER_KEY]?: BrokerState;
}

function state(): BrokerState {
	const container = globalThis as GlobalWithBroker;
	let existing = container[BROKER_KEY];
	if (!existing) {
		existing = { endpoints: new Map(), held: new Map(), queue: Promise.resolve(), pendingCount: 0 };
		container[BROKER_KEY] = existing;
	}
	return existing;
}

/** Test-only: drop every endpoint and held call. */
export function resetBrokerForTests(): void {
	const container = globalThis as GlobalWithBroker;
	delete container[BROKER_KEY];
}

// ---------------------------------------------------------------------------
// Endpoint registry
// ---------------------------------------------------------------------------

export function registerEndpoint(endpoint: BrokerEndpoint): void {
	state().endpoints.set(endpoint.agentId, endpoint);
}

export function unregisterEndpoint(agentId: string): void {
	state().endpoints.delete(agentId);
}

export function listEndpoints(): BrokerEndpoint[] {
	return [...state().endpoints.values()];
}

/**
 * The one endpoint allowed to answer for a human.
 *
 * Only a `main` agent with an interactive capability qualifies. A subagent can
 * never approve its own escalation, and a headless main is not a human channel.
 */
export function humanEndpoint(): BrokerEndpoint | undefined {
	for (const endpoint of state().endpoints.values()) {
		if (endpoint.agentKind === "main" && endpoint.capability === "interactive") return endpoint;
	}
	return undefined;
}

/** Is there a live main-session approval channel right now? Checked synchronously. */
export function hasHumanChannel(): boolean {
	return humanEndpoint() !== undefined;
}

/**
 * Tell the human one line about an escalation they now have to decide out of
 * band. Returns whether anyone heard.
 *
 * Best-effort by construction: a throwing notify is swallowed, because a broken
 * status line must never change a safety verdict. Routed through
 * {@link humanEndpoint} for the same reason `present` is, so a subagent's
 * escalation surfaces in the main session rather than nowhere.
 */
export function notifyHuman(line: string): boolean {
	const endpoint = humanEndpoint();
	if (endpoint?.notifyPending === undefined) return false;
	try {
		endpoint.notifyPending(line);
		return true;
	} catch {
		return false;
	}
}

// ---------------------------------------------------------------------------
// Held literal calls
// ---------------------------------------------------------------------------

export interface HoldOptions {
	auditId: string;
	nonce: string;
	frozenCall: FrozenCall;
	/** Absolute epoch ms, derived from `brokerArgsTtl`. */
	expiresAt: number;
	/** Cap on simultaneously held calls, to bound memory under a runaway agent. */
	maxHeld?: number;
}

export function holdCall(options: HoldOptions): void {
	const s = state();
	const max = options.maxHeld ?? 64;
	if (s.held.size >= max) {
		// Evict the oldest expiring entry rather than refusing to hold: losing the
		// literal bytes degrades a future approval to intent, which is safe, while
		// refusing to hold would lose the escalation entirely.
		let oldestKey: string | undefined;
		let oldestAt = Number.POSITIVE_INFINITY;
		for (const [key, entry] of s.held) {
			if (entry.expiresAt < oldestAt) {
				oldestAt = entry.expiresAt;
				oldestKey = key;
			}
		}
		if (oldestKey) s.held.delete(oldestKey);
	}
	s.held.set(options.auditId, {
		auditId: options.auditId,
		nonce: options.nonce,
		frozenCall: options.frozenCall,
		expiresAt: options.expiresAt,
		consumed: false,
	});
}

export function releaseCall(auditId: string): void {
	state().held.delete(auditId);
}

/** Drop every held call whose broker TTL has passed. Returns the count dropped. */
export function evictExpired(now: number): number {
	const s = state();
	let dropped = 0;
	for (const [key, entry] of s.held) {
		if (entry.expiresAt <= now) {
			s.held.delete(key);
			dropped += 1;
		}
	}
	return dropped;
}

/** The literal frozen call for an audit ID, if it is still held and unexpired. */
export function heldCall(auditId: string, now: number): FrozenCall | undefined {
	const entry = state().held.get(auditId);
	if (!entry || entry.expiresAt <= now) return undefined;
	return entry.frozenCall;
}

export type GrantAuthority =
	| { kind: "mintable"; frozenCall: FrozenCall }
	/** The record is actionable, but no grant can be minted from it. */
	| { kind: "intent-only"; reason: string };

/**
 * Can an approval for this audit ID mint an exact allow grant?
 *
 * Requires the literal arguments to be held, unexpired, and to still hash to the
 * value the audit was opened under. A recompute mismatch means the bytes in
 * memory are not the bytes we are being asked to approve, which is a refusal —
 * not a warning.
 */
export function grantAuthority(
	auditId: string,
	expectedArgumentsHash: string,
	now: number,
	recomputeHash: (args: Readonly<Record<string, unknown>>) => string,
): GrantAuthority {
	const entry = state().held.get(auditId);
	if (!entry) {
		return {
			kind: "intent-only",
			reason: "the literal arguments are no longer in memory (session restart, subagent teardown, or broker TTL expiry)",
		};
	}
	if (entry.expiresAt <= now) {
		return { kind: "intent-only", reason: "the literal arguments passed their broker TTL" };
	}
	const recomputed = recomputeHash(entry.frozenCall.rawArguments);
	if (recomputed !== expectedArgumentsHash) {
		return {
			kind: "intent-only",
			reason: "the held arguments no longer hash to the value this audit record was opened under",
		};
	}
	return { kind: "mintable", frozenCall: entry.frozenCall };
}

// ---------------------------------------------------------------------------
// Decision binding
// ---------------------------------------------------------------------------

export type BindResult = { ok: true; decision: HumanDecision } | { ok: false; reason: string };

/**
 * Validate and single-use-consume a human decision.
 *
 * Every one of these checks is a refusal, never a warning: a late answer, a
 * reused nonce, or a call whose arguments changed underneath the dialog must not
 * unblock execution.
 */
export function bindDecision(decision: HumanDecision, now: number): BindResult {
	const entry = state().held.get(decision.auditId);
	if (!entry) return { ok: false, reason: "no held call for this audit ID" };
	if (entry.consumed) return { ok: false, reason: "this approval was already used" };
	if (entry.expiresAt <= now) return { ok: false, reason: "the approval window expired" };
	if (entry.nonce !== decision.nonce) return { ok: false, reason: "nonce mismatch" };
	if (entry.frozenCall.argumentsHash !== decision.argumentsHash) {
		return { ok: false, reason: "the call arguments changed after the human saw them" };
	}
	entry.consumed = true;
	return { ok: true, decision };
}

// ---------------------------------------------------------------------------
// Escalation routing
// ---------------------------------------------------------------------------

export interface PresentOptions {
	request: EscalationRequest;
	signal: AbortSignal;
	/** Bound on simultaneously queued dialogs. Beyond it, escalation blocks. */
	maxQueued?: number;
}

/**
 * Route an escalation to the human endpoint, serialized FIFO.
 *
 * Returns `undefined` for every non-approval outcome: no human channel, a full
 * queue, an aborted handler, a cancelled dialog, or a timeout. The caller treats
 * `undefined` as "no human answer" and falls through to the durable pending path.
 */
export async function presentToHuman(options: PresentOptions): Promise<HumanDecision | undefined> {
	const s = state();
	const endpoint = humanEndpoint();
	if (!endpoint) return undefined;
	if (options.signal.aborted) return undefined;

	const max = options.maxQueued ?? 8;
	if (s.pendingCount >= max) return undefined;

	// Deduplicate: the same audit ID must never open two dialogs.
	const entry = s.held.get(options.request.auditId);
	if (entry?.consumed) return undefined;

	s.pendingCount += 1;
	const run = s.queue.then(async () => {
		if (options.signal.aborted) return undefined;
		try {
			return await endpoint.present(options.request, options.signal);
		} catch {
			// A throwing dialog is an unavailable dialog, never an approval.
			return undefined;
		}
	});
	// Keep the chain alive even when this presentation rejects, so one failure
	// cannot wedge the queue for every later escalation.
	s.queue = run.then(
		() => undefined,
		() => undefined,
	);

	try {
		return await run;
	} finally {
		s.pendingCount -= 1;
	}
}

/** How many escalations are queued or being presented right now. */
export function queueDepth(): number {
	return state().pendingCount;
}
