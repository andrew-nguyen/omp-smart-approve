/**
 * OMP-specific host adapter: resolve the live session and reconstruct the native
 * approval decision for one tool call.
 *
 * This is the only file that knows OMP internals. Everything downstream consumes
 * the closed {@link HostApproval} shape, so a future public
 * `ToolCallEvent.resolvedApproval` field can replace this adapter without
 * touching policy, judge, or gate code.
 *
 * ## Why this adapter cannot just read a setting
 *
 * OMP 17.2.4 computes the effective approval mode as:
 *
 * ```ts
 * const approvalMode = context?.autoApprove === true ? "yolo" : settings.get("tools.approvalMode") ?? "yolo";
 * ```
 *
 * `context.autoApprove` is private constructor state on `AgentToolContext`. Both
 * `--auto-approve` and `--yolo` set it (`cli/args.ts`: `result.autoApprove = true`)
 * and **neither writes `tools.approvalMode`**. There is no public accessor.
 *
 * So a session started with `--auto-approve` while `tools.approvalMode` is
 * `always-ask` would look like "OMP will prompt" when OMP will in fact run the
 * call silently. Treating that as the prompt branch means we only pre-screen —
 * a fail-open hole. Three signals close it:
 *
 * 1. **argv scan** — the extension shares the CLI process, so `--auto-approve`
 *    and `--yolo` are directly observable. Covers every CLI/TUI/RPC session.
 * 2. **retroactive latch** — if a call we classified `prompt` begins executing
 *    without OMP ever emitting `tool_approval_requested`, the host is
 *    auto-approving regardless of settings. Latch it for the session. Covers
 *    embedded SDK hosts after exactly one call.
 * 3. **fail closed on unresolved state** — an unknown session, tool, or tier is
 *    `unsupported`, never an optimistic `auto` or `prompt`.
 */

import { AgentRegistry } from "@oh-my-pi/pi-coding-agent";
import { type ApprovalMode, resolveApproval, resolveToolTier } from "@oh-my-pi/pi-coding-agent/tools/approval";
import type { HostApproval, ToolTier } from "./contracts.ts";

/** Mirrors the subset of `AgentTool` that `resolveApproval` needs. */
interface ApprovalSubject {
	name: string;
	approval?: unknown;
	formatApprovalDetails?: unknown;
}

/** Mirrors the subset of a live `AgentSession` this adapter reads. */
export interface LiveSession {
	settings: { get(key: string): unknown };
	agent: { state: { tools: ApprovalSubject[] } };
	sessionManager: unknown;
}

export interface ResolvedAgentIdentity {
	agentId: string;
	agentKind: "main" | "sub" | "advisor" | "unknown";
	parentAgentId?: string;
	session?: LiveSession;
}

/** The `--auto-approve` / `--yolo` CLI flags, which never reach `tools.approvalMode`. */
const AUTO_APPROVE_FLAGS = new Set(["--auto-approve", "--yolo"]);

export function argvRequestsAutoApprove(argv: readonly string[]): boolean {
	for (const arg of argv) {
		if (AUTO_APPROVE_FLAGS.has(arg)) return true;
		// `--` ends OMP's own flags; anything after belongs to the prompt.
		if (arg === "--") return false;
	}
	return false;
}

// ---------------------------------------------------------------------------
// Session lookup
// ---------------------------------------------------------------------------

export interface RegistryLike {
	list(): Array<{
		id: string;
		kind: "main" | "sub" | "advisor";
		parentId?: string;
		session: unknown;
	}>;
}

function hasSessionManager(value: unknown): value is LiveSession {
	if (typeof value !== "object" || value === null) return false;
	return "sessionManager" in value && "settings" in value && "agent" in value;
}

/**
 * Find the live session whose `sessionManager` is the one handed to this handler.
 *
 * Identity comparison, not name matching: a subagent and its parent both have
 * extension instances in one process, and only reference equality proves which
 * session a given `tool_call` belongs to.
 */
export function resolveAgentIdentity(registry: RegistryLike, sessionManager: unknown): ResolvedAgentIdentity {
	for (const ref of registry.list()) {
		const session = ref.session;
		if (!hasSessionManager(session)) continue;
		if (session.sessionManager !== sessionManager) continue;
		return {
			agentId: ref.id,
			agentKind: ref.kind,
			...(ref.parentId === undefined ? {} : { parentAgentId: ref.parentId }),
			session,
		};
	}
	return { agentId: "unknown", agentKind: "unknown" };
}

// ---------------------------------------------------------------------------
// Approval classification
// ---------------------------------------------------------------------------

const APPROVAL_MODES = new Set<ApprovalMode>(["always-ask", "write", "yolo"]);

export interface ClassifyInput {
	session: LiveSession | undefined;
	toolName: string;
	args: unknown;
	/** True when argv or the retroactive latch proved the host auto-approves. */
	hostAutoApprove: boolean;
}

/**
 * Reconstruct OMP's native approval decision for this exact call.
 *
 * Uses OMP's own exported `resolveApproval`, so argument-dependent tiers (the
 * `read` tool's `ssh://` escalation, `write`'s `xd://` device dispatch, `bash`'s
 * pattern table) resolve exactly as the real gate will resolve them.
 */
export function classifyHostApproval(input: ClassifyInput): HostApproval {
	const { session } = input;
	if (!session) {
		return {
			branch: "unsupported",
			reason:
				"Smart Approve could not match this tool call to a live OMP session, so it cannot prove " +
				"whether OMP would approve it. Supported hosts are OMP 17.2.x CLI, TUI, and RPC sessions.",
		};
	}

	const tool = session.agent.state.tools.find(candidate => candidate.name === input.toolName);
	if (!tool) {
		return {
			branch: "unsupported",
			reason: `Tool "${input.toolName}" is not present in the live session's tool set, so its approval tier cannot be resolved.`,
		};
	}

	const configured = session.settings.get("tools.approvalMode");
	// OMP itself falls back to "yolo" when the setting is absent, so mirroring
	// that is the accurate reconstruction — not a permissive guess.
	const configuredMode: ApprovalMode = APPROVAL_MODES.has(configured as ApprovalMode)
		? (configured as ApprovalMode)
		: "yolo";
	const mode: ApprovalMode = input.hostAutoApprove ? "yolo" : configuredMode;

	const rawPolicies = session.settings.get("tools.approval");
	const userPolicies =
		typeof rawPolicies === "object" && rawPolicies !== null ? (rawPolicies as Record<string, unknown>) : {};

	let resolved: { policy: "allow" | "deny" | "prompt"; tier: ToolTier; reason?: string };
	try {
		resolved = resolveApproval(tool as Parameters<typeof resolveApproval>[0], input.args, mode, userPolicies);
	} catch (error) {
		return {
			branch: "unsupported",
			reason: `OMP's approval resolver rejected this call (${error instanceof Error ? error.message : String(error)}), so its native decision cannot be proven.`,
		};
	}

	const detail = `mode=${mode}${input.hostAutoApprove && configuredMode !== "yolo" ? " (host auto-approve detected)" : ""}, tier=${resolved.tier}`;

	if (resolved.policy === "deny") {
		return {
			branch: "deny",
			policy: "deny",
			tier: resolved.tier,
			mode,
			reason: `OMP denies this call by policy (${detail}). Smart Approve preserves the denial.`,
		};
	}
	if (resolved.policy === "prompt") {
		return {
			branch: "prompt",
			policy: "prompt",
			tier: resolved.tier,
			mode,
			reason: `OMP will ask the human to approve this call (${detail}).`,
		};
	}
	return {
		branch: "auto",
		policy: "allow",
		tier: resolved.tier,
		mode,
		reason: `OMP would run this call without asking (${detail}).`,
	};
}

/** Argument-dependent tier, resolved by OMP's own logic. Undefined when unresolvable. */
export function resolveTier(session: LiveSession | undefined, toolName: string, args: unknown): ToolTier | undefined {
	const tool = session?.agent.state.tools.find(candidate => candidate.name === toolName);
	if (!tool) return undefined;
	try {
		return resolveToolTier(tool as Parameters<typeof resolveToolTier>[0], args);
	} catch {
		return undefined;
	}
}

// ---------------------------------------------------------------------------
// Auto-approve detection
// ---------------------------------------------------------------------------

/**
 * Tracks whether this host auto-approves despite its configured approval mode.
 *
 * Starts from the argv scan and latches on the first proof from execution
 * ordering. Once latched it never clears for the life of the session: a host
 * that auto-approved one call will auto-approve the next, and un-latching would
 * reopen the hole.
 */
export class AutoApproveDetector {
	#latched: boolean;
	#reason: string;
	/** Calls we classified as `prompt` and are waiting to see approval requested for. */
	readonly #awaitingPrompt = new Map<string, string>();
	readonly #approvalRequested = new Set<string>();

	constructor(argv: readonly string[] = process.argv) {
		this.#latched = argvRequestsAutoApprove(argv);
		this.#reason = this.#latched ? "--auto-approve/--yolo present in process argv" : "";
	}

	get active(): boolean {
		return this.#latched;
	}

	get reason(): string {
		return this.#reason;
	}

	/** Called after classifying a call as the prompt branch. */
	expectPrompt(toolCallId: string, toolName: string): void {
		if (this.#latched) return;
		this.#awaitingPrompt.set(toolCallId, toolName);
	}

	/** OMP emitted `tool_approval_requested`: the prompt branch was accurate. */
	noteApprovalRequested(toolCallId: string): void {
		this.#approvalRequested.add(toolCallId);
		this.#awaitingPrompt.delete(toolCallId);
	}

	/**
	 * OMP began executing a call. If we predicted a prompt and none was requested,
	 * the host is auto-approving regardless of `tools.approvalMode`.
	 *
	 * Returns true when this observation latched the detector.
	 */
	noteExecutionStarted(toolCallId: string): boolean {
		const toolName = this.#awaitingPrompt.get(toolCallId);
		this.#awaitingPrompt.delete(toolCallId);
		if (this.#latched || toolName === undefined) return false;
		if (this.#approvalRequested.has(toolCallId)) return false;
		this.#latched = true;
		this.#reason =
			`OMP executed "${toolName}" without requesting approval even though tools.approvalMode implied a prompt. ` +
			`The host is auto-approving (embedded SDK autoApprove, or an equivalent override). ` +
			`Smart Approve now applies the full gate to every call in this session.`;
		return true;
	}

	/** Drop bookkeeping for a call that never executed. */
	forget(toolCallId: string): void {
		this.#awaitingPrompt.delete(toolCallId);
		this.#approvalRequested.delete(toolCallId);
	}

	/** Test seam: force the latch without waiting for an observation. */
	latchForTest(reason: string): void {
		this.#latched = true;
		this.#reason = reason;
	}
}

/** The process-global registry, wrapped so tests can inject a fake. */
export function globalRegistry(): RegistryLike {
	return AgentRegistry.global();
}
