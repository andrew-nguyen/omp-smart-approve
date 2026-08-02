import { describe, expect, test } from "bun:test";
import {
	AutoApproveDetector,
	argvRequestsAutoApprove,
	classifyHostApproval,
	type LiveSession,
	type RegistryLike,
	resolveAgentIdentity,
	resolveTier,
} from "../src/host.ts";

/**
 * Minimal stand-ins shaped like the real OMP objects. `resolveApproval` is the
 * genuine exported OMP function, so these tests exercise real host semantics
 * rather than a reimplementation of them.
 */
function makeSession(options: {
	approvalMode?: string;
	toolPolicies?: Record<string, unknown>;
	tools?: Array<{ name: string; approval?: unknown }>;
	sessionManager?: unknown;
}): LiveSession {
	const settings = new Map<string, unknown>();
	if (options.approvalMode !== undefined) settings.set("tools.approvalMode", options.approvalMode);
	if (options.toolPolicies !== undefined) settings.set("tools.approval", options.toolPolicies);
	return {
		settings: { get: key => settings.get(key) },
		agent: { state: { tools: options.tools ?? [] } },
		sessionManager: options.sessionManager ?? {},
	};
}

const READ_TOOL = { name: "read", approval: "read" };
const WRITE_TOOL = { name: "write", approval: "write" };
const BASH_TOOL = { name: "bash", approval: "exec" };
/** Argument-dependent tier, exactly like OMP's real read tool. */
const SSH_AWARE_READ = {
	name: "read",
	approval: (args: unknown) =>
		typeof args === "object" && args !== null && "path" in args && String(args.path).startsWith("ssh://")
			? "exec"
			: "read",
};

describe("approval mode reconstruction", () => {
	test("always-ask auto-approves a read", () => {
		const session = makeSession({ approvalMode: "always-ask", tools: [READ_TOOL] });
		const out = classifyHostApproval({ session, toolName: "read", args: { path: "a.ts" }, hostAutoApprove: false });
		expect(out.branch).toBe("auto");
		expect(out.tier).toBe("read");
	});

	test("always-ask prompts for a write", () => {
		const session = makeSession({ approvalMode: "always-ask", tools: [WRITE_TOOL] });
		const out = classifyHostApproval({
			session,
			toolName: "write",
			args: { path: "a.ts" },
			hostAutoApprove: false,
		});
		expect(out.branch).toBe("prompt");
	});

	test("always-ask prompts for an exec", () => {
		const session = makeSession({ approvalMode: "always-ask", tools: [BASH_TOOL] });
		expect(
			classifyHostApproval({ session, toolName: "bash", args: { command: "ls" }, hostAutoApprove: false }).branch,
		).toBe("prompt");
	});

	test("write mode auto-approves a write but prompts for an exec", () => {
		const session = makeSession({ approvalMode: "write", tools: [WRITE_TOOL, BASH_TOOL] });
		expect(
			classifyHostApproval({ session, toolName: "write", args: { path: "a.ts" }, hostAutoApprove: false }).branch,
		).toBe("auto");
		expect(
			classifyHostApproval({ session, toolName: "bash", args: { command: "ls" }, hostAutoApprove: false }).branch,
		).toBe("prompt");
	});

	test("yolo auto-approves every tier", () => {
		const session = makeSession({ approvalMode: "yolo", tools: [BASH_TOOL] });
		expect(
			classifyHostApproval({ session, toolName: "bash", args: { command: "rm -rf /" }, hostAutoApprove: false })
				.branch,
		).toBe("auto");
	});

	test("an absent approvalMode mirrors OMP's own yolo fallback rather than guessing stricter", () => {
		const session = makeSession({ tools: [BASH_TOOL] });
		const out = classifyHostApproval({ session, toolName: "bash", args: {}, hostAutoApprove: false });
		expect(out.mode).toBe("yolo");
		expect(out.branch).toBe("auto");
	});

	test("an invalid approvalMode value falls back to OMP's default", () => {
		const session = makeSession({ approvalMode: "nonsense", tools: [READ_TOOL] });
		expect(classifyHostApproval({ session, toolName: "read", args: {}, hostAutoApprove: false }).mode).toBe("yolo");
	});
});

describe("per-tool user policies", () => {
	test("a per-tool deny is surfaced as the deny branch", () => {
		const session = makeSession({ approvalMode: "yolo", toolPolicies: { bash: "deny" }, tools: [BASH_TOOL] });
		const out = classifyHostApproval({ session, toolName: "bash", args: {}, hostAutoApprove: false });
		expect(out.branch).toBe("deny");
	});

	test("a per-tool prompt overrides an otherwise auto-approving mode", () => {
		const session = makeSession({ approvalMode: "yolo", toolPolicies: { write: "prompt" }, tools: [WRITE_TOOL] });
		expect(classifyHostApproval({ session, toolName: "write", args: {}, hostAutoApprove: false }).branch).toBe(
			"prompt",
		);
	});

	test("a per-tool allow auto-approves under a strict mode", () => {
		const session = makeSession({
			approvalMode: "always-ask",
			toolPolicies: { bash: "allow" },
			tools: [BASH_TOOL],
		});
		expect(classifyHostApproval({ session, toolName: "bash", args: {}, hostAutoApprove: false }).branch).toBe(
			"auto",
		);
	});
});

describe("argument-aware tiers", () => {
	test("a local read resolves to read tier", () => {
		const session = makeSession({ approvalMode: "always-ask", tools: [SSH_AWARE_READ] });
		const out = classifyHostApproval({ session, toolName: "read", args: { path: "a.ts" }, hostAutoApprove: false });
		expect(out.tier).toBe("read");
		expect(out.branch).toBe("auto");
	});

	test("the same tool with an ssh path resolves to exec tier and prompts", () => {
		const session = makeSession({ approvalMode: "always-ask", tools: [SSH_AWARE_READ] });
		const out = classifyHostApproval({
			session,
			toolName: "read",
			args: { path: "ssh://host/etc/passwd" },
			hostAutoApprove: false,
		});
		expect(out.tier).toBe("exec");
		expect(out.branch).toBe("prompt");
	});

	test("resolveTier runs the tool's own argument-dependent logic", () => {
		const session = makeSession({ tools: [SSH_AWARE_READ] });
		expect(resolveTier(session, "read", { path: "a.ts" })).toBe("read");
		expect(resolveTier(session, "read", { path: "ssh://h/x" })).toBe("exec");
	});

	test("resolveTier returns undefined for an unknown tool rather than guessing", () => {
		expect(resolveTier(makeSession({ tools: [] }), "ghost", {})).toBeUndefined();
	});

	test("an MCP tool with no declared approval resolves to the most cautious tier", () => {
		const session = makeSession({ approvalMode: "always-ask", tools: [{ name: "mcp__x_y" }] });
		const out = classifyHostApproval({ session, toolName: "mcp__x_y", args: {}, hostAutoApprove: false });
		// OMP defaults an omitted approval to exec.
		expect(out.tier).toBe("exec");
		expect(out.branch).toBe("prompt");
	});
});

describe("fail-closed host resolution", () => {
	test("a missing session is unsupported, never auto", () => {
		const out = classifyHostApproval({ session: undefined, toolName: "read", args: {}, hostAutoApprove: false });
		expect(out.branch).toBe("unsupported");
		expect(out.reason).toContain("could not match this tool call to a live OMP session");
	});

	test("a tool absent from the live tool set is unsupported", () => {
		const session = makeSession({ approvalMode: "yolo", tools: [READ_TOOL] });
		const out = classifyHostApproval({ session, toolName: "ghost", args: {}, hostAutoApprove: false });
		expect(out.branch).toBe("unsupported");
	});

	test("a throwing approval resolver is unsupported, not allowed", () => {
		const session = makeSession({
			approvalMode: "yolo",
			tools: [
				{
					name: "boom",
					approval: () => {
						throw new Error("resolver exploded");
					},
				},
			],
		});
		const out = classifyHostApproval({ session, toolName: "boom", args: {}, hostAutoApprove: false });
		expect(out.branch).toBe("unsupported");
		expect(out.reason).toContain("resolver exploded");
	});

	test("no classification path ever returns allow for unresolved state", () => {
		const unresolved = [
			classifyHostApproval({ session: undefined, toolName: "x", args: {}, hostAutoApprove: false }),
			classifyHostApproval({
				session: makeSession({ tools: [] }),
				toolName: "x",
				args: {},
				hostAutoApprove: false,
			}),
		];
		for (const out of unresolved) {
			expect(out.branch).toBe("unsupported");
			expect(out.policy).toBeUndefined();
		}
	});
});

describe("session identity resolution", () => {
	test("matches the session by sessionManager identity, not by name", () => {
		const managerA = { id: "a" };
		const managerB = { id: "b" };
		const registry: RegistryLike = {
			list: () => [
				{ id: "Main", kind: "main", session: makeSession({ sessionManager: managerA }) },
				{ id: "Sub1", kind: "sub", parentId: "Main", session: makeSession({ sessionManager: managerB }) },
			],
		};
		expect(resolveAgentIdentity(registry, managerB).agentId).toBe("Sub1");
		expect(resolveAgentIdentity(registry, managerB).parentAgentId).toBe("Main");
		expect(resolveAgentIdentity(registry, managerA).agentKind).toBe("main");
	});

	test("an unmatched session manager yields an unknown identity, never a wrong one", () => {
		const registry: RegistryLike = {
			list: () => [{ id: "Main", kind: "main", session: makeSession({ sessionManager: {} }) }],
		};
		const out = resolveAgentIdentity(registry, { id: "orphan" });
		expect(out.agentId).toBe("unknown");
		expect(out.session).toBeUndefined();
	});

	test("a parked ref with a null session is skipped", () => {
		const manager = {};
		const registry: RegistryLike = {
			list: () => [
				{ id: "Parked", kind: "sub", session: null },
				{ id: "Main", kind: "main", session: makeSession({ sessionManager: manager }) },
			],
		};
		expect(resolveAgentIdentity(registry, manager).agentId).toBe("Main");
	});
});

describe("auto-approve detection closes the private-flag gap", () => {
	test("argv scan detects --auto-approve", () => {
		expect(argvRequestsAutoApprove(["bun", "omp", "--auto-approve"])).toBe(true);
	});

	test("argv scan detects --yolo", () => {
		expect(argvRequestsAutoApprove(["bun", "omp", "--yolo"])).toBe(true);
	});

	test("argv scan ignores the flag after a -- separator, where it is prompt text", () => {
		expect(argvRequestsAutoApprove(["omp", "--", "explain", "--yolo"])).toBe(false);
	});

	test("argv scan is false for an ordinary invocation", () => {
		expect(argvRequestsAutoApprove(["bun", "omp", "--model", "x"])).toBe(false);
	});

	test("a session started with --auto-approve is classified auto even though settings say always-ask", () => {
		const session = makeSession({ approvalMode: "always-ask", tools: [BASH_TOOL] });
		const detector = new AutoApproveDetector(["omp", "--auto-approve"]);
		expect(detector.active).toBe(true);
		const out = classifyHostApproval({
			session,
			toolName: "bash",
			args: { command: "rm -rf /" },
			hostAutoApprove: detector.active,
		});
		// Without the argv signal this would be `prompt`, and Smart Approve would
		// only pre-screen a call OMP is about to run silently.
		expect(out.branch).toBe("auto");
		expect(out.reason).toContain("host auto-approve detected");
	});

	test("execution without an approval request latches the detector", () => {
		const detector = new AutoApproveDetector([]);
		expect(detector.active).toBe(false);
		detector.expectPrompt("call-1", "write");
		expect(detector.noteExecutionStarted("call-1")).toBe(true);
		expect(detector.active).toBe(true);
		expect(detector.reason).toContain("without requesting approval");
	});

	test("execution after a genuine approval request does not latch", () => {
		const detector = new AutoApproveDetector([]);
		detector.expectPrompt("call-1", "write");
		detector.noteApprovalRequested("call-1");
		expect(detector.noteExecutionStarted("call-1")).toBe(false);
		expect(detector.active).toBe(false);
	});

	test("execution of a call we never predicted would prompt does not latch", () => {
		const detector = new AutoApproveDetector([]);
		expect(detector.noteExecutionStarted("unseen")).toBe(false);
		expect(detector.active).toBe(false);
	});

	test("once latched it never clears, since a host that auto-approved once will again", () => {
		const detector = new AutoApproveDetector([]);
		detector.expectPrompt("call-1", "write");
		detector.noteExecutionStarted("call-1");
		detector.expectPrompt("call-2", "write");
		detector.noteApprovalRequested("call-2");
		detector.noteExecutionStarted("call-2");
		expect(detector.active).toBe(true);
	});

	test("a blocked call that never executes is forgotten without latching", () => {
		const detector = new AutoApproveDetector([]);
		detector.expectPrompt("call-1", "write");
		detector.forget("call-1");
		expect(detector.noteExecutionStarted("call-1")).toBe(false);
		expect(detector.active).toBe(false);
	});
});
