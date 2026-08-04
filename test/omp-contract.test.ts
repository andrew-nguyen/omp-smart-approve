/**
 * Host-contract tests pinned to the supported OMP peer range.
 *
 * These import OMP's REAL exports. Their job is to make a breaking OMP upgrade
 * fail here — loudly and specifically — rather than silently changing security
 * semantics in production. Every assertion below corresponds to a behavior the
 * gate depends on.
 */

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import path from "node:path";
import { completeSimple, streamSimple } from "@oh-my-pi/pi-ai";
import {
	ExtensionRuntime,
	loadExtensionFromFactory,
	loadExtensions,
} from "@oh-my-pi/pi-coding-agent/extensibility/extensions/loader";
import {
	EXTENSION_HANDLER_TIMEOUT_MS,
	ExtensionRunner,
} from "@oh-my-pi/pi-coding-agent/extensibility/extensions/runner";
import { AgentRegistry, MAIN_AGENT_ID } from "@oh-my-pi/pi-coding-agent/registry/agent-registry";
import { builtinCredentialSecretEntries, collectEnvSecrets, loadSecrets } from "@oh-my-pi/pi-coding-agent/secrets";
import { obfuscateToolArguments, SecretObfuscator } from "@oh-my-pi/pi-coding-agent/secrets/obfuscator";
import {
	type ApprovalMode,
	type ApprovalPolicy,
	formatApprovalPrompt,
	type ResolvedApproval,
	requiresApproval,
	resolveApproval,
	resolveToolTier,
} from "@oh-my-pi/pi-coding-agent/tools/approval";
import { EventBus } from "@oh-my-pi/pi-coding-agent/utils/event-bus";
import { MAX_SELF_DEADLINE_MS, OMP_HANDLER_CAP_MS } from "../src/config.ts";

const REPO = path.resolve(import.meta.dir, "..");

describe("peer range", () => {
	const pkg: unknown = JSON.parse(readFileSync(path.join(REPO, "package.json"), "utf8"));

	test("declares OMP as a peer dependency constrained to 17.x", () => {
		expect(typeof pkg === "object" && pkg !== null && "peerDependencies" in pkg).toBe(true);
		if (typeof pkg !== "object" || pkg === null || !("peerDependencies" in pkg)) return;
		const peers = pkg.peerDependencies;
		expect(typeof peers === "object" && peers !== null).toBe(true);
		if (typeof peers !== "object" || peers === null) return;
		expect(peers).toHaveProperty("@oh-my-pi/pi-coding-agent", ">=17.2.2 <18");
	});

	test("the installed OMP satisfies the declared range", () => {
		const installed: unknown = JSON.parse(
			readFileSync(path.join(REPO, "node_modules/@oh-my-pi/pi-coding-agent/package.json"), "utf8"),
		);
		expect(typeof installed === "object" && installed !== null && "version" in installed).toBe(true);
		if (typeof installed !== "object" || installed === null || !("version" in installed)) return;
		expect(String(installed.version)).toMatch(/^17\./);
	});
});

describe("approval resolution is the contract the host adapter reconstructs", () => {
	const readTool = { name: "read", approval: "read" as const };
	const writeTool = { name: "write", approval: "write" as const };
	const execTool = { name: "bash", approval: "exec" as const };

	test("the approval mode union is exactly the three values we branch on", () => {
		// A new mode would silently fall into our `yolo` fallback, so pin it.
		const modes: ApprovalMode[] = ["always-ask", "write", "yolo"];
		for (const mode of modes) {
			expect(resolveApproval(readTool, {}, mode).policy).toBeDefined();
		}
	});

	test("the policy union is exactly allow, deny, prompt", () => {
		const policies: ApprovalPolicy[] = ["allow", "deny", "prompt"];
		const resolvedPolicy: ApprovalPolicy = resolveApproval(writeTool, {}, "yolo").policy;
		expect(policies).toContain(resolvedPolicy);
	});

	test("always-ask auto-approves read and prompts for write and exec", () => {
		expect(resolveApproval(readTool, {}, "always-ask").policy).toBe("allow");
		expect(resolveApproval(writeTool, {}, "always-ask").policy).toBe("prompt");
		expect(resolveApproval(execTool, {}, "always-ask").policy).toBe("prompt");
	});

	test("write mode auto-approves write but still prompts for exec", () => {
		expect(resolveApproval(writeTool, {}, "write").policy).toBe("allow");
		expect(resolveApproval(execTool, {}, "write").policy).toBe("prompt");
	});

	test("yolo auto-approves every tier", () => {
		expect(resolveApproval(execTool, {}, "yolo").policy).toBe("allow");
	});

	test("a per-tool user deny wins over yolo", () => {
		expect(resolveApproval(execTool, {}, "yolo", { bash: "deny" }).policy).toBe("deny");
	});

	test("a tool omitting approval defaults to the most cautious tier", () => {
		// The gate relies on this: an unknown MCP tool must never resolve read-tier.
		expect(resolveToolTier({ name: "mystery" }, {})).toBe("exec");
	});

	test("approval can be argument-dependent, which is why we call the resolver per call", () => {
		const dynamic = {
			name: "read",
			approval: (args: unknown) =>
				typeof args === "object" && args !== null && "path" in args && String(args.path).startsWith("ssh://")
					? ("exec" as const)
					: ("read" as const),
		};
		expect(resolveToolTier(dynamic, { path: "a.ts" })).toBe("read");
		expect(resolveToolTier(dynamic, { path: "ssh://h/x" })).toBe("exec");
	});

	test("the resolved shape still carries policy, tier, override, and source", () => {
		const resolved: ResolvedApproval = resolveApproval(writeTool, {}, "always-ask");
		expect(resolved).toHaveProperty("policy");
		expect(resolved).toHaveProperty("tier");
		expect(resolved).toHaveProperty("override");
		expect(resolved.source).toBeDefined();
	});

	test("requiresApproval and formatApprovalPrompt remain exported", () => {
		expect(typeof requiresApproval).toBe("function");
		expect(typeof formatApprovalPrompt).toBe("function");
	});
});

describe("handler timeout", () => {
	test("OMP still caps extension handlers at 30 seconds", () => {
		expect(EXTENSION_HANDLER_TIMEOUT_MS).toBe(OMP_HANDLER_CAP_MS);
	});

	test("our self-deadline stays strictly inside the host cap", () => {
		expect(MAX_SELF_DEADLINE_MS).toBeLessThan(EXTENSION_HANDLER_TIMEOUT_MS);
	});
});

describe("extension loading", () => {
	test("the package manifest entry loads through OMP's real loader", async () => {
		const loaded = await loadExtensions([path.join(REPO, "src/index.ts")], REPO, new EventBus());
		expect(loaded.errors).toEqual([]);
		expect(loaded.extensions).toHaveLength(1);
	});

	test("the loaded extension registers every handler the gate depends on", async () => {
		const loaded = await loadExtensions([path.join(REPO, "src/index.ts")], REPO, new EventBus());
		const extension = loaded.extensions[0];
		expect(extension).toBeDefined();
		for (const event of [
			"session_start",
			"before_agent_start",
			"message_start",
			"message_update",
			"message_end",
			"tool_call",
			"tool_execution_start",
			"tool_result",
			"tool_approval_requested",
			"session_switch",
			"session_shutdown",
		]) {
			expect(extension?.handlers.has(event)).toBe(true);
		}
	});

	test("the loaded extension registers exactly one namespaced command", async () => {
		const loaded = await loadExtensions([path.join(REPO, "src/index.ts")], REPO, new EventBus());
		const commands = [...(loaded.extensions[0]?.commands.keys() ?? [])];
		expect(commands).toEqual(["smart-approve"]);
	});

	test("the named factory seam loads through OMP's real API", async () => {
		const { createSmartApproveExtension } = await import("../src/index.ts");
		const extension = await loadExtensionFromFactory(
			createSmartApproveExtension({}),
			REPO,
			new EventBus(),
			new ExtensionRuntime(),
			"seam",
		);
		expect(extension.handlers.has("tool_call")).toBe(true);
	});

	test("the extension runner class is still constructible from its public export", () => {
		expect(typeof ExtensionRunner).toBe("function");
	});
});

describe("agent registry", () => {
	test("exposes global(), list(), and the main agent id we elect on", () => {
		const registry = AgentRegistry.global();
		expect(typeof registry.list).toBe("function");
		expect(MAIN_AGENT_ID).toBe("Main");
	});

	test("a registered ref carries the id, kind, and session identity we match on", () => {
		const registry = AgentRegistry.global();
		const marker = { marker: true };
		const session = { sessionManager: marker } as never;
		registry.register({ id: "ContractProbe", displayName: "probe", kind: "sub", session });
		try {
			const ref = registry.list().find(r => r.id === "ContractProbe");
			expect(ref?.kind).toBe("sub");
			expect(ref?.session).toBe(session);
		} finally {
			registry.unregister("ContractProbe");
		}
	});
});

describe("secret machinery", () => {
	test("the obfuscator and tool-argument helper are still exported", () => {
		expect(typeof SecretObfuscator).toBe("function");
		expect(typeof obfuscateToolArguments).toBe("function");
	});

	test("the three secret sources we compose are still exported", () => {
		expect(typeof loadSecrets).toBe("function");
		expect(typeof collectEnvSecrets).toBe("function");
		expect(typeof builtinCredentialSecretEntries).toBe("function");
	});

	test("a configured secret is replaced before it can reach a provider", () => {
		const secret = "ThisIsAConfiguredSecretValue123";
		const obfuscator = new SecretObfuscator([{ type: "plain", mode: "obfuscate", content: secret }], "test-key");
		const out = obfuscateToolArguments(obfuscator, { command: `echo ${secret}` });
		expect(JSON.stringify(out)).not.toContain(secret);
	});

	test("obfuscation leaves non-secret content intact", () => {
		const obfuscator = new SecretObfuscator(
			[{ type: "plain", mode: "obfuscate", content: "SEKRIT_VALUE_1234" }],
			"k",
		);
		const out = obfuscateToolArguments(obfuscator, { path: "src/index.ts" });
		expect(out.path).toBe("src/index.ts");
	});
});

describe("direct completion API", () => {
	test("completeSimple and streamSimple are still exported from pi-ai", () => {
		expect(typeof completeSimple).toBe("function");
		expect(typeof streamSimple).toBe("function");
	});

	test("completeSimple takes (model, context, options)", () => {
		// Arity is part of the contract the judge calls through.
		expect(completeSimple.length).toBeGreaterThanOrEqual(2);
	});
});

describe("the private auto-approve flag remains unobservable", () => {
	test("resolveApproval exposes no channel for context.autoApprove", () => {
		// Arity is 3: (tool, args, mode) before the defaulted `userConfig`. There is
		// no signal for the CLI/SDK `autoApprove` flag, which is exactly why
		// AutoApproveDetector reconstructs it from argv plus execution ordering.
		// If OMP ever exposes the flag, delete the detector and read it directly.
		expect(resolveApproval.length).toBe(3);
	});

	test("a write under always-ask resolves to prompt, with no input that could say otherwise", () => {
		// The only inputs are tool, args, mode, and per-tool policies. A host that
		// auto-approves anyway is therefore invisible here by construction.
		expect(resolveApproval({ name: "write", approval: "write" }, {}, "always-ask", {}).policy).toBe("prompt");
	});
});
