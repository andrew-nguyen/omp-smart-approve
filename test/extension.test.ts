/**
 * Extension lifecycle, event ordering, and failure containment.
 *
 * Loaded through OMP's real `loadExtensionFromFactory`, so `api.on(...)` and
 * `api.registerCommand(...)` run against OMP's own API implementation. Only the
 * provider, the terminal, and the clock are scripted.
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { ExtensionRuntime, loadExtensionFromFactory } from "@oh-my-pi/pi-coding-agent/extensibility/extensions/loader";
import type {
	Extension,
	ExtensionCommandContext,
	ExtensionContext,
} from "@oh-my-pi/pi-coding-agent/extensibility/extensions/types";
import { AgentRegistry, MAIN_AGENT_ID } from "@oh-my-pi/pi-coding-agent/registry/agent-registry";
import { EventBus } from "@oh-my-pi/pi-coding-agent/utils/event-bus";
import { resetBrokerForTests } from "../src/broker.ts";
import { type DiscoveryPaths, resolveConfig } from "../src/config.ts";
import type { JudgeResult } from "../src/contracts.ts";
import { createSmartApproveExtension } from "../src/index.ts";
import type { openStore } from "../src/store.ts";

let home: string;
let cwd: string;
let agentDir: string;
let clock: number;
let counter: number;

function nextSeq(): number {
	counter += 1;
	return counter;
}

beforeEach(() => {
	home = mkdtempSync(path.join(tmpdir(), "sa-ext-home-"));
	cwd = mkdtempSync(path.join(tmpdir(), "sa-ext-cwd-"));
	agentDir = path.join(home, ".omp", "agent");
	clock = 1_700_000_000_000;
	counter = 0;
	resetBrokerForTests();
});

afterEach(() => {
	rmSync(home, { recursive: true, force: true });
	rmSync(cwd, { recursive: true, force: true });
	resetBrokerForTests();
	AgentRegistry.global().unregister(MAIN_AGENT_ID);
});

interface Recorder {
	widgets: Map<string, unknown>;
	statuses: Map<string, string | undefined>;
	notices: string[];
	selectAnswer: string | undefined;
	selectCalls: number;
	/** Answer for every `ui.confirm`. Default `false` keeps dialogs declining. */
	confirmAnswer: boolean;
	/** Authenticated models the session exposes; default none. */
	models: Array<{ id: string; provider: string }>;
	entries: Array<{ type: string; data: unknown }>;
}

function makeCtx(recorder: Recorder, hasUI: boolean): ExtensionContext {
	return {
		hasUI,
		cwd,
		ui: {
			select: async () => {
				recorder.selectCalls += 1;
				return hasUI ? recorder.selectAnswer : undefined;
			},
			confirm: async () => recorder.confirmAnswer,
			input: async () => undefined,
			notify: (message: string) => recorder.notices.push(message),
			setStatus: (key: string, text: string | undefined) => recorder.statuses.set(key, text),
			setWidget: (key: string, content: unknown) => recorder.widgets.set(key, content),
			theme: {},
		},
		sessionManager: {
			getCwd: () => cwd,
			getSessionId: () => "ext-test",
			getSessionDir: () => agentDir,
			getEntries: () => [],
		},
		modelRegistry: { hasConfiguredAuth: () => false, getApiKey: async () => "" },
		model: undefined,
		models: {
			list: () => recorder.models,
			current: () => undefined,
			resolve: () => undefined,
			family: (model: { provider: string }) => model.provider,
		},
		setInterval: () => 0 as unknown as Timer,
		setTimeout: () => 0 as unknown as Timer,
		clearTimer: () => {},
		isIdle: () => true,
		abort: () => {},
		hasPendingMessages: () => false,
		shutdown: () => {},
		getSystemPrompt: () => [],
		getContextUsage: () => undefined,
		getAsyncJobSnapshot: () => null,
		compact: async () => {},
	} as unknown as ExtensionContext;
}

function registerSession(ctx: ExtensionContext, approvalMode = "yolo"): void {
	const settings = new Map<string, unknown>([["tools.approvalMode", approvalMode]]);
	AgentRegistry.global().register({
		id: MAIN_AGENT_ID,
		displayName: "Main",
		kind: "main",
		session: {
			// Without this the extension falls back to `${HOME}/.omp/agent` and the
			// suite reads — and, once a command writes config, overwrites — the
			// developer's real installation.
			settings: { get: (key: string) => settings.get(key), getAgentDir: () => agentDir },
			agent: {
				state: {
					tools: [
						{ name: "write", approval: "write" },
						{ name: "read", approval: "read" },
						{ name: "bash", approval: "exec" },
					],
					messages: [],
				},
			},
			sessionManager: ctx.sessionManager,
		} as never,
	});
}

const ALLOW: JudgeResult = {
	ok: true,
	verdict: { decision: "allow", risk: "uncertain", rationale: "routine" },
	metrics: { attempts: 1, latencyMs: 5, overTarget: false },
};
const BLOCK: JudgeResult = {
	ok: true,
	verdict: { decision: "block", risk: "destructive-action", rationale: "irreversible" },
	metrics: { attempts: 1, latencyMs: 5, overTarget: false },
};

interface Built {
	extension: Extension;
	ctx: ExtensionContext;
	recorder: Recorder;
	dbPath: string;
}

async function build(
	options: {
		judge?: () => JudgeResult;
		hasUI?: boolean;
		approvalMode?: string;
		openStoreOverride?: typeof openStore;
		resolveOverride?: () => never;
		skipSessionStart?: boolean;
		selectAnswer?: string;
		confirmAnswer?: boolean;
		models?: Array<{ id: string; provider: string }>;
		/** Resolve configuration from disk, so a mid-session write is observable. */
		realConfig?: boolean;
	} = {},
): Promise<Built> {
	const recorder: Recorder = {
		widgets: new Map(),
		statuses: new Map(),
		notices: [],
		selectAnswer: options.selectAnswer,
		selectCalls: 0,
		confirmAnswer: options.confirmAnswer ?? false,
		models: options.models ?? [],
		entries: [],
	};
	const ctx = makeCtx(recorder, options.hasUI ?? true);
	registerSession(ctx, options.approvalMode);
	const dbPath = path.join(agentDir, "smart-approve", `s-${nextSeq()}.sqlite`);
	const paths: DiscoveryPaths = { cwd, agentDir, home };

	const scriptedConfiguration =
		options.resolveOverride ??
		(() =>
			resolveConfig(
				[
					{
						scope: "user",
						filePath: path.join(agentDir, "smart-approve.yml"),
						rawContent: "{}",
						data: {
							judge: { authorizedModels: ["anthropic/scripted"] },
							audit: { databasePath: dbPath },
						},
					},
				],
				[],
				paths,
			));

	const factory = createSmartApproveExtension({
		now: () => clock,
		randomId: () => `audit-${nextSeq()}`,
		randomNonce: () => `nonce-${nextSeq()}`,
		...(options.realConfig === true ? {} : { resolveConfiguration: scriptedConfiguration }),
		judge: async () => (options.judge ?? (() => ALLOW))(),
		redactor: {
			redactArguments: args => structuredClone(args),
			redactText: text => text,
			hasSecrets: () => false,
		},
		argv: [],
		...(options.openStoreOverride ? { openStore: options.openStoreOverride } : {}),
	});

	const extension = await loadExtensionFromFactory(factory, cwd, new EventBus(), new ExtensionRuntime(), "ext-test");
	if (!options.skipSessionStart) {
		await fire(extension, "session_start", { type: "session_start" }, ctx);
	}
	return { extension, ctx, recorder, dbPath };
}

async function runCommand(built: Built, args: string): Promise<void> {
	const command = built.extension.commands.get("smart-approve");
	if (command === undefined) throw new Error("smart-approve command is not registered");
	// `ExtensionCommandContext` adds session-tree operations (branch, newSession,
	// navigateTree, …) that this command never calls; the scripted context covers
	// every member it does touch.
	const commandCtx = built.ctx as unknown as ExtensionCommandContext;
	await command.handler(args, commandCtx);
}

async function fire(extension: Extension, event: string, payload: object, ctx: ExtensionContext): Promise<unknown> {
	let last: unknown;
	for (const handler of extension.handlers.get(event) ?? []) {
		last = await handler(payload as never, ctx);
	}
	return last;
}

async function toolCall(
	built: Built,
	toolCallId: string,
	toolName: string,
	input: Record<string, unknown>,
): Promise<{ block?: boolean; reason?: string } | undefined> {
	for (const handler of built.extension.handlers.get("tool_call") ?? []) {
		const result = await handler({ type: "tool_call", toolCallId, toolName, input } as never, built.ctx);
		if (result && typeof result === "object" && "block" in result) {
			return result as { block?: boolean; reason?: string };
		}
	}
	return undefined;
}

describe("registration", () => {
	test("registers every lifecycle handler the gate depends on", async () => {
		const built = await build();
		for (const event of [
			"session_start",
			"before_agent_start",
			"message_end",
			"tool_call",
			"tool_execution_start",
			"tool_result",
			"tool_approval_requested",
			"session_switch",
			"session_shutdown",
		]) {
			expect(built.extension.handlers.has(event)).toBe(true);
		}
	});

	test("registers exactly one namespaced command", async () => {
		const built = await build();
		expect([...built.extension.commands.keys()]).toEqual(["smart-approve"]);
	});

	test("startup makes no provider call", async () => {
		let judged = 0;
		await build({
			judge: () => {
				judged += 1;
				return ALLOW;
			},
		});
		expect(judged).toBe(0);
	});

	test("startup opens no dialog, so there is no automatic first-use wizard", async () => {
		const built = await build();
		expect(built.recorder.selectCalls).toBe(0);
	});
});

/**
 * `setup` ends by telling the operator to run `/smart-approve status`. If the
 * write does not reach the running session, that instruction answers with a
 * stale "not configured" and every scoped call keeps failing closed until the
 * operator guesses that a restart is required.
 */
describe("configuration written mid-session", () => {
	const SETUP_SESSION = {
		realConfig: true,
		models: [{ id: "claude-fast", provider: "anthropic" }],
		selectAnswer: "anthropic/claude-fast",
		confirmAnswer: true,
	};

	test("a successful setup arms the running session instead of waiting for a restart", async () => {
		const built = await build({ ...SETUP_SESSION });
		expect(built.recorder.statuses.get("smart-approve")).toContain("not configured");

		await runCommand(built, "setup");

		expect(readFileSync(path.join(agentDir, "smart-approve.yml"), "utf8")).toContain("anthropic/claude-fast");
		expect(built.recorder.statuses.get("smart-approve")).toBeUndefined();

		built.recorder.notices.length = 0;
		await runCommand(built, "status");
		const status = built.recorder.notices.join("\n");
		expect(status).toContain("Gate: armed");
		expect(status).toContain("authorized: anthropic/claude-fast");
	});

	test("setup adds the judge model without discarding the rest of the user's config", async () => {
		const configPath = path.join(agentDir, "smart-approve.yml");
		await Bun.write(
			configPath,
			["sensitivity:", "  fallback: strict", "judge:", "  maxOutputTokens: 2000", ""].join("\n"),
		);

		const built = await build({ ...SETUP_SESSION });
		await runCommand(built, "setup");

		// A wizard that silently deletes hand-written safety settings is worse than
		// one that refuses to run: the operator keeps a config they no longer have.
		const written = readFileSync(configPath, "utf8");
		expect(written).toContain("anthropic/claude-fast");
		expect(written).toContain("strict");
		expect(written).toContain("2000");

		built.recorder.notices.length = 0;
		await runCommand(built, "status");
		const status = built.recorder.notices.join("\n");
		expect(status).toContain("Gate: armed");
		expect(status).toContain("fallback:      strict");
	});

	test("a scoped call is judged as soon as setup writes, not blocked as unconfigured", async () => {
		const built = await build({ ...SETUP_SESSION, judge: () => ALLOW });
		const beforeSetup = await toolCall(built, "c1", "write", { path: "a.ts", content: "x" });
		expect(beforeSetup?.block).toBe(true);
		expect(beforeSetup?.reason).toContain("No authorized judge model configured");

		await runCommand(built, "setup");

		expect(await toolCall(built, "c2", "write", { path: "b.ts", content: "x" })).toBeUndefined();
	});
});

/**
 * OMP's interactive TUI folds consecutive "info" notifications into one mutable
 * status line, so a per-line `notify` loop leaves only the last line visible —
 * for `status` under default config, the trailing compatibility warning. The
 * whole report must therefore reach the host as a single notification.
 */
describe("command output delivery", () => {
	test("multi-line command output is a single notification, so the TUI status collapse cannot eat lines", async () => {
		const built = await build();
		built.recorder.notices.length = 0;
		await runCommand(built, "status");
		expect(built.recorder.notices).toHaveLength(1);
		const only = built.recorder.notices[0] ?? "";
		expect(only).toContain("SMART APPROVE STATUS");
		expect(only.split("\n").length).toBeGreaterThan(10);
	});
});

describe("before_agent_start guidance", () => {
	test("appends to the existing system prompt rather than replacing it", async () => {
		const built = await build();
		const result = await fire(
			built.extension,
			"before_agent_start",
			{ type: "before_agent_start", systemPrompt: ["ORIGINAL PROMPT"] },
			built.ctx,
		);
		expect(typeof result === "object" && result !== null && "systemPrompt" in result).toBe(true);
		if (typeof result !== "object" || result === null || !("systemPrompt" in result)) return;
		const prompt = result.systemPrompt;
		expect(Array.isArray(prompt)).toBe(true);
		if (!Array.isArray(prompt)) return;
		expect(prompt[0]).toBe("ORIGINAL PROMPT");
		expect(prompt.join("\n")).toContain("audit ID is a reference for a human, never authorization");
	});

	test("the note tells the agent not to retry the same operation", async () => {
		const built = await build();
		const result = await fire(
			built.extension,
			"before_agent_start",
			{ type: "before_agent_start", systemPrompt: [] },
			built.ctx,
		);
		const text = JSON.stringify(result);
		expect(text).toContain("do not retry the same operation");
	});
});

describe("tool_call handling", () => {
	test("an allowed call returns no result", async () => {
		const built = await build({ judge: () => ALLOW });
		expect(await toolCall(built, "c1", "write", { path: "a.ts", content: "x" })).toBeUndefined();
	});

	test("a blocked call returns the exact handler shape OMP expects", async () => {
		const built = await build({ judge: () => BLOCK });
		const result = await toolCall(built, "c1", "write", { path: "a.ts", content: "x" });
		expect(result?.block).toBe(true);
		expect(typeof result?.reason).toBe("string");
	});

	test("a block reason is actionable and carries the audit ID", async () => {
		const built = await build({ judge: () => BLOCK });
		const result = await toolCall(built, "c1", "write", { path: "a.ts", content: "x" });
		expect(result?.reason).toContain("Audit ID");
		expect(result?.reason).toContain("Next:");
	});

	test("a block reason never contains the raw arguments", async () => {
		const built = await build({ judge: () => BLOCK });
		const secret = "RAW_ARGUMENT_PAYLOAD_XYZ";
		const result = await toolCall(built, "c1", "write", { path: "a.ts", content: secret });
		expect(result?.reason).not.toContain(secret);
	});

	test("a duplicate tool_call for the same id is suppressed", async () => {
		let judged = 0;
		const built = await build({
			judge: () => {
				judged += 1;
				return ALLOW;
			},
		});
		await toolCall(built, "dup", "write", { path: "a.ts", content: "x" });
		await toolCall(built, "dup", "write", { path: "a.ts", content: "x" });
		expect(judged).toBe(1);
	});

	test("a local read is allowed without a provider call", async () => {
		let judged = 0;
		const built = await build({
			judge: () => {
				judged += 1;
				return ALLOW;
			},
		});
		expect(await toolCall(built, "r1", "read", { path: "a.ts" })).toBeUndefined();
		expect(judged).toBe(0);
	});
});

describe("failure containment", () => {
	test("a tool_call before session_start fails closed with a block", async () => {
		const built = await build({ skipSessionStart: true });
		const result = await toolCall(built, "c1", "write", { path: "a.ts", content: "x" });
		expect(result?.block).toBe(true);
		expect(result?.reason).toContain("could not start");
	});

	test("a startup failure is surfaced in status and blocks every scoped call", async () => {
		const built = await build({
			resolveOverride: () => {
				throw new Error("config exploded");
			},
		});
		expect(built.recorder.statuses.get("smart-approve")).toContain("FAILED");
		const result = await toolCall(built, "c1", "write", { path: "a.ts", content: "x" });
		expect(result?.block).toBe(true);
		expect(result?.reason).toContain("config exploded");
	});

	test("a judge that throws still yields a block, never an allow", async () => {
		const built = await build({
			judge: () => {
				throw new Error("judge exploded");
			},
		});
		const result = await toolCall(built, "c1", "write", { path: "a.ts", content: "x" });
		expect(result?.block).toBe(true);
	});

	test("the emergency reason carries no raw data", async () => {
		const built = await build({
			judge: () => {
				throw new Error("judge exploded");
			},
		});
		const secret = "EMERGENCY_RAW_VALUE";
		const result = await toolCall(built, "c1", "write", { path: "a.ts", content: secret });
		expect(result?.reason).not.toContain(secret);
	});
});

describe("provenance capture", () => {
	test("a user message and a tool result are captured without throwing", async () => {
		const built = await build();
		await fire(
			built.extension,
			"message_end",
			{ type: "message_end", message: { role: "user", content: "please refactor this" } },
			built.ctx,
		);
		await fire(
			built.extension,
			"tool_result",
			{
				type: "tool_result",
				toolCallId: "t1",
				toolName: "read",
				input: {},
				content: [{ type: "text", text: "file body" }],
				isError: false,
			},
			built.ctx,
		);
		// No assertion on internals: the contract is that these never throw and the
		// gate keeps working afterwards.
		expect(await toolCall(built, "c1", "write", { path: "a.ts", content: "x" })).toBeUndefined();
	});

	test("a malformed message event does not break the session", async () => {
		const built = await build();
		await fire(built.extension, "message_end", { type: "message_end" }, built.ctx);
		expect(await toolCall(built, "c1", "write", { path: "a.ts", content: "x" })).toBeUndefined();
	});
});

describe("pending notice on startup", () => {
	test("stays silent when there are no open records", async () => {
		const built = await build();
		expect(built.recorder.notices.filter(n => n.includes("still open"))).toHaveLength(0);
	});

	test("names the count and the pending command when open records exist", async () => {
		// First session leaves an open escalation behind.
		const first = await build({
			judge: () => ({
				ok: true,
				verdict: { decision: "escalate", risk: "uncertain", rationale: "needs a human" },
				metrics: { attempts: 1, latencyMs: 5, overTarget: false },
			}),
			hasUI: false,
		});
		await toolCall(first, "c1", "write", { path: "a.ts", content: "x" });
		const dbPath = first.dbPath;
		await fire(first.extension, "session_shutdown", { type: "session_shutdown" }, first.ctx);
		resetBrokerForTests();
		AgentRegistry.global().unregister(MAIN_AGENT_ID);

		// A fresh session pointed at the same database must surface the record.
		const recorder: Recorder = {
			widgets: new Map(),
			statuses: new Map(),
			notices: [],
			selectAnswer: undefined,
			selectCalls: 0,
			confirmAnswer: false,
			models: [],
			entries: [],
		};
		const ctx = makeCtx(recorder, true);
		registerSession(ctx);
		const paths: DiscoveryPaths = { cwd, agentDir, home };
		const factory = createSmartApproveExtension({
			now: () => clock,
			randomId: () => `audit-r-${nextSeq()}`,
			randomNonce: () => `nonce-r-${nextSeq()}`,
			resolveConfiguration: () =>
				resolveConfig(
					[
						{
							scope: "user",
							filePath: path.join(agentDir, "smart-approve.yml"),
							rawContent: "{}",
							data: {
								judge: { authorizedModels: ["anthropic/scripted"] },
								audit: { databasePath: dbPath },
							},
						},
					],
					[],
					paths,
				),
			judge: async () => ALLOW,
			redactor: { redactArguments: a => structuredClone(a), redactText: t => t, hasSecrets: () => false },
			argv: [],
		});
		const extension = await loadExtensionFromFactory(
			factory,
			cwd,
			new EventBus(),
			new ExtensionRuntime(),
			"restart",
		);
		await fire(extension, "session_start", { type: "session_start" }, ctx);
		const notice = recorder.notices.find(n => n.includes("still open"));
		expect(notice).toBeDefined();
		expect(notice).toContain("/smart-approve pending");
	});
});

describe("teardown", () => {
	test("shutdown clears widgets and status", async () => {
		const built = await build();
		await fire(built.extension, "session_shutdown", { type: "session_shutdown" }, built.ctx);
		expect(built.recorder.widgets.get("smart-approve:risk")).toBeUndefined();
		expect(built.recorder.statuses.get("smart-approve")).toBeUndefined();
	});

	test("after shutdown a tool call fails closed rather than using a stale runtime", async () => {
		const built = await build();
		await fire(built.extension, "session_shutdown", { type: "session_shutdown" }, built.ctx);
		const result = await toolCall(built, "c-after", "write", { path: "a.ts", content: "x" });
		expect(result?.block).toBe(true);
	});

	test("session_switch tears down the same way as shutdown", async () => {
		const built = await build();
		await fire(built.extension, "session_switch", { type: "session_switch" }, built.ctx);
		const result = await toolCall(built, "c-after", "write", { path: "a.ts", content: "x" });
		expect(result?.block).toBe(true);
	});

	test("shutdown is idempotent", async () => {
		const built = await build();
		await fire(built.extension, "session_shutdown", { type: "session_shutdown" }, built.ctx);
		await fire(built.extension, "session_shutdown", { type: "session_shutdown" }, built.ctx);
		expect(true).toBe(true);
	});
});

describe("auto-approve detection wiring", () => {
	/**
	 * The detector's own state machine is covered in host.test.ts. What matters
	 * here is the observable consequence: once the host is caught auto-approving,
	 * a judge `block` must become a real block instead of falling through to a
	 * native prompt that will never appear.
	 */
	test("after the host is caught auto-approving, a judge block becomes a real block", async () => {
		// Under always-ask a write is the prompt branch, so a judge block still
		// hard-blocks. Use an escalate verdict to observe the branch difference.
		const beforeLatch = await build({
			approvalMode: "always-ask",
			judge: () => ({
				ok: true,
				verdict: { decision: "escalate", risk: "uncertain", rationale: "needs a human" },
				metrics: { attempts: 1, latencyMs: 5, overTarget: false },
			}),
			hasUI: false,
		});
		// Prompt branch: escalate falls through to OMP's own dialog, so no block.
		expect(await toolCall(beforeLatch, "b1", "write", { path: "a.ts", content: "x" })).toBeUndefined();

		// Now teach the same session that the host auto-approves anyway.
		await toolCall(beforeLatch, "b2", "write", { path: "b.ts", content: "y" });
		await fire(
			beforeLatch.extension,
			"tool_execution_start",
			{ type: "tool_execution_start", toolCallId: "b2" },
			beforeLatch.ctx,
		);

		// Auto branch now: the same escalate verdict must block, because no native
		// prompt is coming to catch it.
		const after = await toolCall(beforeLatch, "b3", "write", { path: "c.ts", content: "z" });
		expect(after?.block).toBe(true);
		expect(after?.reason).toContain("/smart-approve review");
	});

	test("a genuine approval request keeps the prompt branch intact", async () => {
		const built = await build({
			approvalMode: "always-ask",
			judge: () => ({
				ok: true,
				verdict: { decision: "escalate", risk: "uncertain", rationale: "needs a human" },
				metrics: { attempts: 1, latencyMs: 5, overTarget: false },
			}),
			hasUI: false,
		});
		await toolCall(built, "p1", "write", { path: "a.ts", content: "x" });
		await fire(
			built.extension,
			"tool_approval_requested",
			{
				type: "tool_approval_requested",
				toolCallId: "p1",
				toolName: "write",
				sessionId: "s",
				approvalMode: "always-ask",
			},
			built.ctx,
		);
		await fire(
			built.extension,
			"tool_execution_start",
			{ type: "tool_execution_start", toolCallId: "p1" },
			built.ctx,
		);

		// The host behaved as predicted, so the prompt branch still applies and an
		// escalate keeps falling through to OMP's own dialog.
		expect(await toolCall(built, "p2", "write", { path: "b.ts", content: "y" })).toBeUndefined();
	});
});
