/**
 * Smart Approve — extension entry point and lifecycle wiring.
 *
 * Everything here is glue plus containment. The security decisions live in
 * `policy.ts`, `judge.ts`, `gate.ts`, and `broker.ts`; this file's job is to
 * feed them accurate host state and to make sure no exception, missing
 * dependency, or lifecycle race can turn a safety decision into an accidental
 * allow.
 *
 * The one rule that governs this file: **the `tool_call` boundary never
 * throws.** OMP converts a handler exception into a generic host error, which
 * is indistinguishable from a tool failure and would let a caller retry into
 * the same unsafe operation. Every failure is caught and converted into a
 * fail-closed block with an actionable reason.
 */

import type {
	ExtensionAPI,
	ExtensionContext,
	ToolCallEvent,
	ToolCallEventResult,
} from "@oh-my-pi/pi-coding-agent/extensibility/extensions/types";
import * as broker from "./broker.ts";
import { type CommandDeps, clearSuggestions, createCommands, recordSuggestion } from "./commands.ts";
import {
	argumentSizeThreshold,
	CONFIG_FILENAME,
	configCandidates,
	type DiscoveryPaths,
	defaultDatabasePath,
	type LoadedLayerInput,
	POLICY_FILENAME,
	type PolicyDocument,
	policyCandidates,
	type ResolvedConfig,
	resolveConfig,
} from "./config.ts";
import {
	buildJudgeInput,
	createProvenanceTracker,
	loadSessionRedactor,
	type ProvenanceTracker,
	type Redactor,
} from "./context.ts";
import type { GatePorts, GateRequest, HostApproval, JudgeInput, JudgeResult, SensitivityLevel } from "./contracts.ts";
import { Gate, type RiskCard, summarizeTargets } from "./gate.ts";
import {
	AutoApproveDetector,
	classifyHostApproval,
	globalRegistry,
	type LiveSession,
	resolveAgentIdentity,
} from "./host.ts";
import { createJudge, type JudgePorts } from "./judge.ts";
import { extractTargets, hashArguments } from "./policy.ts";
import { openStore, type SmartApproveStore, serializeSessionEntry } from "./store.ts";
import {
	createApprovalPresenter,
	renderRiskCard,
	STATUS_KEY,
	type UiHost,
	WIDGET_BYPASS,
	WIDGET_RISK_CARD,
} from "./ui.ts";

export const COMMAND_NAME = "smart-approve";

/**
 * Injection seam. Only tests and the local smoke harness supply these; the
 * default export always constructs real OMP-backed dependencies, and there is
 * deliberately no runtime config or environment path that can select a fake.
 */
export interface SmartApproveDependencies {
	now?(): number;
	randomId?(): string;
	randomNonce?(): string;
	randomChallenge?(): string;
	/** Override the resolved config, bypassing filesystem discovery. */
	resolveConfiguration?(paths: DiscoveryPaths): Promise<ResolvedConfig> | ResolvedConfig;
	openStore?: typeof openStore;
	/** Replace the judge with a scripted one. */
	judge?(input: JudgeInput, signal: AbortSignal): Promise<JudgeResult>;
	/** Replace the redactor, so a test need not construct OMP secret machinery. */
	redactor?: Redactor;
	/** argv used for auto-approve detection. */
	argv?: readonly string[];
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

async function readLayer(scope: "user" | "project", filePath: string): Promise<LoadedLayerInput | undefined> {
	const file = Bun.file(filePath);
	if (!(await file.exists())) return undefined;
	const rawContent = await file.text();
	let data: unknown;
	try {
		data = Bun.YAML.parse(rawContent);
	} catch (error) {
		throw new Error(`${filePath} is not valid YAML: ${error instanceof Error ? error.message : String(error)}`);
	}
	return { scope, filePath, data, rawContent };
}

async function discover(paths: DiscoveryPaths): Promise<ResolvedConfig> {
	const layers: LoadedLayerInput[] = [];
	for (const candidate of configCandidates(paths)) {
		const layer = await readLayer(candidate.scope, candidate.filePath);
		if (layer) layers.push(layer);
	}
	const documents: PolicyDocument[] = [];
	for (const candidate of policyCandidates(paths)) {
		const file = Bun.file(candidate.filePath);
		if (!(await file.exists())) continue;
		const content = await file.text();
		documents.push({
			filePath: candidate.filePath,
			scope: candidate.scope,
			content,
			contentHash: Bun.SHA256.hash(content, "hex"),
		});
	}
	return resolveConfig(layers, documents, paths);
}

/**
 * Resolve the agent directory the same way OMP does, honoring the live session's
 * own setting so an isolated smoke run lands in its temporary HOME rather than
 * the developer's real one.
 */
function resolveAgentDir(session: LiveSession | undefined, home: string): string {
	const settings = session?.settings;
	if (settings && "getAgentDir" in settings && typeof settings.getAgentDir === "function") {
		const value: unknown = settings.getAgentDir();
		if (typeof value === "string" && value.length > 0) return value;
	}
	const fromEnv = Bun.env.PI_CODING_AGENT_DIR;
	if (fromEnv) return fromEnv;
	return `${home}/.omp/agent`;
}

// ---------------------------------------------------------------------------
// Session runtime
// ---------------------------------------------------------------------------

interface SessionRuntime {
	resolved: ResolvedConfig;
	store: SmartApproveStore;
	gate: Gate;
	tracker: ProvenanceTracker;
	redactor: Redactor;
	detector: AutoApproveDetector;
	agentId: string;
	agentKind: "main" | "sub" | "advisor" | "unknown";
	parentAgentId?: string;
	session?: LiveSession;
}

/** Session-scoped bypass. Deliberately not persisted: it must die with the session. */
class BypassState {
	#active = false;
	#reason = "";

	active(): boolean {
		return this.#active;
	}

	get reason(): string {
		return this.#reason;
	}

	enable(reason: string): void {
		this.#active = true;
		this.#reason = reason;
	}

	disable(): void {
		this.#active = false;
		this.#reason = "";
	}
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Build the extension.
 *
 * Exported as a named seam so tests and `scripts/smoke.ts` can inject scripted
 * judge/UI/time ports. The default export calls this with no arguments.
 */
export function createSmartApproveExtension(dependencies: SmartApproveDependencies = {}) {
	const now = dependencies.now ?? (() => Date.now());
	const randomId = dependencies.randomId ?? (() => crypto.randomUUID());
	const randomNonce = dependencies.randomNonce ?? (() => crypto.randomUUID());
	const randomChallenge =
		dependencies.randomChallenge ?? (() => crypto.randomUUID().replaceAll("-", "").slice(0, 8).toUpperCase());

	return (api: ExtensionAPI): void => {
		let runtime: SessionRuntime | undefined;
		let startupError: string | undefined;
		const bypass = new BypassState();
		/** Tool calls we have seen, so a duplicate event cannot be judged twice. */
		const seenToolCalls = new Set<string>();

		const uiFor = (ctx: ExtensionContext): UiHost => ({
			hasUI: ctx.hasUI,
			select: (title, options) => ctx.ui.select(title, options),
			confirm: (title, message) => ctx.ui.confirm(title, message),
			input: (title, placeholder) => ctx.ui.input(title, placeholder),
			notify: (message, type) => ctx.ui.notify(message, type),
			setStatus: (key, text) => ctx.ui.setStatus(key, text),
			setWidget: (key, lines) => ctx.ui.setWidget(key, lines),
		});

		// ------------------------------------------------------------ session start

		api.on("session_start", async (_event, ctx) => {
			try {
				const home = Bun.env.HOME ?? "/";
				const identity = resolveAgentIdentity(globalRegistry(), ctx.sessionManager);
				const agentDir = resolveAgentDir(identity.session, home);
				const paths: DiscoveryPaths = { cwd: ctx.cwd, agentDir, home };

				const resolved = dependencies.resolveConfiguration
					? await dependencies.resolveConfiguration(paths)
					: await discover(paths);

				const store = (dependencies.openStore ?? openStore)(resolved.databasePath, {
					busyTimeoutMs: resolved.config.audit.busyTimeoutMs,
				});

				// A configuration or policy edit invalidates every outstanding allow
				// grant. Deny rules survive, so tightening never widens the gate.
				store.revokeGrantsForPolicy(resolved.policyHash, ctx.cwd, now());
				store.expirePending(now());

				const redactor = dependencies.redactor ?? (await loadSessionRedactor(ctx.cwd, agentDir));
				const tracker = createProvenanceTracker({ redactor });

				const judgePorts: JudgePorts = {
					listModels: () => ctx.models.list(),
					currentModel: () => ctx.models.current(),
					resolveModel: spec => ctx.models.resolve(spec),
					family: model => ctx.models.family(model),
					hasConfiguredAuth: model => ctx.modelRegistry.hasConfiguredAuth(model),
					getApiKey: async (model, sessionId) => (await ctx.modelRegistry.getApiKey(model, sessionId)) ?? "",
					complete: async (model, context, options) => {
						const { completeSimple } = await import("@oh-my-pi/pi-ai");
						return completeSimple(model, context, options);
					},
					now,
				};
				const realJudge = createJudge({ config: resolved.config, ports: judgePorts });

				const ports: GatePorts = {
					classifyHostApproval: async () => ({ branch: "unsupported", reason: "unused" }),
					judge: dependencies.judge
						? (input, signal) =>
								dependencies.judge?.(input, signal) ?? Promise.reject(new Error("no judge"))
						: (input, signal) => realJudge(input, signal, randomId()),
					escalate: createApprovalPresenter(uiFor(ctx), now),
					now,
					randomNonce,
					randomId,
				};

				const gate = new Gate({
					resolved,
					store,
					ports,
					buildJudgeInput: (request, context) =>
						buildJudgeInput({
							toolName: request.toolName,
							operation: request.canonicalCall.operation,
							targets: request.canonicalCall.targets,
							sourceAgentId: request.sourceAgentId,
							rawArguments: request.rawArguments,
							threshold: argumentSizeThreshold(resolved.config, request.toolName),
							redactor,
							tracker,
							policyDocuments: resolved.policyDocuments.map(d => d.content),
							postureHints: context.postureHints,
							sensitivity: context.sensitivity,
						}),
					publishRiskCard: (card: RiskCard) => ctx.ui.setWidget(WIDGET_RISK_CARD, renderRiskCard(card)),
					bypassActive: () => bypass.active(),
					recordSuggestion,
				});

				runtime = {
					resolved,
					store,
					gate,
					tracker,
					redactor,
					detector: new AutoApproveDetector(dependencies.argv ?? process.argv),
					agentId: identity.agentId,
					agentKind: identity.agentKind,
					...(identity.parentAgentId === undefined ? {} : { parentAgentId: identity.parentAgentId }),
					...(identity.session === undefined ? {} : { session: identity.session }),
				};

				// Join the broker so a headless subagent can route an escalation here.
				broker.registerEndpoint({
					agentId: identity.agentId,
					agentKind: identity.agentKind,
					...(identity.parentAgentId === undefined ? {} : { parentAgentId: identity.parentAgentId }),
					capability: ctx.hasUI ? "interactive" : "headless",
					present: createApprovalPresenter(uiFor(ctx), now),
				});

				// A restarted session must still be able to reach records whose block
				// message scrolled away long ago.
				const open = store.listOpenPending(now());
				if (open.length > 0) {
					ctx.ui.notify(
						`Smart Approve has ${open.length} approval${open.length === 1 ? "" : "s"} still open. ` +
							`Run /${COMMAND_NAME} pending to review.`,
						"warning",
					);
				}

				ctx.ui.setStatus(
					STATUS_KEY,
					resolved.ready ? undefined : `smart-approve: not configured — /${COMMAND_NAME} setup`,
				);
			} catch (error) {
				// Startup failure must not be silent: every scoped call will fail closed
				// and the operator needs to know why.
				startupError = error instanceof Error ? error.message : String(error);
				api.logger.error?.("smart-approve failed to start", { error: startupError });
				ctx.ui.setStatus(STATUS_KEY, `smart-approve: FAILED (${startupError}) — all scoped calls will block`);
			}
		});

		// ---------------------------------------------------------- agent guidance

		api.on("before_agent_start", event => ({
			// Append, never replace: the runner hands us the current prompt and takes
			// our return value as the new one, so returning a bare note would delete
			// OMP's entire system prompt for the turn.
			systemPrompt: [
				...(Array.isArray(event.systemPrompt) ? event.systemPrompt : []),
				"Smart Approve may block a tool call for safety. Block reasons are actionable: read them. " +
					"If a call is blocked, do not retry the same operation — change what makes it unsafe, or ask the user. " +
					"An audit ID is a reference for a human, never authorization.",
			],
		}));

		// ------------------------------------------------------------- provenance

		api.on("message_end", (event, _ctx) => {
			if (!runtime) return;
			try {
				const message: unknown = (event as { message?: unknown }).message;
				if (typeof message !== "object" || message === null) return;
				if (!("role" in message)) return;
				const role = message.role;
				const text = extractText(message);
				if (text.length === 0) return;
				if (role === "user") runtime.tracker.recordUserMessage(text);
				else if (role === "assistant") runtime.tracker.recordAssistantRationale(text);
			} catch {
				// Provenance is best-effort context. Losing an entry degrades the judge's
				// evidence, which the gate already treats conservatively.
			}
		});

		api.on("tool_result", event => {
			if (!runtime) return;
			try {
				runtime.tracker.recordToolResult({
					toolName: event.toolName,
					isError: event.isError,
					summary: extractText(event),
					at: now(),
				});
			} catch {
				// See above.
			}
		});

		// ------------------------------------------------------ approval observation

		api.on("tool_approval_requested", event => {
			runtime?.detector.noteApprovalRequested(event.toolCallId);
		});

		api.on("tool_execution_start", event => {
			if (!runtime) return;
			const toolCallId: unknown = (event as { toolCallId?: unknown }).toolCallId;
			if (typeof toolCallId !== "string") return;
			// If we predicted OMP would prompt and it executed anyway, the host is
			// auto-approving behind a private flag. Latch it and say so loudly.
			if (runtime.detector.noteExecutionStarted(toolCallId)) {
				api.logger.warn?.("smart-approve detected host auto-approve", { reason: runtime.detector.reason });
			}
			// The pre-screen card belongs to the call that just started running.
			void toolCallId;
		});

		// -------------------------------------------------------------- the gate

		api.on("tool_call", async (event: ToolCallEvent, ctx): Promise<ToolCallEventResult | undefined> => {
			// Duplicate suppression: judging one call twice would double-count strikes
			// and could produce two conflicting audit rows.
			if (seenToolCalls.has(event.toolCallId)) return undefined;
			seenToolCalls.add(event.toolCallId);
			if (seenToolCalls.size > 512) {
				const oldest = seenToolCalls.values().next().value;
				if (oldest !== undefined) seenToolCalls.delete(oldest);
			}

			if (!runtime) {
				return {
					block: true,
					reason:
						`Smart Approve could not start${startupError ? ` (${startupError})` : ""}, so it cannot prove ` +
						`this call is safe. Scoped calls stay blocked until /${COMMAND_NAME} status reports healthy.`,
				};
			}

			const active = runtime;
			try {
				// `ToolCallEvent` is a union whose per-tool members carry concrete input
				// shapes. Every one is a string-keyed object; this widens to the common
				// record type without asserting any particular field exists.
				const args: Readonly<Record<string, unknown>> = { ...event.input };
				const extracted = extractTargets({ toolName: event.toolName, args, cwd: ctx.cwd });
				const argumentsHash = hashArguments(args);
				const receivedAt = now();

				const request: GateRequest = {
					auditId: randomId(),
					toolCallId: event.toolCallId,
					toolName: event.toolName,
					sourceAgentId: active.agentId,
					sourceAgentKind: active.agentKind,
					...(active.parentAgentId === undefined ? {} : { parentAgentId: active.parentAgentId }),
					canonicalCall: {
						toolName: event.toolName,
						operation: extracted.operation,
						targets: extracted.targets,
						argumentsHash,
						...(extracted.device === undefined ? {} : { device: extracted.device }),
					},
					rawArguments: Object.freeze({ ...args }),
					argumentsHash,
					cwd: ctx.cwd,
					receivedAt,
					deadlineAt: receivedAt + active.resolved.config.timeouts.handlerSelfDeadlineMs,
				};

				const hostApproval: HostApproval = classifyHostApproval({
					session: active.session,
					toolName: event.toolName,
					args,
					hostAutoApprove: active.detector.active,
				});
				// Only a prompt prediction is worth verifying: an auto prediction that
				// turns out to prompt is strictly safer than we assumed.
				if (hostApproval.branch === "prompt") {
					active.detector.expectPrompt(event.toolCallId, event.toolName);
				}

				const result = await active.gate.evaluate(request, hostApproval);

				// Compact redacted session entry, never the raw call or full rationale.
				// Isolated deliberately: the durable audit row is the record of truth,
				// and a host that cannot append a transcript entry must not be able to
				// turn a completed safety decision into a generic internal error.
				if (active.resolved.config.audit.sessionEntries) {
					try {
						const record = active.store.getAudit(result.auditId);
						if (record) api.appendEntry?.("smart-approve", JSON.parse(serializeSessionEntry(record)));
					} catch (error) {
						api.logger.warn?.("smart-approve could not append a session entry", {
							error: error instanceof Error ? error.message : String(error),
						});
					}
				}

				if (result.decision === "block") {
					active.detector.forget(event.toolCallId);
					try {
						ctx.ui.setWidget(WIDGET_RISK_CARD, undefined);
					} catch {
						// A UI that cannot clear a widget still gets the block.
					}
					return { block: true, reason: result.reason };
				}
				return undefined;
			} catch (error) {
				// Last line of defense. A thrown handler would become a generic host
				// error; a block is an unambiguous safety result.
				const detail = error instanceof Error ? error.message : String(error);
				api.logger.error?.("smart-approve tool_call failed", { error: detail });
				return {
					block: true,
					reason:
						`Smart Approve failed while evaluating this call (${detail}) and will not assume it is safe. ` +
						`Run /${COMMAND_NAME} status.`,
				};
			}
		});

		// ------------------------------------------------------------- teardown

		const teardown = (ctx: ExtensionContext) => {
			try {
				ctx.ui.setWidget(WIDGET_RISK_CARD, undefined);
				ctx.ui.setWidget(WIDGET_BYPASS, undefined);
				ctx.ui.setStatus(STATUS_KEY, undefined);
			} catch {
				// A torn-down UI cannot be cleaned; nothing else depends on it.
			}
			if (!runtime) return;
			broker.unregisterEndpoint(runtime.agentId);
			// Raw in-memory calls die with the session, deliberately and immediately.
			broker.evictExpired(Number.POSITIVE_INFINITY);
			runtime.tracker.clear();
			clearSuggestions();
			bypass.disable();
			seenToolCalls.clear();
			try {
				runtime.store.close();
			} catch {
				// Closing a store that already failed is not worth escalating.
			}
			runtime = undefined;
		};

		api.on("session_shutdown", (_event, ctx) => teardown(ctx));
		api.on("session_switch", (_event, ctx) => teardown(ctx));

		// ------------------------------------------------------------- commands

		api.registerCommand(COMMAND_NAME, {
			description: "Inspect and control Smart Approve: status, rules, pending approvals, overrides, bypass.",
			handler: async (args: string, ctx: ExtensionContext) => {
				if (!runtime) {
					ctx.ui.notify(`Smart Approve is not running${startupError ? `: ${startupError}` : ""}.`, "error");
					return;
				}
				const active = runtime;
				const deps: CommandDeps = {
					resolved: active.resolved,
					store: active.store,
					ui: uiFor(ctx),
					now,
					randomId,
					randomChallenge,
					recomputeHash: hashArguments,
					// The unguarded warning has exactly one renderer, in `unguarded`
					// and `guarded`, so two copies of it cannot drift apart. This port
					// carries session state and nothing else.
					bypass,
					models: {
						list: () => ctx.models.list().map(m => ({ id: m.id, provider: m.provider })),
						current: () => {
							const current = ctx.models.current();
							return current ? { id: current.id, provider: current.provider } : undefined;
						},
						family: model => {
							const resolvedModel = ctx.models.resolve(`${model.provider}/${model.id}`);
							return resolvedModel ? ctx.models.family(resolvedModel) : model.provider;
						},
					},
					writeConfig: async patch => {
						const target = `${active.resolved.paths.agentDir}/${CONFIG_FILENAME}`;
						// Write through a temporary file so a crash mid-write cannot leave a
						// truncated security configuration behind.
						const temporary = `${target}.tmp-${randomId()}`;
						await Bun.write(temporary, Bun.YAML.stringify(patch));
						await Bun.$`mv ${temporary} ${target}`.quiet();
						return target;
					},
				};
				const commands = createCommands(deps);
				const output = await commands.run(args);
				for (const line of output.lines) ctx.ui.notify(line, "info");
			},
		});
	};
}

/** Best-effort text extraction from a message or tool result event. */
function extractText(value: object): string {
	if ("content" in value) {
		const content = value.content;
		if (typeof content === "string") return content;
		if (Array.isArray(content)) {
			return content
				.map(block =>
					typeof block === "object" && block !== null && "text" in block && typeof block.text === "string"
						? block.text
						: "",
				)
				.filter(text => text.length > 0)
				.join("\n");
		}
	}
	return "";
}

export default createSmartApproveExtension();

export type { SensitivityLevel };
export { CONFIG_FILENAME, defaultDatabasePath, POLICY_FILENAME, summarizeTargets };
