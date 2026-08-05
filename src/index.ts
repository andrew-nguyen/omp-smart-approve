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
	writableConfigPath,
} from "./config.ts";
import {
	buildEscalationContext,
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

/** Narrow to a mergeable mapping: arrays and scalars are replaced, not merged. */
function asSection(value: unknown): Record<string, unknown> | undefined {
	return typeof value === "object" && value !== null && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: undefined;
}

/**
 * Fold a written patch into the configuration already on disk, section by
 * section — the same key-by-key merge layers get at read time.
 *
 * Serializing the patch alone would delete every other setting in the file, so
 * an operator who had tuned sensitivity, rules, or timeouts would lose all of it
 * the moment they re-ran `setup`. Values survive the YAML round-trip; comments
 * do not.
 */
function mergeConfigPatch(
	existing: Readonly<Record<string, unknown>>,
	patch: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
	const merged: Record<string, unknown> = { ...existing };
	for (const [key, value] of Object.entries(patch)) {
		const currentSection = asSection(merged[key]);
		const patchSection = asSection(value);
		merged[key] = currentSection && patchSection ? mergeConfigPatch(currentSection, patchSection) : value;
	}
	return merged;
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

		/**
		 * Everything the gate derives from configuration, in one place, so the
		 * startup path and the reconfigure path cannot drift into judging by
		 * different rules.
		 */
		const buildGate = (
			ctx: ExtensionContext,
			resolved: ResolvedConfig,
			store: SmartApproveStore,
			redactor: Redactor,
			tracker: ProvenanceTracker,
		): Gate => {
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
					? (input, signal) => dependencies.judge?.(input, signal) ?? Promise.reject(new Error("no judge"))
					: (input, signal) => realJudge(input, signal, randomId()),
				escalate: createApprovalPresenter(uiFor(ctx), now),
				now,
				randomNonce,
				randomId,
			};

			return new Gate({
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
				buildEscalationContext: () => buildEscalationContext(tracker),
				publishRiskCard: (card: RiskCard) => ctx.ui.setWidget(WIDGET_RISK_CARD, renderRiskCard(card)),
				bypassActive: () => bypass.active(),
				recordSuggestion,
			});
		};

		/**
		 * Fold a just-written configuration into the *running* session.
		 *
		 * Configuration is read once at `session_start`, so without this a
		 * successful `setup` changes a file nobody rereads: `status` keeps
		 * answering "not configured", the status line keeps advertising the
		 * wizard, and every scoped call keeps failing closed until the operator
		 * guesses that a restart is required.
		 *
		 * The store is deliberately reused. A judgment already in flight holds it,
		 * and closing it underneath one would turn a configuration edit into a
		 * spurious block. A configuration that moves the audit database therefore
		 * still needs a restart, and says so rather than silently splitting the
		 * session between two databases.
		 */
		const rearm = async (ctx: ExtensionContext, active: SessionRuntime): Promise<void> => {
			const resolved = dependencies.resolveConfiguration
				? await dependencies.resolveConfiguration(active.resolved.paths)
				: await discover(active.resolved.paths);

			// Same invariant as startup: a configuration edit invalidates every
			// outstanding allow grant. Deny rules survive, so tightening never widens
			// the gate.
			active.store.revokeGrantsForPolicy(resolved.policyHash, ctx.cwd, now());

			if (resolved.databasePath !== active.resolved.databasePath) {
				ctx.ui.notify(
					`Smart Approve keeps auditing to ${active.resolved.databasePath} until this session restarts;` +
						` the new configuration names ${resolved.databasePath}.`,
					"warning",
				);
			}

			active.resolved = resolved;
			active.gate = buildGate(ctx, resolved, active.store, active.redactor, active.tracker);
			ctx.ui.setStatus(
				STATUS_KEY,
				resolved.ready ? undefined : `smart-approve: not configured — /${COMMAND_NAME} setup`,
			);
		};

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
				seedUserIntent(tracker, ctx.sessionManager);

				const gate = buildGate(ctx, resolved, store, redactor, tracker);

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
					// A block the human never sees is a block they cannot act on. The
					// gate uses this only on the async path, once per escalation.
					notifyPending: line => ctx.ui.notify(line, "warning"),
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

		/**
		 * The current turn's narration, captured while it streams.
		 *
		 * The host prepares tool dispatch — and so fires `tool_call` — before it
		 * publishes the finished assistant message, so `message_end` always arrives
		 * too late to explain the calls that message makes. Reading the partials is
		 * the only way the judge sees why *this* call is happening instead of what
		 * the agent said a message ago.
		 */
		const streamingRationale = (event: unknown, take: "clear" | "buffer"): void => {
			if (!runtime) return;
			try {
				const message: unknown = (event as { message?: unknown }).message;
				if (typeof message !== "object" || message === null) return;
				if (!("role" in message) || message.role !== "assistant") return;
				runtime.tracker.observeInFlightRationale(take === "clear" ? undefined : extractRationaleText(message));
			} catch {
				// See `message_end`: provenance is best-effort.
			}
		};

		// A new turn starts with nothing said yet; the last turn's words must not
		// stand in for it.
		api.on("message_start", event => streamingRationale(event, "clear"));
		api.on("message_update", event => streamingRationale(event, "buffer"));

		api.on("message_end", (event, _ctx) => {
			if (!runtime) return;
			try {
				const message: unknown = (event as { message?: unknown }).message;
				if (typeof message !== "object" || message === null) return;
				const source = classifyIntentSource(message);
				if (source.kind === "ignore") return;
				if (source.kind === "user-intent") {
					// Empty means "nothing capturable here", not "the user asked for
					// nothing". Recording it would erase the authority the judge
					// measures every later call against.
					if (source.text.length > 0) runtime.tracker.recordUserMessage(source.text);
					return;
				}
				const rationale = extractRationaleText(message);
				// The turn is over: its text is now history, not the live account of a
				// call in flight.
				runtime.tracker.observeInFlightRationale(undefined);
				if (rationale.text.length === 0) return;
				runtime.tracker.recordAssistantRationale(rationale.text, {
					fromReasoning: rationale.fromReasoning,
				});
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
						const target = writableConfigPath(active.resolved.paths);
						// The patch changes one setting; everything else in the file is the
						// operator's and must survive.
						const existing = await readLayer("user", target);
						const merged = mergeConfigPatch(asSection(existing?.data) ?? {}, patch);
						// Write through a temporary file so a crash mid-write cannot leave a
						// truncated security configuration behind.
						const temporary = `${target}.tmp-${randomId()}`;
						await Bun.write(temporary, Bun.YAML.stringify(merged));
						await Bun.$`mv ${temporary} ${target}`.quiet();
						// The session read its configuration at startup, so the write only
						// counts once the running session has taken it up.
						await rearm(ctx, active);
						return target;
					},
				};
				const commands = createCommands(deps);
				const output = await commands.run(args);
				// The interactive TUI collapses consecutive status notifications into a
				// single mutable line, so one notify per line would show only the last.
				if (output.lines.length > 0) ctx.ui.notify(output.lines.join("\n"), "info");
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

/**
 * The account this assistant turn gives of itself.
 *
 * Prose first. A turn that thought and then called a tool without narrating has
 * no prose at all, and reading that as "no rationale" is what left the judge
 * quoting a sentence from two messages earlier as if it were live justification.
 * The reasoning text is then the only account of this turn that exists, so it is
 * used — and flagged, so the judge is never told the agent said something it did
 * not say out loud.
 */
function extractRationaleText(message: object): { text: string; fromReasoning: boolean } {
	const prose = extractText(message);
	if (prose.length > 0) return { text: prose, fromReasoning: false };
	return { text: extractThinking(message), fromReasoning: true };
}

/** Reasoning blocks carry `thinking`, not `text`, so {@link extractText} skips them. */
function extractThinking(message: object): string {
	if (!("content" in message) || !Array.isArray(message.content)) return "";
	return message.content
		.map(block =>
			typeof block === "object" && block !== null && "thinking" in block && typeof block.thinking === "string"
				? block.thinking
				: "",
		)
		.filter(text => text.length > 0)
		.join("\n");
}

/**
 * Host constants, duplicated rather than imported: `SKILL_PROMPT_MESSAGE_TYPE`
 * lives in `@oh-my-pi/pi-coding-agent/session/messages`, whose import pulls the
 * native addon bundle in at runtime. Both values are part of the persisted
 * session format, so they are as stable as the entry schema itself.
 */
const SKILL_PROMPT_CUSTOM_TYPE = "skill-prompt";
const COLLAB_PROMPT_CUSTOM_TYPE = "collab-prompt";

/**
 * The only custom types whose content or details a human authored.
 *
 * An allowlist, because `attribution: "user"` alone does not mean the user wrote
 * it: the host stamps the same attribution on the `ultrathink-notice`,
 * `orchestrate-notice`, and `workflow-notice` boilerplate it appends *after* a
 * user turn, and on the model-generated `image-attachment-description`. Any of
 * those would overwrite the real request — one with harness prose, one with
 * model output wearing user authority.
 *
 * These two are exactly the custom types the host itself converts into a
 * `role: "user"` message for the model (`isUserInvokedSkillPrompt`,
 * `isSteeringUserMessage` in `session/messages.ts`).
 */
const USER_AUTHORED_CUSTOM_TYPES: Record<string, true> = {
	[SKILL_PROMPT_CUSTOM_TYPE]: true,
	[COLLAB_PROMPT_CUSTOM_TYPE]: true,
};

/** Which authority channel a completed message may feed. */
type IntentSource = { kind: "user-intent"; text: string } | { kind: "assistant" } | { kind: "ignore" };

/**
 * Classify a message into the channel it speaks for.
 *
 * This is a trust boundary, not bookkeeping. USER INTENT is the only authority
 * the judge measures a call against, so a message reaches it only when the human
 * actually authored it — role alone is not enough, and neither is arriving in a
 * user-shaped envelope the agent or the harness produced.
 */
function classifyIntentSource(message: object): IntentSource {
	if (!("role" in message)) return { kind: "ignore" };
	switch (message.role) {
		case "assistant":
			return { kind: "assistant" };
		case "user":
			// Auto-continue and agent-issued prompts wear the user role without being
			// the user. A steering message is typed by the human mid-turn, so it
			// carries their authority and is deliberately not filtered out.
			if ("synthetic" in message && message.synthetic === true) return { kind: "ignore" };
			if ("attribution" in message && message.attribution === "agent") return { kind: "ignore" };
			return { kind: "user-intent", text: extractText(message) };
		case "custom": {
			// Skill and collab prompts reach the model as user messages; every other
			// custom type is harness or model text, whatever it is attributed to.
			if (!("attribution" in message) || message.attribution !== "user") return { kind: "ignore" };
			const customType = "customType" in message ? message.customType : undefined;
			if (typeof customType !== "string" || USER_AUTHORED_CUSTOM_TYPES[customType] !== true) {
				return { kind: "ignore" };
			}
			return {
				kind: "user-intent",
				text: customType === SKILL_PROMPT_CUSTOM_TYPE ? describeSkillInvocation(message) : extractText(message),
			};
		}
		default:
			// `developer`, `toolResult`, and any future role: no user authority.
			return { kind: "ignore" };
	}
}

/**
 * Recover the last user request from the session already on disk.
 *
 * A session resumed mid-task holds the request in its history but not in the
 * tracker, so without this its first calls are judged as if the user had asked
 * for nothing — the same starved-authority state that turns a routine call into
 * an escalation. The branch is root-to-leaf, so it is walked backward: the
 * latest user-authored entry wins, exactly as live capture would have left it.
 */
function seedUserIntent(tracker: ProvenanceTracker, sessionManager: ExtensionContext["sessionManager"]): void {
	try {
		const getBranch: unknown = sessionManager.getBranch;
		if (typeof getBranch !== "function") return;
		const branch: unknown = getBranch.call(sessionManager);
		if (!Array.isArray(branch)) return;
		for (let index = branch.length - 1; index >= 0; index--) {
			const message = messageFromEntry(branch[index]);
			if (message === undefined) continue;
			const source = classifyIntentSource(message);
			if (source.kind !== "user-intent" || source.text.length === 0) continue;
			tracker.recordUserMessage(source.text);
			return;
		}
	} catch {
		// Seeding is best-effort, like every other provenance path: a session that
		// cannot read its own history starts with empty intent, which the judge
		// already handles conservatively. It must never fail startup, because a
		// failed startup blocks every scoped call.
	}
}

/**
 * Project a persisted session entry onto the message shape
 * {@link classifyIntentSource} reads.
 *
 * A custom message persists as its own entry type with the fields on the entry
 * itself, not nested under `message`, so the skill invocation a resumed session
 * was started from is invisible to a `type === "message"` filter.
 */
function messageFromEntry(entry: unknown): object | undefined {
	if (typeof entry !== "object" || entry === null || !("type" in entry)) return undefined;
	if (entry.type === "message") {
		const message: unknown = "message" in entry ? entry.message : undefined;
		return typeof message === "object" && message !== null ? message : undefined;
	}
	if (entry.type !== "custom_message") return undefined;
	return {
		role: "custom",
		...("customType" in entry ? { customType: entry.customType } : {}),
		...("attribution" in entry ? { attribution: entry.attribution } : {}),
		...("details" in entry ? { details: entry.details } : {}),
		...("content" in entry ? { content: entry.content } : {}),
	};
}

/**
 * Describe a skill invocation using only what the human supplied: the skill they
 * named and the arguments they wrote.
 *
 * The message content is deliberately not read. The host renders the whole
 * SKILL.md body into it, and that body is disk content the agent chose to load —
 * recording it as user intent would let any skill file on disk authorize the
 * calls it asks for.
 */
function describeSkillInvocation(message: object): string {
	const details: unknown = "details" in message ? message.details : undefined;
	if (typeof details !== "object" || details === null) return "";
	const name = "name" in details && typeof details.name === "string" ? details.name : "";
	// Without the skill's name nothing trustworthy is left to attribute, so the
	// channel stays empty and the judge treats authority as unproven.
	if (name.length === 0) return "";
	const args = "args" in details && typeof details.args === "string" ? details.args.trim() : "";
	return args.length === 0 ? `Invoked skill "${name}"` : `Invoked skill "${name}": ${args}`;
}

export default createSmartApproveExtension();

export type { SensitivityLevel };
export { CONFIG_FILENAME, defaultDatabasePath, POLICY_FILENAME, summarizeTargets };
