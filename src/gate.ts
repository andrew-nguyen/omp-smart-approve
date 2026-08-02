/**
 * End-to-end decision orchestration.
 *
 * This is where every safety invariant converges, so the ordering below is the
 * specification, not an implementation detail:
 *
 * ```text
 * freeze + hash call -> start audit -> protected/deny checks
 *   -> resolve native approval branch
 *   -> if native prompt: semantic pre-screen only (never a second dialog)
 *   -> if native auto and scoped:
 *        exact grant (including approval/override grants) -> allow
 *        else retry-family loop-break check
 *        else judge
 *   -> durable terminal audit write
 *   -> allow, or return an actionable block reason
 * ```
 *
 * Two rules hold on every path:
 *
 * 1. **Audit before allow.** A scoped call cannot return allow until its terminal
 *    redacted audit row has committed. A failed write becomes escalation, then a
 *    block — never a silent unaudited execution.
 * 2. **Every failure becomes escalation.** Judge failure, config failure, storage
 *    failure, missing UI, and deadline exhaustion all funnel into the escalation
 *    path, which ends in a durable pending record and an audited block. No branch
 *    converts unavailability into approval.
 *
 * Escalation is asynchronous by default. OMP caps this handler at 30 seconds,
 * which is far too short for a human decision, so the handler persists a pending
 * approval and returns a block carrying the audit ID. The in-handler dialog is a
 * best-effort fast path, offered only when a live main TUI exists and the
 * remaining budget clears the dialog floor.
 */

import * as broker from "./broker.ts";
import { effectiveSensitivity, type ResolvedConfig } from "./config.ts";
import type {
	AuditEvent,
	AuditRecord,
	CanonicalCall,
	Decision,
	FrozenCall,
	GatePorts,
	GateRequest,
	GateResult,
	GateStage,
	HostApproval,
	JudgeInput,
	JudgeMetrics,
	PendingApproval,
	PolicyRule,
	RiskClass,
	RuleSuggestion,
	SensitivityLevel,
	ToolTier,
	Verdict,
} from "./contracts.ts";
import { evaluateDeterministic, hashCanonicalCall, matchExactAllow, retryFamilyKey } from "./policy.ts";
import type { SmartApproveStore } from "./store.ts";

/** How many blocked attempts in one retry family before the loop breaker fires. */
export const LOOP_BREAK_THRESHOLD = 3;

/** Ordering used to decide whether a per-risk override TIGHTENS the posture. */
const SENSITIVITY_RANK: Record<SensitivityLevel, number> = { permissive: 0, balanced: 1, strict: 2 };

export interface GateDependencies {
	resolved: ResolvedConfig;
	store: SmartApproveStore;
	ports: GatePorts;
	/** Builds the redacted judge snapshot. Injected so the gate stays testable. */
	buildJudgeInput(request: GateRequest, context: JudgeContextInput): JudgeInput;
	/** Publishes a companion risk card next to OMP's native prompt. */
	publishRiskCard?(card: RiskCard): void;
	/** True when this session is deliberately unguarded by a human. */
	bypassActive?(): boolean;
	/**
	 * Surfaces a judge's non-binding rule suggestion so `/smart-approve
	 * apply-suggestion` can offer it. Suggestions are never persisted and never
	 * applied automatically.
	 */
	recordSuggestion?(auditId: string, suggestion: RuleSuggestion): void;
}

export interface JudgeContextInput {
	tier: ToolTier | undefined;
	postureHints: string[];
	sensitivity: SensitivityLevel;
}

export interface RiskCard {
	auditId: string;
	toolName: string;
	risk: RiskClass;
	rationale: string;
	targetSummary: string;
	judgeAvailable: boolean;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** One-line, redacted description of where a call points. Safe to persist. */
export function summarizeTargets(call: CanonicalCall): string {
	if (call.targets.length === 0) return `${call.toolName} (no resolved target)`;
	return call.targets
		.slice(0, 4)
		.map(t => `${t.kind}:${t.resolved ?? t.requested}${t.dynamic ? " (unresolved)" : ""}`)
		.join(", ");
}

function blockReason(auditId: string, cause: string, nextAction: string): string {
	return `Smart Approve blocked this call.\nReason: ${cause}\nAudit ID: ${auditId}\nNext: ${nextAction}`;
}

const RETRY_GUIDANCE =
	"Do not retry the same operation. Change what makes it unsafe, or ask the user directly. " +
	"An audit ID is not authorization.";

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------

export class Gate {
	readonly #deps: GateDependencies;

	constructor(deps: GateDependencies) {
		this.#deps = deps;
	}

	/**
	 * Evaluate one tool call.
	 *
	 * Never throws: the caller is an OMP event handler, and an exception there
	 * becomes an ambiguous host error rather than a safety decision. Every
	 * unexpected failure is contained and converted into a fail-closed result.
	 */
	async evaluate(request: GateRequest, hostApproval: HostApproval): Promise<GateResult> {
		try {
			return await this.#evaluate(request, hostApproval);
		} catch (error) {
			const detail = error instanceof Error ? error.message : String(error);
			// The store may itself be the thing that failed, so this path must not
			// depend on it. Emergency reason only, no raw data.
			return {
				auditId: request.auditId,
				decision: "block",
				stage: "internal-error",
				risk: "uncertain",
				reason: blockReason(
					request.auditId,
					`Smart Approve failed internally and cannot prove this call is safe (${detail}).`,
					"Run /smart-approve status. Until it reports healthy, scoped calls stay blocked.",
				),
			};
		}
	}

	async #evaluate(request: GateRequest, hostApproval: HostApproval): Promise<GateResult> {
		const { resolved, store, ports } = this.#deps;
		const { config } = resolved;

		const canonicalHash = hashCanonicalCall(request.canonicalCall);
		const targetSummary = summarizeTargets(request.canonicalCall);

		// ---------------------------------------------------------------- host deny
		// OMP normally filters a denied call before `tool_call` fires. Observing one
		// means something unusual happened; preserve the denial and skip judgment.
		if (hostApproval.branch === "deny") {
			return {
				auditId: request.auditId,
				decision: "block",
				stage: "host-deny",
				risk: "policy-violation",
				reason: hostApproval.reason,
			};
		}

		// ------------------------------------------------------------- deterministic
		// Runs before scope filtering and before any model call, so a deny applies
		// even to an otherwise-skippable local read.
		const deterministic = evaluateDeterministic({
			toolName: request.toolName,
			operation: request.canonicalCall.operation,
			tier: hostApproval.tier,
			targets: request.canonicalCall.targets,
			device: request.canonicalCall.device,
			rawArguments: request.rawArguments,
			rules: this.#allRules(),
			protectedTargets: resolved.protectedTargets,
			alwaysJudge: config.scope.alwaysJudge,
			neverJudge: config.scope.neverJudge,
			judgeUnknownTools: config.scope.judgeUnknownTools,
		});

		// A deterministic block is authoritative on BOTH branches: it is the one
		// thing that hard-blocks even when OMP was going to prompt.
		if (deterministic.kind === "block") {
			this.#begin(request, canonicalHash, targetSummary, "");
			return this.#terminal(request, canonicalHash, targetSummary, {
				decision: "block",
				stage: deterministic.stage,
				risk: deterministic.risk,
				rationale: deterministic.reason,
				reason: blockReason(request.auditId, deterministic.reason, RETRY_GUIDANCE),
				...(deterministic.ruleId === undefined ? {} : { matchedRuleId: deterministic.ruleId }),
			});
		}

		// A safe local read never reaches the judge and is not worth an audit row on
		// the auto branch — but it must still be skipped rather than allowed loudly.
		if (deterministic.kind === "allow") {
			return {
				auditId: request.auditId,
				decision: "allow",
				stage: "local-read",
				risk: "uncertain",
				reason: deterministic.reason,
			};
		}

		// ------------------------------------------------------------ unsupported host
		// We could not prove what OMP would do. Blocking is the only honest answer:
		// pre-screening a call that might execute unattended is a fail-open.
		if (hostApproval.branch === "unsupported") {
			this.#begin(request, canonicalHash, targetSummary, "");
			return this.#terminal(request, canonicalHash, targetSummary, {
				decision: "block",
				stage: "unsupported-host",
				risk: "uncertain",
				rationale: hostApproval.reason,
				reason: blockReason(
					request.auditId,
					hostApproval.reason,
					"Smart Approve supports OMP 17.2.x CLI, TUI, and RPC sessions. Run /smart-approve status.",
				),
			});
		}

		// -------------------------------------------------------------- not configured
		// Fail closed until setup has run. This is checked after the deterministic
		// ladder so protected/deny still work on a fresh install.
		if (!resolved.ready) {
			const cause = resolved.notReadyReason ?? "Smart Approve is not configured.";
			if (hostApproval.branch === "prompt") {
				// OMP will still ask a human, so surface the problem and fall through
				// rather than converting a prompt into a block.
				this.#publishCard(request, canonicalHash, "uncertain", cause, targetSummary, false);
				return this.#noBlock(request, "config-invalid", cause);
			}
			this.#begin(request, canonicalHash, targetSummary, "");
			return this.#terminal(request, canonicalHash, targetSummary, {
				decision: "block",
				stage: "config-invalid",
				risk: "uncertain",
				rationale: cause,
				reason: blockReason(request.auditId, cause, "Run /smart-approve setup."),
			});
		}

		const sensitivity = this.#sensitivity(request.toolName);
		const judgeContext: JudgeContextInput = {
			tier: hostApproval.tier,
			postureHints: deterministic.postureHints,
			sensitivity,
		};

		// ------------------------------------------------------------- native prompt
		// OMP owns the only approval control here. A valid judge `block` still hard
		// blocks; everything else becomes a companion risk card and falls through to
		// OMP's single native dialog. No second approval prompt, ever.
		if (hostApproval.branch === "prompt") {
			return await this.#preScreen(request, canonicalHash, targetSummary, judgeContext);
		}

		// ------------------------------------------------------------- session bypass
		// A human deliberately turned the gate off for this session. It is audited
		// and loudly visible; the model cannot set it.
		if (this.#deps.bypassActive?.() === true) {
			this.#begin(request, canonicalHash, targetSummary, "");
			store.appendEvent({
				auditId: request.auditId,
				type: "allowed",
				detail: "session is in unguarded mode",
				actor: "human",
				at: ports.now(),
			});
			return {
				auditId: request.auditId,
				decision: "allow",
				stage: "bypass",
				risk: "uncertain",
				reason: "session is in unguarded mode",
			};
		}

		return await this.#gateAuto(request, canonicalHash, targetSummary, judgeContext);
	}

	// ------------------------------------------------------------------ auto branch

	async #gateAuto(
		request: GateRequest,
		canonicalHash: string,
		targetSummary: string,
		judgeContext: JudgeContextInput,
	): Promise<GateResult> {
		const { resolved, store, ports } = this.#deps;

		const familyKey = retryFamilyKey({
			sourceAgentId: request.sourceAgentId,
			toolName: request.toolName,
			operation: request.canonicalCall.operation,
			targets: request.canonicalCall.targets,
			risk: "uncertain",
		});

		this.#begin(request, canonicalHash, targetSummary, familyKey);

		// ----------------------------------------------------------- exact grant
		// Grant matching runs BEFORE the loop breaker so a human-approved retry is
		// admitted by its exact grant and closes the family, rather than being
		// counted as another strike against the very call the human just approved.
		const grant = store.consumeGrant(request.argumentsHash, resolved.policyHash, request.cwd, ports.now());
		if (grant) {
			store.clearFamily(familyKey);
			store.appendEvent({
				auditId: request.auditId,
				type: "allowed",
				detail: `admitted by exact grant ${grant.id} (${grant.scope}) from audit ${grant.auditId}`,
				actor: grant.createdBy,
				at: ports.now(),
			});
			return this.#terminal(request, canonicalHash, targetSummary, {
				decision: "allow",
				stage: "exact-grant",
				risk: "uncertain",
				rationale: `exact hash-bound grant ${grant.id}`,
				reason: "admitted by an exact human-approved grant",
				retryFamilyKey: familyKey,
			});
		}

		// ------------------------------------------------------ exact allow rule
		// A hand-authored allow that pins the literal call. It carries the same
		// authority as a grant and the same requirement: the exact arguments hash.
		// An allow without that hash never reaches here — it is posture only.
		const exactAllow = matchExactAllow(
			this.#allRules(),
			request.toolName,
			request.argumentsHash,
			request.canonicalCall.targets,
			request.cwd,
		);
		if (exactAllow) {
			store.clearFamily(familyKey);
			return this.#terminal(request, canonicalHash, targetSummary, {
				decision: "allow",
				stage: "exact-allow-rule",
				risk: "uncertain",
				rationale: `exact allow rule ${exactAllow.id}: ${exactAllow.reason}`,
				reason: `admitted by exact allow rule ${exactAllow.id}`,
				matchedRuleId: exactAllow.id,
				retryFamilyKey: familyKey,
			});
		}

		// --------------------------------------------------- open escalation reuse
		// A retry of a call a human is already deliberating over must not re-judge:
		// that burns a model call per retry and scatters the decision across several
		// audit IDs. Point the agent at the one open record instead.
		const reuse = this.#reuseOpenEscalation(request);
		if (reuse.kind === "await-human") {
			return this.#terminal(request, canonicalHash, targetSummary, {
				decision: "block",
				stage: "escalation",
				risk: reuse.pending.risk,
				rationale: reuse.pending.rationale,
				reason: blockReason(
					reuse.pending.auditId,
					`${reuse.pending.rationale} A human is already reviewing this exact call.`,
					`Wait for the decision, or ask the user. Review: \`/smart-approve review ${reuse.pending.auditId}\`. ${RETRY_GUIDANCE}`,
				),
				retryFamilyKey: familyKey,
				pendingAuditId: reuse.pending.auditId,
			});
		}

		// ----------------------------------------------------------- loop breaker
		// `reuse.kind === "reopen"` means an approved-intent record spent its single
		// exempt attempt, so this retry deliberately skips the strike check and goes
		// on to open a fresh dialog against the real arguments.
		const strikes = store.getStrikes(familyKey);
		if (reuse.kind !== "reopen" && strikes >= LOOP_BREAK_THRESHOLD) {
			const cause =
				`This is attempt ${strikes + 1} at the same blocked operation ` +
				`(${request.toolName} -> ${targetSummary}). Smart Approve is treating it as a retry loop.`;
			store.appendEvent({
				auditId: request.auditId,
				type: "loop-broken",
				detail: `family ${familyKey} reached ${strikes} strikes`,
				actor: "smart-approve",
				at: ports.now(),
			});
			return await this.#escalate(
				request,
				canonicalHash,
				targetSummary,
				familyKey,
				{ decision: "escalate", risk: "policy-violation", rationale: cause },
				"loop-breaker",
			);
		}

		// ------------------------------------------------------------------ judge
		const controller = new AbortController();
		const remaining = request.deadlineAt - ports.now();
		const timer = setTimeout(() => controller.abort(), Math.max(0, remaining));
		let verdict: Verdict | undefined;
		let metrics: JudgeMetrics | undefined;
		let judgeFailure: string | undefined;
		try {
			const judgeInput = this.#deps.buildJudgeInput(request, judgeContext);
			const result = await this.#deps.ports.judge(judgeInput, controller.signal);
			metrics = result.metrics;
			if (result.ok) {
				verdict = result.verdict;
			} else {
				judgeFailure = `${result.failure.kind}: ${result.failure.detail}`;
			}
		} catch (error) {
			judgeFailure = `judge threw: ${error instanceof Error ? error.message : String(error)}`;
		} finally {
			clearTimeout(timer);
		}

		// Non-binding: recorded only so a human can review it through
		// `/smart-approve apply-suggestion`. It never affects this decision.
		if (verdict?.suggestion) {
			this.#deps.recordSuggestion?.(request.auditId, verdict.suggestion);
		}

		// A judge that could not produce a valid verdict is an escalation, never an
		// allow. This covers timeout, provider error, malformed output, missing
		// model, and internal error alike.
		if (!verdict) {
			return await this.#escalate(
				request,
				canonicalHash,
				targetSummary,
				familyKey,
				{
					decision: "escalate",
					risk: "uncertain",
					rationale: judgeFailure ?? "the judge produced no verdict",
				},
				"judge-failure",
				metrics,
			);
		}

		if (verdict.decision === "allow") {
			// Per-risk sensitivity can only be resolved now: the risk class does not
			// exist until the judge answers. If the risk-specific level is stricter
			// than the posture the judge was given, this allow becomes an escalation.
			// The tightening is one-directional by construction — a permissive
			// per-risk override can never turn a block or escalate into an allow.
			const applied = effectiveSensitivity(resolved.config, request.toolName, verdict.risk);
			if (SENSITIVITY_RANK[applied] > SENSITIVITY_RANK[judgeContext.sensitivity]) {
				return await this.#escalate(
					request,
					canonicalHash,
					targetSummary,
					familyKey,
					{
						decision: "escalate",
						risk: verdict.risk,
						rationale:
							`The judge allowed this call under ${judgeContext.sensitivity} posture, but policy sets ` +
							`${applied} sensitivity for ${verdict.risk} risk, so it needs a human. ${verdict.rationale}`,
						...(verdict.suggestion === undefined ? {} : { suggestion: verdict.suggestion }),
					},
					"escalation",
					metrics,
				);
			}
			return this.#terminal(request, canonicalHash, targetSummary, {
				decision: "allow",
				stage: "judge",
				risk: verdict.risk,
				rationale: verdict.rationale,
				reason: verdict.rationale,
				retryFamilyKey: familyKey,
				...(metrics === undefined ? {} : { metrics }),
			});
		}

		if (verdict.decision === "block") {
			store.recordStrike(familyKey, request.auditId, ports.now());
			return this.#terminal(request, canonicalHash, targetSummary, {
				decision: "block",
				stage: "judge",
				risk: verdict.risk,
				rationale: verdict.rationale,
				reason: blockReason(request.auditId, verdict.rationale, RETRY_GUIDANCE),
				retryFamilyKey: familyKey,
				...(metrics === undefined ? {} : { metrics }),
			});
		}

		return await this.#escalate(request, canonicalHash, targetSummary, familyKey, verdict, "escalation", metrics);
	}

	// ---------------------------------------------------------------- prompt branch

	async #preScreen(
		request: GateRequest,
		canonicalHash: string,
		targetSummary: string,
		judgeContext: JudgeContextInput,
	): Promise<GateResult> {
		const { ports } = this.#deps;
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), Math.max(0, request.deadlineAt - ports.now()));
		let verdict: Verdict | undefined;
		let failure: string | undefined;
		try {
			const result = await ports.judge(this.#deps.buildJudgeInput(request, judgeContext), controller.signal);
			if (result.ok) verdict = result.verdict;
			else failure = `${result.failure.kind}: ${result.failure.detail}`;
		} catch (error) {
			failure = `judge threw: ${error instanceof Error ? error.message : String(error)}`;
		} finally {
			clearTimeout(timer);
		}

		if (verdict?.decision === "block") {
			this.#begin(request, canonicalHash, targetSummary, "");
			return this.#terminal(request, canonicalHash, targetSummary, {
				decision: "block",
				stage: "judge",
				risk: verdict.risk,
				rationale: verdict.rationale,
				reason: blockReason(request.auditId, verdict.rationale, RETRY_GUIDANCE),
			});
		}

		// Everything else — allow, escalate, or judge failure — becomes a card and
		// falls through. OMP's native prompt is the sole approval control, so the
		// human still decides, and they only see one dialog.
		const rationale = verdict?.rationale ?? failure ?? "the judge produced no verdict";
		this.#publishCard(
			request,
			canonicalHash,
			verdict?.risk ?? "uncertain",
			rationale,
			targetSummary,
			verdict !== undefined,
		);
		return this.#noBlock(request, "judge", rationale);
	}

	// ------------------------------------------------------------------ escalation

	/**
	 * Resolve an escalation.
	 *
	 * Always persists a durable pending record FIRST, so the human retains an entry
	 * point even if the fast path is unavailable, the handler is killed, or the
	 * process restarts. Only then is the in-handler dialog attempted, and only when
	 * a live main TUI exists and the remaining budget clears the dialog floor.
	 */
	async #escalate(
		request: GateRequest,
		canonicalHash: string,
		targetSummary: string,
		familyKey: string,
		verdict: Verdict,
		stage: GateStage,
		metrics?: JudgeMetrics,
	): Promise<GateResult> {
		const { resolved, store, ports } = this.#deps;
		const { timeouts } = resolved.config;
		const now = ports.now();
		const nonce = ports.randomNonce();

		const pending: PendingApproval = {
			auditId: request.auditId,
			toolName: request.toolName,
			operation: request.canonicalCall.operation,
			targetSummary,
			risk: verdict.risk,
			rationale: verdict.rationale,
			argumentsHash: request.argumentsHash,
			canonicalHash,
			policyHash: resolved.policyHash,
			nonce,
			sourceAgentId: request.sourceAgentId,
			...(request.parentAgentId === undefined ? {} : { parentAgentId: request.parentAgentId }),
			cwd: request.cwd,
			state: "awaiting-human",
			createdAt: now,
			expiresAt: now + timeouts.pendingApprovalTtlMs,
			exemptAttempts: 0,
		};
		store.putPending(pending);
		store.appendEvent({
			auditId: request.auditId,
			type: "escalated",
			detail: `${verdict.risk}: ${verdict.rationale}`,
			actor: "smart-approve",
			at: now,
		});

		// The literal arguments are held only in memory, under their own shorter TTL.
		// They are what makes a later approval mintable into a grant.
		broker.holdCall({
			auditId: request.auditId,
			nonce,
			frozenCall: this.#freeze(request),
			expiresAt: now + timeouts.brokerArgsTtlMs,
		});

		const decision = await this.#tryFastPath(request, verdict, nonce);

		if (decision?.choice === "allow-once") {
			store.updatePendingState(request.auditId, "approved-granted", ports.now());
			store.clearFamily(familyKey);
			store.appendEvent({
				auditId: request.auditId,
				type: "granted",
				detail: "approved in the in-handler dialog with a matching nonce",
				actor: "human",
				at: ports.now(),
			});
			broker.releaseCall(request.auditId);
			return this.#terminal(request, canonicalHash, targetSummary, {
				decision: "allow",
				stage: "escalation",
				risk: verdict.risk,
				rationale: `human approved: ${verdict.rationale}`,
				reason: "approved by a human in the approval dialog",
				retryFamilyKey: familyKey,
				...(metrics === undefined ? {} : { metrics }),
			});
		}

		if (decision?.choice === "deny") {
			store.updatePendingState(request.auditId, "denied", ports.now());
			store.recordStrike(familyKey, request.auditId, ports.now());
			store.appendEvent({
				auditId: request.auditId,
				type: "denied",
				detail: "denied in the in-handler dialog",
				actor: "human",
				at: ports.now(),
			});
			broker.releaseCall(request.auditId);
			return this.#terminal(request, canonicalHash, targetSummary, {
				decision: "block",
				stage: "escalation",
				risk: verdict.risk,
				rationale: `human denied: ${verdict.rationale}`,
				reason: blockReason(request.auditId, `A human denied this call. ${verdict.rationale}`, RETRY_GUIDANCE),
				retryFamilyKey: familyKey,
				...(metrics === undefined ? {} : { metrics }),
			});
		}

		// No trusted human answer inside the handler budget. The durable record is
		// already persisted, so the human decides out-of-band with no handler clock.
		const headless = !broker.hasHumanChannel();
		const cause = headless
			? `${verdict.rationale} No interactive main session is available to approve it.`
			: `${verdict.rationale} It needs a human decision, which does not fit in OMP's handler budget.`;
		return this.#terminal(request, canonicalHash, targetSummary, {
			decision: "block",
			stage,
			risk: verdict.risk,
			rationale: verdict.rationale,
			reason: blockReason(
				request.auditId,
				cause,
				`A human can review it with \`/smart-approve review ${request.auditId}\`. ${RETRY_GUIDANCE}`,
			),
			retryFamilyKey: familyKey,
			pendingAuditId: request.auditId,
			...(metrics === undefined ? {} : { metrics }),
		});
	}

	/**
	 * Best-effort in-handler dialog.
	 *
	 * Skipped entirely — in favor of the already-persisted async path — whenever
	 * the UI is off, no live main TUI exists, or the remaining window is below the
	 * floor. A window too short to read a literal call is worse than no window: it
	 * pressures a human into a snap decision on a security question.
	 */
	async #tryFastPath(request: GateRequest, verdict: Verdict, nonce: string) {
		const { resolved, ports } = this.#deps;
		const { timeouts, ui } = resolved.config;
		if (!ui.fastPathDialog) return undefined;
		if (!broker.hasHumanChannel()) return undefined;

		const remaining = request.deadlineAt - ports.now() - timeouts.cleanupMarginMs;
		const window = Math.min(remaining, timeouts.dialogMaxMs);
		if (window < timeouts.dialogFloorMs) return undefined;

		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), window);
		try {
			const decision = await ports.escalate(
				{
					auditId: request.auditId,
					nonce,
					frozenCall: this.#freeze(request),
					canonicalCall: request.canonicalCall,
					risk: verdict.risk,
					rationale: verdict.rationale,
					sourceAgentId: request.sourceAgentId,
					sourceAgentKind: request.sourceAgentKind,
					...(request.parentAgentId === undefined ? {} : { parentAgentId: request.parentAgentId }),
					expiresAt: ports.now() + window,
				},
				controller.signal,
			);
			if (!decision) return undefined;
			// Every dialog answer is re-validated against the held literal call, so a
			// stale, forged, or replayed response cannot unblock execution.
			const bound = broker.bindDecision(decision, ports.now());
			if (!bound.ok) return undefined;
			// Belt and braces: the bound decision must still describe this exact call.
			if (bound.decision.argumentsHash !== request.argumentsHash) return undefined;
			return bound.decision;
		} catch {
			return undefined;
		} finally {
			clearTimeout(timer);
		}
	}

	// ------------------------------------------------------------------- internals

	/**
	 * How should this retry interact with an escalation already open for the exact
	 * same call?
	 *
	 * Three outcomes, and the bounds are the whole point:
	 *
	 * - `await-human` — a human is deliberating, and this retry is inside every
	 *   bound. Suppress the strike, skip the judge, and point at the open record.
	 * - `reopen` — an `approved-intent` record spent its single exempt attempt.
	 *   The retry proceeds so a fresh dialog can be opened against real arguments.
	 * - `none` — no open record, or every bound is spent. Strikes resume and the
	 *   loop breaker fires normally.
	 *
	 * Exemption is bounded independently of how long the audit ID stays actionable.
	 * It ends at the earliest of: leaving `awaiting-human`, `strikeExemptionWindow`
	 * elapsing, or `maxExemptAttempts` being exhausted — so a human deliberating
	 * for hours never buys the agent an unbounded retry budget, even though the
	 * record itself stays reviewable for the rest of `pendingApprovalTtl`.
	 */
	#reuseOpenEscalation(
		request: GateRequest,
	): { kind: "await-human"; pending: PendingApproval } | { kind: "reopen" } | { kind: "none" } {
		const { resolved, store, ports } = this.#deps;
		const { timeouts } = resolved.config;
		const now = ports.now();

		// The retry may belong to a family whose record was opened under a different
		// audit ID, so look it up by the exact call rather than by family.
		const open = store.listOpenPending(now).find(p => p.argumentsHash === request.argumentsHash);
		if (!open) return { kind: "none" };

		if (open.state === "approved-intent") {
			return store.consumeReopen(open.auditId, now) ? { kind: "reopen" } : { kind: "none" };
		}
		if (open.state !== "awaiting-human") return { kind: "none" };
		if (now - open.createdAt > timeouts.strikeExemptionWindowMs) return { kind: "none" };
		if (open.exemptAttempts >= timeouts.maxExemptAttempts) return { kind: "none" };
		store.incrementExemptAttempts(open.auditId);
		return { kind: "await-human", pending: open };
	}

	#allRules(): PolicyRule[] {
		// Config rules plus rules a human persisted through an override.
		return [...this.#deps.resolved.rules, ...this.#deps.store.listRules()].sort(
			(a, b) => b.specificity - a.specificity,
		);
	}

	#sensitivity(toolName: string): SensitivityLevel {
		const s = this.#deps.resolved.config.sensitivity;
		return s.byTool[toolName] ?? s.fallback;
	}

	#freeze(request: GateRequest): FrozenCall {
		return {
			toolName: request.toolName,
			toolCallId: request.toolCallId,
			rawArguments: request.rawArguments,
			argumentsHash: request.argumentsHash,
			frozenAt: request.receivedAt,
		};
	}

	#begin(request: GateRequest, canonicalHash: string, targetSummary: string, familyKey: string): void {
		this.#deps.store.beginAudit({
			auditId: request.auditId,
			toolCallId: request.toolCallId,
			toolName: request.toolName,
			operation: request.canonicalCall.operation,
			targetSummary,
			argumentsHash: request.argumentsHash,
			canonicalHash,
			policyHash: this.#deps.resolved.policyHash,
			sourceAgentId: request.sourceAgentId,
			sourceAgentKind: request.sourceAgentKind,
			...(request.parentAgentId === undefined ? {} : { parentAgentId: request.parentAgentId }),
			cwd: request.cwd,
			retryFamilyKey: familyKey,
			createdAt: request.receivedAt,
		});
	}

	#publishCard(
		request: GateRequest,
		_canonicalHash: string,
		risk: RiskClass,
		rationale: string,
		targetSummary: string,
		judgeAvailable: boolean,
	): void {
		if (!this.#deps.resolved.config.ui.riskCardOnNativePrompt) return;
		this.#deps.publishRiskCard?.({
			auditId: request.auditId,
			toolName: request.toolName,
			risk,
			rationale,
			targetSummary,
			judgeAvailable,
		});
	}

	#noBlock(request: GateRequest, stage: GateStage, reason: string): GateResult {
		return { auditId: request.auditId, decision: "allow", stage, risk: "uncertain", reason };
	}

	/**
	 * Commit the terminal audit row, then return the result.
	 *
	 * A failed commit downgrades an allow to a block: running unaudited is exactly
	 * the state this plugin exists to prevent, so storage failure is a safety
	 * failure, not a logging inconvenience.
	 */
	#terminal(
		request: GateRequest,
		canonicalHash: string,
		targetSummary: string,
		outcome: {
			decision: Decision;
			stage: GateStage;
			risk: RiskClass;
			rationale: string;
			reason: string;
			matchedRuleId?: string;
			retryFamilyKey?: string;
			metrics?: JudgeMetrics;
			pendingAuditId?: string;
		},
	): GateResult {
		const { store, resolved, ports } = this.#deps;
		const record: AuditRecord = {
			auditId: request.auditId,
			toolCallId: request.toolCallId,
			toolName: request.toolName,
			operation: request.canonicalCall.operation,
			targetSummary,
			argumentsHash: request.argumentsHash,
			canonicalHash,
			policyHash: resolved.policyHash,
			sourceAgentId: request.sourceAgentId,
			sourceAgentKind: request.sourceAgentKind,
			...(request.parentAgentId === undefined ? {} : { parentAgentId: request.parentAgentId }),
			cwd: request.cwd,
			decision: outcome.decision,
			stage: outcome.stage,
			risk: outcome.risk,
			rationale: outcome.rationale,
			...(outcome.matchedRuleId === undefined ? {} : { matchedRuleId: outcome.matchedRuleId }),
			...(outcome.metrics?.model === undefined ? {} : { judgeModel: outcome.metrics.model }),
			...(outcome.metrics?.provider === undefined ? {} : { judgeProvider: outcome.metrics.provider }),
			...(outcome.metrics === undefined
				? {}
				: {
						judgeLatencyMs: outcome.metrics.latencyMs,
						judgeAttempts: outcome.metrics.attempts,
						...(outcome.metrics.inputTokens === undefined
							? {}
							: { inputTokens: outcome.metrics.inputTokens }),
						...(outcome.metrics.outputTokens === undefined
							? {}
							: { outputTokens: outcome.metrics.outputTokens }),
						...(outcome.metrics.costUsd === undefined ? {} : { costUsd: outcome.metrics.costUsd }),
					}),
			retryFamilyKey: outcome.retryFamilyKey ?? "",
			retryCount: 0,
			createdAt: request.receivedAt,
		};

		try {
			store.commitAudit(record);
		} catch (error) {
			const detail = error instanceof Error ? error.message : String(error);
			if (outcome.decision === "allow") {
				return {
					auditId: request.auditId,
					decision: "block",
					stage: "store-failure",
					risk: "uncertain",
					reason: blockReason(
						request.auditId,
						`Smart Approve could not durably record this decision (${detail}), so it will not let the call run unaudited.`,
						"Run /smart-approve status to check audit database health.",
					),
				};
			}
			// The decision was already a block; an unrecorded block is still a block.
		}

		const event: AuditEvent = {
			auditId: request.auditId,
			type: outcome.decision === "allow" ? "allowed" : "blocked",
			detail: `${outcome.stage}: ${outcome.risk}`,
			actor: "smart-approve",
			at: ports.now(),
		};
		try {
			store.appendEvent(event);
		} catch {
			// The terminal row is what matters; a missing transition event must not
			// change the decision.
		}

		return {
			auditId: request.auditId,
			decision: outcome.decision,
			stage: outcome.stage,
			risk: outcome.risk,
			reason: outcome.reason,
			...(outcome.pendingAuditId === undefined ? {} : { pendingAuditId: outcome.pendingAuditId }),
		};
	}
}
