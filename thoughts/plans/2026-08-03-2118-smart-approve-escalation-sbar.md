# Smart Approve Escalation SBAR. Implementation Plan

- date: 2026-08-03 21:18 (local), revised 21:32
- git_commit: b46328b
- branch: trunk
- repository: omp-smart-approve
- research: (inline; Current State Analysis cites sources directly)
- topic: give every escalation surface a very short SBAR (Situation / Background / Assessment / Recommendation) so an operator can decide whether to override a block without spelunking
- tags: [smart-approve, ux, escalation, ui, broker, store]
- status: implemented, awaiting human verification (phases 4 and 6)

## Overview

Early usage produced many blocks. When a block escalates to a human, the approval surfaces answer what is blocked (tool, target, hash, literal arguments) but not the three questions that decide an override: what was the agent trying to do, why was it stopped, and what happens on approval. The operator is asked to approve with forensic data and no decision support.

Fix: compose a deterministic, hard-clamped SBAR (at most 6 short lines) at escalation time from context the gate already holds. Persist its redacted ingredients on the pending record. Render it at the top of every escalation surface: the fast-path dialog, `/smart-approve review`, `/smart-approve pending`, the native-prompt risk card, and a new one-line notification when an async escalation opens. Today the user gets no live signal at all for async escalations; the only hint is the agent's blocked tool result.

Copy rule, applied to every rendered line this plan adds or touches: complete sentences that end in periods. No em dashes. No separator glyphs such as "·" or "->" inside sentences. Parentheses only for short labels such as "(stated this turn)". A rendering test enforces this so it cannot regress.

## Coverage: which block classes get an SBAR

An SBAR exists only where a human decision is requested, which requires a pending escalation record.

- Covered: judge escalations, posture-clamp escalations, judge-failure escalations, loop-breaker escalations, and the native-prompt risk card (live context; no pending record involved).
- Not covered, by design: deterministic deny rules, protected-target hits, judge hard blocks, no-judge-configured blocks, unsupported-host blocks, and store-failure blocks. These create no pending record, request no approval, and cannot be overridden today because `runOverride` requires a pending record (`src/commands.ts:730-735`). They keep the existing one-line `blockReason` unchanged.

If those uncovered classes turn out to be a meaningful share of the blocks users actually hit, extending context into the judge hard-block reason is a small separate follow-up. Decide that outside this plan.

## Current State Analysis

What a human sees today, per surface:

- Fast-path dialog (`src/ui.ts:117-143`, `renderApprovalRequest`): audit ID, source agent, tool, operation, destination, risk class, one unlabeled judge sentence, call hash, expiry, literal JSON arguments, and the deny-default footer. Nothing about what the user asked or what the agent said it was doing.
- Async path, which dominates. `#tryFastPath` skips whenever there is no live main TUI or the remaining window is under `dialogFloorMs` (`src/gate.ts:735-743`), and config warns that escalation is always asynchronous when the fast path is structurally unreachable (`src/config.ts:854-858`). The agent's tool result carries the block reason (`src/gate.ts:120-122, 716-720`). The human's entry points are `/smart-approve pending` (`src/ui.ts:244-271`; rows of id, tool, target, risk, age, ttl) and `/smart-approve review` (`src/ui.ts:436-531`; a thorough forensic dump whose only "why" is the same one-line rationale). No mid-session notification exists when a pending opens; the only pending notify runs at session start (`src/index.ts:404-408`).
- Native-prompt companion card (`src/ui.ts:224-234`, `renderRiskCard`): risk and finding only.

What the gate already knows but never shows a human:

- Commit b46328b built exactly the needed capture: redacted `userIntent` (user turns, user-invoked skills, collab prompts, session-start seeding) and `agentRationale` with a `rationaleFreshness` label (`current-turn`, `previous-turn`, `none`) and a `rationaleFromReasoning` flag. See `src/context.ts:352-353, 601-635` and `src/contracts.ts:209-219`. These flow only into the judge prompt. `EscalationRequest` (`src/contracts.ts:397-409`) and `PendingApproval` (`src/contracts.ts:357-381`) carry neither, so no renderer can show them, and after `brokerArgsTtl` the durable record cannot reconstruct them.
- All four `#escalate` callsites sit in `#gateAuto` (`src/gate.ts:440, 482, 505, 546`), where `judgeContext: JudgeContextInput` is in scope. But `JudgeContextInput` is only `{ tier, postureHints, sensitivity }` (`src/gate.ts:92-95`). Intent and rationale live behind the injected `buildJudgeInput` seam (`src/gate.ts:79`, wired in `src/index.ts` with the tracker closure).
- Escalation stages that never produce a judge verdict still need decision support: loop breaker (`src/gate.ts:440-447`), judge failure (`:482-494`), posture clamp (`:505-520`).
- Retries of a call already under review reuse the open record (`src/gate.ts:403-421`; `#reuseOpenEscalation` at `:799`), so per-escalation surfaces fire once per decision, not once per retry.

Adjacent defect observed, flagged for a separate fix: a protected-target block advertises `/smart-approve override` (`src/policy.ts:1027-1029`), but deterministic blocks never create a pending record and `runOverride` requires one (`src/commands.ts:730-735`). That hint is currently a dead end.

## Desired End State

- Every escalation surface leads with a compact SBAR of complete sentences:

  ```
  S  Held for your decision: bash `git push --force` targeting origin/main. Risk: data-destruction.
  B  You asked: "clean up the branch history".
     Agent's reason: "force-pushing the rebased branch" (stated this turn).
  A  Flagged by the judge: rewrites remote history that the user did not clearly request.
  R  Deny unless this matches what you asked for. Approving runs this exact call once, then re-locks.
  ```

- Empty channels render as explicit signal, never blank: "No user request was captured this session." and "The agent stated no reason for this call." An agent acting with no captured request is itself decision-relevant.
- Freshness is always labeled: "(stated this turn)", "(may predate this call)", "(from private reasoning, this turn)".
- The Recommendation line is deterministic and stage-keyed, never model-authored text.
- The SBAR ingredients are persisted (redacted, clamped) on the pending record, so review and pending render it after a restart. Legacy rows say "(recorded before context capture)".
- When an escalation resolves asynchronously, the main session gets one notify line: the situation plus the review command. Headless sessions no-op.
- Literal arguments, hash binding, and the deny-default footer are untouched. SBAR is additive decision support above the existing ground truth.

## What We're NOT Doing

- No judge-authored SBAR and no new model calls. Rejected because: (a) judge-failure and loop-breaker escalations, the most confusing ones, have no judge output to draw on; (b) a model-authored Recommendation acted on by a human is a prompt-injection laundering channel, since tool arguments are attacker-influenceable evidence; (c) it costs tokens and latency on every escalation; (d) deterministic clamps are the only way to guarantee "very short". The judge's existing 1-3 sentence rationale becomes the Assessment line; everything else is composed from deterministic state.
- No judge prompt, schema, or eval-corpus changes (`eval/` untouched).
- No change to the agent-facing `blockReason` text or `RETRY_GUIDANCE`. The consequence is spelled out in the Coverage section: deny-rule, protected-target, judge hard-block, no-judge-configured, unsupported-host, and store-failure blocks keep the existing one-line reason and get no SBAR.
- Not persisting raw arguments or anything beyond clamped, already-redacted one-liners. Store rule 2 (`src/store.ts:11-14`) stands; `guardWrite` screens the new columns.
- Not making deterministic hard blocks overridable, and not fixing the stale override hint at `src/policy.ts:1029`. Flagged above as a separate follow-up.
- Not adding a second approval control anywhere. OMP's native prompt remains the only control on the prompt branch.

## Implementation Approach

Compose deterministically at escalation time; persist ingredients, not prose. A new `EscalationContext` (clamped intent, rationale, freshness, plus `flaggedBy`) is built by `src/context.ts`, the single owner of capture semantics, so freshness logic cannot drift from `buildJudgeInput`. It is injected into the gate beside `buildJudgeInput`, threaded into the escalation request, the pending record, and the risk card, and rendered by one shared `renderSbar` helper in `src/ui.ts`. A small optional broker capability delivers the one-line async notification to the main session.

Hard conciseness budgets (named constants, single-line clamp): intent at most 160 chars, agent rationale at most 200, assessment at most 220, target summary at most 200 (`DISPLAY_SUMMARY_MAX`, applied at render only). SBAR is 5 renderer rows, or 1 for a record that predates context capture. Notification is exactly 1 string.

**As-built correction.** "Rows" means logical strings handed to the terminal, not visual screen lines. Visual wrapping depends on the reader's terminal width, which the process cannot know: the Recommendation sentence alone wraps below roughly 100 columns. What is enforced is that no agent- or judge-supplied value can add a row, via escaping every control character it may contain. No claim is made, anywhere, about where text lands on a screen.

---

## Phase 1: `EscalationContext` contract and builder [COMPLETE]

**Files:** `src/contracts.ts`, `src/context.ts`; tests in `test/context.test.ts`.

**Changes:**
1. `src/contracts.ts`: add
   ```ts
   export type EscalationFlaggedBy = "judge" | "judge-failure" | "loop-breaker";
   export interface EscalationContext {
     /** Redacted, one line, at most 160 chars. Empty string means nothing was captured this session. */
     userIntent: string;
     /** Redacted, one line, at most 200 chars. Empty string means no stated reason. */
     agentRationale: string;
     rationaleFreshness: RationaleFreshness;
     rationaleFromReasoning: boolean;
     flaggedBy: EscalationFlaggedBy;
   }
   ```
   Extend `EscalationRequest` with required `context: EscalationContext`, `PendingApproval` with optional `context?: EscalationContext` (legacy rows), and `RiskCard` with optional `context?: Omit<EscalationContext, "flaggedBy">`.
2. `src/context.ts`: export `buildEscalationContext(tracker: ProvenanceTracker): Omit<EscalationContext, "flaggedBy">`. It reuses `latestUserIntent()` plus `rationaleView()` (the same sources as `buildJudgeInput`, `src/context.ts:603-613`) and applies the `oneLine` clamp with new exported constants `SBAR_INTENT_MAX = 160` and `SBAR_RATIONALE_MAX = 200`. No evidence fencing; this text is for human display, not the judge.

**Agent verification:**
- New tests: clamping at both budgets; whitespace collapsed to one line; empty tracker yields empty strings with `freshness: "none"`; values match what `buildJudgeInput` reports for the same tracker state (drift guard).
- [x] `bun test test/context.test.ts` green (44 pass).

**Human verification:** None.

## Phase 2: Persist context on pending records [COMPLETE]

**Files:** `src/store.ts`; tests in `test/store.test.ts`, `test/audit-redaction.test.ts`.

**Changes:**
1. Additive nullable columns on `pending_approvals`, following the `cwd` migration precedent (`src/store.ts:306-312`): `ctx_user_intent TEXT`, `ctx_agent_rationale TEXT`, `ctx_rationale_freshness TEXT`, `ctx_rationale_from_reasoning INTEGER`, `ctx_flagged_by TEXT`.
2. `putPending` writes them when `pending.context` is present. The row mapper hydrates `context` all-or-nothing, keyed on `ctx_flagged_by IS NOT NULL`, so a legacy row reads back with `context: undefined` and never a half-filled object.
3. `guardWrite` screens the two new text fields exactly like `rationale` and `targetSummary`. They arrive pre-redacted from the tracker; screening is belt and braces.

**Agent verification:**
- Round-trip test (put, then get and list) with and without context; migration test opening a pre-existing database created without the columns; redaction-guard test proving an unredacted-shaped value in either text field throws `StoreRedactionError`.
- [x] `bun test test/store.test.ts test/audit-redaction.test.ts` green (69 pass).

**Human verification:** None.

## Phase 3: Thread context through the gate [COMPLETE]

**Files:** `src/gate.ts`, `src/index.ts`; tests in `test/gate.test.ts`.

**Changes:**
1. `GateDeps` gains `buildEscalationContext(): Omit<EscalationContext, "flaggedBy">` beside `buildJudgeInput` (`src/gate.ts:79`); wire it in `src/index.ts` from the same tracker closure.
2. `#escalate` (`src/gate.ts:608`) builds the full context once: the dep result plus `flaggedBy` mapped from its `stage` parameter (`"loop-breaker"` maps to `"loop-breaker"`, `"judge-failure"` to `"judge-failure"`, `"escalation"` to `"judge"`). It stores the context on the pending record (`:622-640`) and passes it into the `EscalationRequest` built in `#tryFastPath` (`:748-760`; add a context parameter).
3. `#preScreen` attaches the builder result to the risk card it publishes, so the native-prompt branch gets the Background lines too.

**Agent verification:**
- Gate tests: every escalation stage (loop breaker, judge failure, posture clamp, judge escalate) persists a pending record whose `context.flaggedBy` matches; the fast-path presenter receives the same context; the risk card carries context on the prompt branch; retries reusing an open escalation (`:403-421`) do not write a second record (existing behavior, asserted unchanged).
- [x] `bun test test/gate.test.ts` green (83 pass), with `test/deadline.test.ts` (10 pass) updated for the new dep.

**Human verification:** None.

## Phase 4: `renderSbar` and all reading surfaces [COMPLETE, pending human wording check]

**Files:** `src/ui.ts`, `src/commands.ts`; tests in `test/ui-state.test.ts`, `test/commands.test.ts`.

**Changes:**
1. New pure helper in `src/ui.ts`:
   ```ts
   export function renderSbar(input: {
     toolName: string; operation: string; targetSummary: string;
     risk: RiskClass; rationale: string; context?: EscalationContext;
   }): string[]
   ```
   Line templates, all complete sentences:
   - S: `Held for your decision: <tool> <operation> targeting <targetSummary>. Risk: <risk>.`
   - B, line 1: `You asked: "<intent>".` or `No user request was captured this session.`
   - B, line 2: `Agent's reason: "<reason>" (<freshness label>).` or `The agent stated no reason for this call.` The label reads `stated this turn`, `may predate this call`, or `from private reasoning, this turn`.
   - A: `Flagged by the judge: <rationale clamped to 220 chars>.` or `The judge never screened this call: <failure detail>.` or `Flagged by the retry loop breaker: <rationale>.`
   - R, keyed on `flaggedBy`:
     - judge: `Deny unless this matches what you asked for. Approving runs this exact call once, then re-locks.`
     - judge-failure: `The judge did not screen this call. Approve only if you can verify the literal arguments yourself.`
     - loop-breaker: `The agent has retried this operation repeatedly. Deny unless you explicitly want it, and consider steering the agent.`
   - Context absent entirely: one line, `(recorded before context capture)`, matching the parenthetical style of the existing legacy-cwd placeholder (`src/ui.ts:453`).
2. `renderApprovalRequest` (`src/ui.ts:117-143`): insert the SBAR block directly under the title. Keep every existing line (hash, expiry, literal arguments, deny-default footer). The full rationale remains on its `Judge:` line, so the clamped A line loses nothing.
3. `renderReview` (`:436-531`): SBAR block right under the header, built from `pending.context` plus the pending or record rationale.
4. `renderPendingList` (`:244-271`): one added row per record: `asked: "<intent>"`, or `asked: (no user request captured)` when context exists with empty intent. Omitted for legacy rows.
5. `renderRiskCard` (`:224-234`): add the two B lines when `card.context` is present.
6. Copy sweep of the five touched surfaces: rewrite existing rendered lines that stitch clauses with em dashes (for example `src/ui.ts:265, 340, 378, 453`) into plain sentences, and update the tests that pin those strings (`test/ui-state.test.ts:427, 762` and similar). Scope stays inside the `src/ui.ts` rendering functions this plan already edits. Deviation: `:340` and `:378` are inside `renderStatus`, which is not one of the five surfaces and is not covered by the item 7 guard, so its em dashes are left alone. Swept instead: `:119`, `:139`, `:226`, `:230`, `:265`, `:437`, `:453`, `:469`, `:483`, `:516`.
7. Add a rendering test asserting no rendered SBAR, dialog, pending, review, or risk-card line contains an em dash or a "·". This pins the copy rule.
8. `src/commands.ts` `runReview` (`:599-618`): confirm the pending record it already passes through reaches `ReviewInput` unchanged; no shape change expected.

**Agent verification:**
- `ui-state.test.ts`: SBAR ordering and all placeholder and freshness variants; clamping; legacy-row wording; the approval view still contains the literal-arguments header line and deny-default footer verbatim (existing assertions at `test/ui-state.test.ts:322-356` stay green); pending list `asked:` row; risk card B lines; the no-em-dash guard.
- `commands.test.ts`: `review` output contains the SBAR for a context-bearing pending and the legacy placeholder for one without.
- [x] `bun test test/ui-state.test.ts test/commands.test.ts` green (64 and 118 pass).

**Human verification:** Skim one rendered dialog and one `review` output (pasted in the PR) for tone and length. Wording judgment only.

## Phase 5: Live one-line notification for async escalations [COMPLETE]

**Files:** `src/broker.ts`, `src/index.ts`, `src/gate.ts`; tests in `test/broker.test.ts`, `test/extension.test.ts`.

**Changes:**
1. `BrokerEndpoint` gains optional `notifyPending?(line: string): void`. New `notifyHuman(line: string): boolean` in `src/broker.ts` delivers to `humanEndpoint()` and reports whether anyone heard. A throwing notify is swallowed; it can never affect the verdict.
2. `src/index.ts`: the main session's `registerEndpoint` call (`:393`) supplies `notifyPending: line => ctx.ui.notify(line, "warning")`.
3. `src/gate.ts` `#escalate`: when `#tryFastPath` returns no decision (the async fall-through at `:705`), emit exactly one line: `Smart Approve held a <tool> call targeting <targetSummary>. Risk: <risk>. Decide with /smart-approve review <auditId>.` This fires once per escalation by construction, because retries reuse the open record and never reach `#escalate`.

**Agent verification:**
- Broker tests: delivery to the main endpoint; no-op when headless; a subagent-origin escalation notifies the main session; a thrown notify is swallowed.
- Gate and extension tests: notify fires on the async path, not when the dialog resolved (allow or deny), and not on reused open escalations.
- [x] `bun test test/broker.test.ts test/extension.test.ts test/gate.test.ts` green (41, 52, 92 pass).

**Human verification:** None.

## Phase 6: Docs, smoke, full verification [COMPLETE, pending human end-to-end check]

**Files:** `README.md`, `CHANGELOG.md`, `docs/fact-coverage.md` (check only), `scripts/smoke.ts`.

**Changes:**
1. README: update the escalation and review walkthrough with the SBAR block, the copy rule, the coverage statement (which block classes get an SBAR and which keep the one-line reason), and the new notification line.
2. CHANGELOG entry under Unreleased.
3. `docs/fact-coverage.md`: confirmed unchanged. `test/fact-citations.test.ts` stays green with no edits. Fact 23 ("interactive escalation shows the literal call, source agent, rationale, risk, and policy") is not weakened: the SBAR is inserted above those lines and every one of them still renders, asserted by `test/ui-state.test.ts` "leads with the SBAR block, above the forensic detail it does not replace".
4. `scripts/smoke.ts`: extend the escalation scenario to assert the SBAR lines appear in the dialog body and the notify line fires on the async path.

**Agent verification:**
- [x] `bun run check` (tsc plus biome) clean, `bun test` green (1085 pass, 20 files), `bun run smoke` green (19/19 scenarios).
- [x] Hardening beyond the plan. All of these are pre-existing or self-inflicted defects found while defending the plan's own budgets; each has a regression verified to fail with its fix removed.
  - **Row forgery via target.** A newline-bearing tool argument split the SBAR and the notification, putting a fake `R  ` recommendation ABOVE the real one. `summarizeTargets` escapes cursor-moving characters; renderers escape again for records persisted by an earlier build.
  - **Flooding via target.** `DISPLAY_SUMMARY_MAX` and `displaySummary` clamp head-and-tail with an honest marker, at render only. The durable record keeps the full summary: literal arguments never reach disk, so it is the sole lasting answer to which targets were named.
  - **`override` asked before it showed.** It built a verdict block and then called `ui.select` without it. It now publishes `WIDGET_OVERRIDE` before the chooser and clears it in a `finally`, mirroring `createApprovalPresenter`.
  - **Control characters past `\s`.** JavaScript's `\s` matches none of ESC, BEL, backspace, or C1 NEL, so Background, Assessment, and every rationale line leaked terminal controls. `escapeControls` now runs at every decision surface, including the `apply-suggestion` and `rules revoke` confirms, which authorize a policy change.
  - **`operation` is agent-controlled.** `operationFor` returns `${toolName}:${args.action}`, so it is not a closed enum. Raw, it forged an SBAR row, and in the judge prompt it forged a fake `## AUTHORITATIVE POLICY` section on a bare `key: value` line outside every evidence fence. Now JSON-quoted, delimiter-neutralized, and bounded by `SCALAR_FIELD_MAX` in the prompt, and clamped by `displaySummary` on every display surface.
  - **Unbounded `operation` bypassed the arguments budget.** A 200 KB `action` produced a 201 KB judge prompt while `buildArgumentsView` reported two bytes, defeating the one mechanism that bounds the request and inviting a judge failure that escalates anyway.
  - **Targets bypassed the arguments budget.** Targets are extracted from the arguments but rendered outside `argumentsView`, so one 60 KB `path` added ~120 KB to the prompt as `requested` plus `resolved`, and `paths[]` multiplied it per entry. Worse, a 60 KB path sits under `MAX_PRESERVED_FIELD_BYTES`, so the arguments view kept it whole and `incompleteCriticalContext` stayed **false**: the judge could answer `allow` on a 181 KB request. `buildJudgeInput` now caps target count and per-value length, reports `omittedTargets` on the contract, renders an omission marker, and forces `incompleteCriticalContext` whenever anything was hidden, so `allow` becomes unavailable. Targets section: 120 KB to 1.1 KB.
  - **Canonical values are never touched.** Rule matching, retry-family hashing, and the audit row still see raw `operation`, raw rule `target`, and the full `targetSummary`. Only projections are escaped, quoted, or clamped.
  - Not claimed: anything about visual screen rows, or that the summary identifies every target of a call. Wrapping depends on the reader's terminal width, which this process cannot know; and the summary still lists at most four targets.
  - **Prompt-size ceiling added; aggregate budget deferred to [#5](https://github.com/andrew-nguyen/omp-smart-approve/issues/5).** Nothing bounded the assembled prompt in aggregate: `buildArgumentsView` exempts nine preserved field names at up to 64 KB each, measured at 545,981 bytes. `judge.maxPromptBytes` (96 KB default) now refuses such a request before sending it, as a non-retryable `input-too-large` failure that escalates like any other. That is a backstop, not a fix. The per-field allowance is deliberate, because a judge that cannot see the whole `command` it is judging is worse than a large prompt, so the real budget question is a design decision and is filed rather than guessed at.

**Human verification:** Trigger one real block in a live session (any judge-escalated call) and confirm the notification and the `review` SBAR read well end to end. This is UX judgment on real content, which the harness cannot supply.
