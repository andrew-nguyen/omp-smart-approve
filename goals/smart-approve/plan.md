# OMP Smart Approval Implementation Plan

**Goal:** Ship a release-ready, locally installable OMP plugin that semantically gates tool calls OMP would otherwise auto-approve, hard-blocking clear attacks and dangerous mistakes, escalating uncertainty to a human, and leaving OMP's native approval dialog as the only prompt for calls OMP already requires a human to review.

**Execution method:** Implement test-first. For every behavior task below, add the named failing tests, run the focused test command and observe the expected failure, implement only enough production code to satisfy the contract, then rerun that focused command. Do not weaken assertions to make implementation pass.

## Solution approach

Use one extension entry point and a small set of deep modules:

1. A **host adapter** resolves the live OMP tool and effective approval policy for each `tool_call` by matching `ctx.sessionManager` to the public `AgentRegistry`, reading the session's live `settings`, and calling OMP's public argument-aware `resolveApproval(...)` function.
2. A **deterministic policy layer** runs before any model call: protected-policy-file rules, canonical target extraction, exact grants, deny rules, scoped sensitive-read detection, and oversized-argument checks.
3. A **stateless judge** receives a redacted, provenance-aware snapshot in a fresh direct provider request. It returns one strict structured verdict: `allow`, `escalate`, or `block`.
4. An **orchestrator** combines host policy, deterministic policy, judge verdicts, deadlines, retry-family state, and audit durability. Every failure defaults to escalation, and escalation is asynchronous by default: the handler returns an audited pending block and the human decides out-of-band; an in-handler dialog is only a best-effort fast path when a live main TUI and leftover budget allow.
5. A **main-session approval broker** uses process-global module state so subagent extension instances can post a frozen pending call to the main extension instance. The main TUI renders the literal call and returns a nonce-bound, single-use decision — in the fast-path dialog or later from pending-approval review — without asking an agent to paraphrase it. Approval authority always requires the literal frozen arguments.
6. A **local SQLite store** persists compact redacted decisions, durable pending approvals, exact grants, deny/posture rules, retry families, override history, and latency/cost aggregates. Raw arguments exist only in memory for the pending call and are never persisted.

The plugin does not modify OMP source. The host-specific approval classifier is isolated behind one interface so a future public `ToolCallEvent.resolvedApproval` field can replace it without changing policy or judge code.

## Validated OMP host contracts

The plan relies on these verified OMP 17.2.2 behaviors:

- A plugin package declares `omp.extensions`; `omp plugin link .` symlinks the package into OMP's plugin tree and records it in `omp-plugins.lock.json`.
- `tool_call` fires after tool arguments are normalized but before OMP's native approval gate. Returning `{ block: true, reason }` prevents execution; returning no block allows native approval to continue.
- OMP's tool wrapper computes native approval with `resolveApproval(tool, args, mode, ...)`; `AgentSession.settings`, `Agent.state.tools`, `Agent.state.messages`, `AgentRegistry`, and `resolveApproval` are public package exports.
- OMP applies `--auto-approve` and `--yolo` to live session settings before tools execute, so the host adapter sees standard CLI/TUI/RPC overrides through `settings.get("tools.approvalMode")`.
- OMP hard-caps a `tool_call` handler at 30 seconds. Smart Approve therefore sizes its stricter self-deadline for judge attempts plus cleanup only, and resolves human escalation asynchronously so a human decision never races the handler budget.
- OMP already obfuscates configured secrets before provider calls and exports `SecretObfuscator` plus `obfuscateToolArguments(...)`; Smart Approve reuses that machinery before its independent judge request.
- A direct judge call can use OMP's authenticated `ModelRegistry`, `streamSimple`, and `completeSimple` APIs with a unique `sessionId`/`promptCacheKey` and `statefulResponses: false`.
- Subagents receive the discovered extension path and create separate extension instances in the same process. A broker stored under `Symbol.for(...)` is therefore shared even when Bun imports the extension through separate cache-busted module URLs.
- Interactive extension dialogs are serialized by OMP's UI controller. Headless extension UI methods return safe empty values; Smart Approve treats those as unavailable, never as approval.
- OMP's native approval prompt already renders the literal tool call. Smart Approve can add a companion risk widget for pre-screened native prompts without opening a second approval dialog.

**Supported host surface for v1:** OMP 17.2.x CLI/TUI/RPC sessions and their in-process task subagents. If the live session/tool cannot be resolved, or an embedded SDK host bypasses settings through an unobservable private `autoApprove` constructor option, the plugin blocks the scoped call with an explicit unsupported-host reason rather than guessing.

## Proposed file map

| Path | Responsibility |
| --- | --- |
| `package.json`, `tsconfig.json`, `biome.json`, `LICENSE` | Package identity, OMP manifest, scripts, compatibility, formatting/type-checking |
| `src/index.ts` | Default plugin export and testable factory |
| `src/contracts.ts` | Verdict, risk, policy, call, audit, and port types |
| `src/config.ts` | Layered config/policy discovery, validation, protected paths, deadlines |
| `src/policy.ts` | Canonicalization, target extraction, scope classification, deterministic rules/scanners |
| `src/context.ts` | Redaction, provenance tracker, bounded primary-session snapshot, prompt assembly |
| `src/store.ts` | SQLite schema, audit/event writes, rules, grants, retry families, aggregates |
| `src/judge.ts` | Model selection, auth checks, strict prompt/result contract, retries, timing/cost |
| `src/host.ts` | OMP-specific live session lookup and native approval classification |
| `src/gate.ts` | Side-effect ordering and end-to-end decision orchestration |
| `src/broker.ts` | Process-global main/subagent escalation broker and nonce/TTL state machine |
| `src/ui.ts` | Full-call approval component, prompt risk card, status and review renderers |
| `src/commands.ts` | Setup, status, rules, review, override, bypass, and re-enable commands |
| `test/**/*.test.ts` | Deterministic unit, integration, host-contract, and UI-state tests |
| `eval/cases.jsonl`, `eval/run.ts`, `eval/schema.ts` | Versioned adversarial/benign corpus and machine-readable live-eval reports |
| `scripts/smoke.ts` | Isolated local package-link/load/enforcement smoke scenario |
| `examples/` and `README.md` | Installation, setup, policy/config examples, operation, and troubleshooting |

## Core contracts

Keep the boundary types small and closed:

```ts
export type Verdict =
  | { decision: "allow"; risk: RiskClass; rationale: string; suggestion?: RuleSuggestion }
  | { decision: "escalate"; risk: RiskClass; rationale: string; suggestion?: RuleSuggestion }
  | { decision: "block"; risk: RiskClass; rationale: string; suggestion?: RuleSuggestion };

export type RiskClass =
  | "prompt-injection"
  | "exfiltration"
  | "destructive-action"
  | "wrong-target"
  | "policy-violation"
  | "safety-tampering"
  | "uncertain";

export interface GateRequest {
  auditId: string;
  toolCallId: string;
  toolName: string;
  sourceAgentId: string;
  canonicalCall: CanonicalCall;
  rawArguments: Readonly<Record<string, unknown>>;
  argumentsHash: string;
  receivedAt: number;
  deadlineAt: number;
}

export interface HostApproval {
  branch: "auto" | "prompt";
  policy: "allow" | "deny" | "prompt";
  tier: "read" | "write" | "exec";
  reason: string;
}

export interface GatePorts {
  classifyHostApproval(request: GateRequest): Promise<HostApproval>;
  judge(input: JudgeInput, signal: AbortSignal): Promise<JudgeResult>;
  escalate(request: EscalationRequest, signal: AbortSignal): Promise<HumanDecision | undefined>;
  now(): number;
  randomNonce(): string;
}
```

`GateRequest.rawArguments` is frozen, lives only for the active call, and is dropped after the result. Persistence functions accept only redacted/canonical audit DTOs, not `GateRequest`, making accidental raw-argument storage a type error.

## Ordered implementation steps

### 1. Establish the package and OMP compatibility boundary

**Create:** `package.json`, `tsconfig.json`, `biome.json`, `LICENSE`, `src/index.ts`, `test/package.test.ts`

1. Define package name `omp-smart-approve`, ESM output, `files` allowlist, MIT license, and a single `omp.extensions` entry pointing at `src/index.ts` so local linking works without a build step.
2. Add `@oh-my-pi/pi-coding-agent` as a peer dependency constrained to `>=17.2.2 <18`; add the same version as a dev dependency. Add `@oh-my-pi/pi-ai`, `zod`, and a YAML parser only when not already available through the peer package's public surface.
3. Add scripts: `check`, `test`, `smoke`, `eval:live`, and `pack:check`. Ordinary CI must never require provider credentials.
4. Export a default extension factory and a named `createSmartApproveExtension(dependencies?)` seam. Only tests and the local smoke harness inject ports; the default export always constructs real OMP-backed dependencies.
5. Test manifest shape, peer range, public entry import, absence of runtime test dependencies, and dry-run package contents.

**Focused verification:**

```bash
bun install
bun test test/package.test.ts
bun run check
bun pm pack --dry-run
```

Expected evidence: the package imports under Bun, the manifest exposes exactly one extension, and the pack list contains source/runtime files, README/examples, facts/plan references only where intended, and no test fixtures, local databases, credentials, or generated live-eval reports.

### 2. Define configuration, policy discovery, and the deadline invariant

**Create:** `src/contracts.ts`, `src/config.ts`, `test/config.test.ts`, `test/fixtures/config/**`

1. Define a strict versioned config schema with these top-level sections: `judge`, `scope`, `sensitivity`, `rules`, `audit`, `timeouts`, and `ui`. Reject unknown keys so misspelled security settings cannot silently weaken the gate.
2. Use these defaults:
   - scoped tools: write/exec plus arbitrary network egress;
   - target latency: 5 seconds;
   - model attempt timeout: 10 seconds;
   - one retry for transient provider failures only;
   - escalation fast-path dialog: best-effort only, window `min(remaining budget - cleanup, 20s cap)`, skipped entirely below a 10-second floor so a window too short to read a literal call is never presented;
   - `brokerArgsTtl` (in-memory literal arguments, gates whether a grant can be minted): 10 minutes, dies with the process;
   - `pendingApprovalTtl` (durable redacted record, gates whether an audit ID is actionable at all): 24 hours, single-use;
   - `strikeExemptionWindow` (how long a pending record suppresses loop-breaker strikes): 10 minutes;
   - `maxExemptAttempts` (retries a pending record may absorb before strikes resume): 10;
   - handler self-deadline: 28 seconds;
   - no judge cache;
   - no authorized judge provider/model until explicit setup.
3. Enforce at load time:

   ```text
   attempts × modelTimeout + 1 second cleanup margin
   <= min(handlerSelfDeadline, 29 seconds)
   ```

   The escalation dialog never extends the deadline; it only consumes leftover budget after the judge, and below the floor it is skipped in favor of the asynchronous pending path. The two TTLs are independent by design: the durable record holds no raw arguments, so it stays actionable long after the in-memory arguments are evicted — expiring them together would make the intent-to-approve path unreachable in exactly the restart case it exists to serve. Invalid timing combinations fail closed with the exact invalid fields and a setup command; they are never clamped silently.
4. Discover config in deterministic precedence order: built-in defaults < user config < project config. Resolve policy documents from ancestor directories, user agent directory, and leaf project directory, with nearer files overriding only the rule IDs they explicitly redefine.
5. Recognize `SMART_APPROVE.md`, `.omp/SMART_APPROVE.md`, `smart-approve.yml`, and the plugin's SQLite state path as protected policy surfaces. Project deny rules may add restrictions; only explicit local configuration can relax default scope/sensitivity.
6. Return one immutable `ResolvedConfig` carrying source paths, content hashes, precedence trace, protected targets, and a versioned `policyHash` used by grants and audits.

**Focused verification:**

```bash
bun test test/config.test.ts
```

Required cases: zero-config fail-closed state, user/project precedence, leaf policy overrides by rule ID, malformed YAML, unknown key, missing provider, exact protected-path detection, symlink/`..` normalization, invalid timeout budget, independent validation of both TTLs, `brokerArgsTtl > pendingApprovalTtl` rejected as incoherent, worst-case judge spend leaving a sub-floor window so the dialog is skipped in favor of the async path, a configuration whose fast path is structurally unreachable surfacing a status warning rather than silently degrading, and a valid 2 × 10s + 1s budget under the 28s deadline.

### 3. Build deterministic call canonicalization, scope, and rule evaluation

**Create:** `src/policy.ts`, `test/policy.test.ts`, `test/scanners.test.ts`

1. Canonicalize JSON deterministically: Unicode-normalize strings, sort object keys, preserve array order, distinguish number/string/boolean/null, and hash the complete canonical bytes with SHA-256. No size-based truncation occurs before hashing.
2. Extract targets without executing or expanding shell content:
   - `path`, `_path`, and every `paths[]` entry for file tools;
   - command executable/operation and obvious literal operands for `bash`/`exec`;
   - URL host/path and request method for network-capable reads/browser actions;
   - MCP server/tool plus destination-like fields for MCP calls;
   - nested `xd://` device name and payload shape while preserving the parent `xdev` call relationship.
3. Normalize filesystem targets against `ctx.cwd`, retain both requested and resolved paths, and mark unresolved/dynamic targets rather than guessing. A scoped write with an unresolved target cannot match an allow rule.
4. Classify tool scope from the resolved live OMP tool tier plus arguments. Local `read`/`grep`/`glob` skip the model after deny/protected checks; remote URLs, browser/network actions, execution, mutation, and every unknown custom/MCP tool are scoped.
5. Implement deterministic precedence:

   ```text
   protected-policy write or matching deny rule -> block
   exact unexpired allow grant with same policy/config hash -> allow
   obvious-sensitive-content check -> block
   safe unscoped local read -> allow
   otherwise -> judge
   ```

6. Support exact deny rules and human-authored glob/regex deny or posture rules. Allow rules containing any wildcard/regex/capture/omitted argument are `allow-pattern` posture hints only and can never skip the judge. Only a complete exact canonical call can be an `allow-exact` grant.
7. Add cheap deterministic sensitive-read checks for configured environment names, OMP credential placeholder/token shapes, credential files, private key material, and protected policy files. Treat high-entropy text alone as an escalation signal, not a hard block, to avoid blocking ordinary generated IDs.
8. Make rule specificity deterministic: exact call > exact tool+operation+target > risk-category override > tool override > global fallback; deny beats allow at equal specificity.

**Focused verification:**

```bash
bun test test/policy.test.ts test/scanners.test.ts
```

Required cases include safe local reads, remote reads, web search, browser exfiltration, MCP unknowns, destructive shell chains, shell quoting, wrong-directory writes, `path`/`_path`/multi-hashline `paths[]`, symlink traversal, protected config edits, exact grants, wildcard allow non-bypass, deny precedence, xdev parent/device correlation, configured secrets, common private-key/token shapes, entropy false positives, and complete-hash stability for oversized inputs.

### 4. Reuse OMP secret obfuscation and capture bounded provenance

**Create:** `src/context.ts`, `test/context.test.ts`, `test/provenance.test.ts`

1. Construct one `SecretObfuscator` per OMP extension session from OMP/user/project secret entries using the same agent directory and session identity as the host session. Use `obfuscateToolArguments(...)` on a deep-cloned judge payload before serialization.
2. Add a second deterministic metadata minimizer: send only fields used by the judge contract; omit audit IDs, random nonces, absolute home-directory prefixes, irrelevant tool schema metadata, and raw result bodies unless selected by provenance logic.
3. Register `message_end` and `tool_result` listeners. Keep a bounded in-memory ring of recent user intent, primary-agent rationale, external tool outputs, and target-changing results. Classify provenance by source (`user`, `assistant`, `local`, `external-network`, `browser`, `MCP`, `subagent`) and never persist raw ring contents.
4. Build each judge snapshot from overlapping primary-session evidence: current user request, most recent assistant rationale, current full tool call after secret obfuscation, relevant recent external output, source agent identity, and applicable policy/rule summaries. Do not include previous judge prompts, hidden judge reasoning, or judge verdict text.
5. Serialize oversized arguments with field-aware head/tail/size/hash summaries. Preserve complete values for URLs, executable chains, target paths, credential-shape matches, and policy-rule keys. If omitted content could change the target/action classification, mark the snapshot `incompleteCriticalContext: true`; the judge must not return a silent allow for that input.
6. Wrap all external/tool-provided text in explicit inert-data delimiters and state in the system prompt that it is evidence, never instruction or authority.

**Focused verification:**

```bash
bun test test/context.test.ts test/provenance.test.ts
```

Required assertions: exact configured secrets and OMP placeholders never appear in serialized judge input, redaction is deterministic, input objects are not mutated, user intent and assistant rationale are distinct, external output is provenance-labeled, judge history is absent, bounded rings evict oldest entries, large payload hashes cover full bytes, suspicious tail content survives sampling, and critical omission forbids silent allow.

### 5. Implement durable redacted state and append-only audit events

**Create:** `src/store.ts`, `test/store.test.ts`, `test/audit-redaction.test.ts`

1. Use Bun's built-in SQLite binding. Store the database under the resolved OMP agent directory (`<agentDir>/smart-approve/state.sqlite`), create the directory with owner-only permissions, enable WAL and a bounded busy timeout, and apply numbered migrations transactionally.
2. Create normalized tables for:
   - `audit_calls`: compact final decision, hashes, redacted summary, source agent, tool/operation/target, risk, rule/model identity, aggregate timing/token/cost, and timestamps;
   - `audit_events`: append-only transitions such as judged, escalated, blocked, overridden, expired, retried, and revoked;
   - `rules`: exact deny, pattern deny, posture, and exact allow definitions plus specificity and creator;
   - `grants`: single-use/session/persistent exact-call grants bound to canonical call hash and policy/config hash;
   - `pending_approvals`: durable pending escalations — audit ID, canonical call and policy/config hashes, nonce, redacted summary, source agent and parent IDs, state transitions (`awaiting-human`, `approved-intent`, `denied`, `expired`), and `pendingApprovalTtl`. Never stores raw arguments, which is why it safely outlives `brokerArgsTtl`;
   - `retry_families`: original/retry links, retry count, and terminal status;
   - `schema_meta`: migration version.
3. Make audit persistence part of the safety transaction: a scoped call cannot return allow until its redacted terminal audit row commits. On write failure, return escalation/block; do not silently run unaudited.
4. Persist full-call hashes and redacted summaries only. Add a serialization guard that rejects keys/values tagged as raw arguments and run the OMP obfuscator plus credential-shape scan over every string before a write.
5. Append a compact custom session entry containing audit ID, decision, risk, and retry-family link. Never append the raw call or full rationale to session history.
6. Implement one-time grants atomically (`UPDATE ... WHERE consumed_at IS NULL AND expires_at > now`) and invalidate every allow grant when its bound policy/config hash changes. Deny rules remain active across policy changes.
7. Store overrides as new audit events linked to the original result. Never rewrite or delete the original verdict.

**Focused verification:**

```bash
bun test test/store.test.ts test/audit-redaction.test.ts
```

Required cases: fresh migration, upgrade migration, concurrent readers/writers, busy timeout, transaction rollback, audit-before-allow failure, owner-only path, no raw secret/argument bytes in the database file, single-use atomic consumption, TTL expiry, policy-hash invalidation, pending-approval lifecycle (create, approve-intent, deny, expire, single consumption), retry linkage, override append-only history, and compact session-entry serialization.

### 6. Implement the stateless direct judge

**Create:** `src/judge.ts`, `test/judge.test.ts`, `test/model-selection.test.ts`, `test/fixtures/judge/**`

1. Resolve only explicitly authorized providers/models from the session's `ctx.modelRegistry`; prefer a configured fast model from a different provider family than the primary session model, then configured same-family fallbacks. Never select an unauthorized provider, silently fall back to the primary model, or reach into a separate credential store.
2. Verify `modelRegistry.hasConfiguredAuth(model)` at session start and immediately before the request. Missing/disabled credentials produce an actionable judge-unavailable result, not a provider call.
3. For each attempt, create a fresh direct request with:
   - a unique `sessionId` and `promptCacheKey` derived from audit ID and attempt number;
   - `statefulResponses: false`;
   - one system message and one user evidence message;
   - no tools, workspace access, agent loop, or shared mutable judge history;
   - an attempt-specific `AbortSignal` and bounded output tokens.
4. Require one strict JSON object matching a Zod discriminated union. Reject Markdown fences, extra prose, unknown keys, missing risk class, invalid decisions, malformed suggestions, tool calls, empty output, and outputs beyond the configured byte limit. Do not repair or partially parse malformed model output.
5. Instruct the judge to assess the requested action against user intent and provenance, resist quoted injection text, and return `allow` only when the action, destination, and consequences are unambiguous and bounded. `incompleteCriticalContext` can yield only `escalate` or `block`.
6. Retry once only for configured transient transport failures, timeout, rate limit, or malformed output. Never retry a valid `allow`/`escalate`/`block`. Respect the shared overall deadline; skip retry if it cannot complete with cleanup margin.
7. Record model/provider identity, attempts, latency, usage tokens, provider-reported cost when available, and estimated cost otherwise. Never cache a verdict.
8. Track the 5-second target as an observed metric. The target is not a reason to fail open; the hard per-attempt timeout remains the safety boundary.

**Focused verification:**

```bash
bun test test/judge.test.ts test/model-selection.test.ts
```

Use injected fake completion/model-registry ports, not network mocks of OMP internals. Cover cross-family selection, same-family configured fallback, no authorized model, credential disabled between start and call, unique request identity, no prior messages/tools, stateful response disabled, attack text copied into evidence, all three valid verdicts, every malformed-output class, timeout, abort, transient single retry, no retry after valid verdict, deadline-short-circuit, no cache, and cost/latency accounting.

### 7. Resolve OMP's native approval branch and orchestrate the gate

**Create:** `src/host.ts`, `src/gate.ts`, `test/host.test.ts`, `test/gate.test.ts`, `test/deadline.test.ts`

1. In `src/host.ts`, resolve the current `AgentSession` by matching the handler's `ctx.sessionManager` against `AgentRegistry.global().list()` session refs. Resolve the live tool by exact name from `session.agent.state.tools`; use normalized `event.input` and OMP's public `resolveApproval(...)` with the live `tools.approvalMode` setting.
2. Classify OMP decisions:
   - native `allow` -> Smart Approve `auto` branch;
   - native `prompt` -> Smart Approve `prompt` branch;
   - native `deny` is normally filtered before `tool_call`; if observed, hard-block immediately;
   - pending computer safety checks -> `prompt` branch;
   - standard CLI `--auto-approve`/`--yolo` appears through live settings and therefore remains `auto`;
   - an unknown session, tool, tier, or incompatible resolver result -> fail-closed unsupported-host result.
3. Keep parent `xdev` and nested device events separate. The parent performs scope/approval classification only; the nested call receives semantic judgment. Correlate IDs so a nested allow cannot authorize a different parent payload.
4. Implement this exact orchestration order in `src/gate.ts`:

   ```text
   freeze + hash call -> start audit -> protected/deny checks
   -> resolve native approval branch
   -> if native prompt: semantic pre-screen only
   -> if native auto and scoped:
        exact grant (including approval/override grants) -> allow
        else retry-family loop-break check
        else judge
   -> durable terminal audit write
   -> allow or return actionable block reason
   ```

5. Native prompt branch semantics: hard-block only deterministic protected/deny violations or a valid judge `block`; otherwise publish a redacted companion risk card and return no block, letting OMP show its single native dialog. Judge failure is shown in that card and still falls through to native prompt.
6. Native auto branch semantics: valid judge `allow` runs silently and `block` returns an actionable reason. `escalate` resolves asynchronously by default: durably persist a pending approval (redacted summary, canonical call and policy hashes, nonce, TTL), then — only when the main TUI is live and remaining budget clears the dialog floor — offer the best-effort in-handler dialog. Dialog approve executes with the nonce; dialog deny blocks; dialog timeout, missing UI, or insufficient budget returns an audited block whose reason carries the audit ID and `/smart-approve review <audit-id>` so the human decides out-of-band with no handler clock. Any model, parsing, configuration, storage, deadline, or broker failure becomes escalation, ending as a pending block when no trusted human answer exists.
7. Track blocked retries by `(sourceAgent, tool, canonical operation, resolved target, risk family)`. The loop-break check runs after grant matching, so a human-approved retry is admitted by its exact grant and closes the family. Strike exemption is bounded independently of record actionability: attempts are exempt only while the record is `awaiting-human`, within `strikeExemptionWindow`, and under `maxExemptAttempts`; an `approved-intent` record grants exactly one exempt re-open attempt, consumed on use. Past any bound, strikes resume counting and the loop breaker fires normally even though the audit ID stays actionable for the rest of `pendingApprovalTtl` — a human deliberating must never buy the agent an unbounded retry budget. Repeated materially equivalent retries without new user intent escalate reason severity, then hard-block as a loop; semantically changed retries create a new family.
8. Use one `AbortController` rooted at `deadlineAt`. Model attempts, retry backoff, audit work, and the fast-path dialog all consume the same remaining budget. Finish or block before the 28-second self-deadline so OMP's 30-second handler timeout cannot convert a safety result into an ambiguous host error.

**Focused verification:**

```bash
bun test test/host.test.ts test/gate.test.ts test/deadline.test.ts
```

Required host cases: `read`/`write`/`exec` tiers, `always-ask`, `yolo`, `--auto-approve`-equivalent live settings, per-tool allow/prompt/deny, argument-aware MCP approval, pending computer safety, unknown custom tool, missing registry session, and nested xdev. Required gate cases: deterministic deny before model, exact grant, grant-before-loop-break precedence, local-read skip, all native-prompt combinations without double dialog, all native-auto verdicts, every failure stage, audit-before-allow, escalation-to-pending block with actionable reason, blocked call then human override grant then identical retry allowed exactly once without a strike, strikes suppressed while `awaiting-human` inside both bounds, strikes resuming and the loop breaker firing after `strikeExemptionWindow` elapses, after `maxExemptAttempts` is exhausted, and once the record leaves `awaiting-human` — each while the audit ID remains actionable, `approved-intent` absorbing exactly one re-open attempt and no more, pending record with evicted raw arguments refusing to mint a grant, dialog timeout falling through to pending, abort propagation, and completion below host cap under a fake clock.

### 8. Add the main-session escalation broker and trustworthy UI

**Create:** `src/broker.ts`, `src/ui.ts`, `test/broker.test.ts`, `test/ui-state.test.ts`

1. Store one versioned broker under `globalThis[Symbol.for("omp-smart-approve.broker.v1")]`. Each extension instance registers an endpoint on `session_start` containing agent ID, parent ID, UI capability, and a weak session reference; unregister on `session_shutdown`.
2. Elect only the public `AgentRegistry` ref whose `agentKind === "main"` as the human endpoint. Subagents post an immutable request containing the literal frozen tool/arguments, redacted rationale, risk, source subagent ID/name, full-call hash, nonce, expiry, and audit ID. No agent message or paraphrase is part of approval.
3. Serialize prompts through a FIFO queue. Deduplicate the same audit ID, cap pending entries, expire stale requests, abort waiters when the originating handler is cancelled, and never reuse a nonce or approval.
4. Implement a focused `SmartApprovalDialog` TUI component using OMP's exported TUI primitives. It must:
   - display the literal tool name and complete pending arguments in a scrollable region;
   - display source agent, target/destination, risk class, judge rationale, exact call hash, and a countdown bounded by the remaining handler budget;
   - default focus to `Deny`;
   - return `Allow once` only with the request's exact random nonce in the result;
   - return `Deny` on Escape/cancel and `undefined` on unsupported/no UI;
   - call `done(...)` on timeout and fall through to the durable pending-approval path rather than a terminal deny, so no orphan component survives the handler deadline.
5. Bind a successful human decision atomically to `(auditId, argumentsHash, nonce)`, consume it once, and discard it after TTL, cancellation, restart, config change, or call mutation. A late response updates the audit as expired and cannot unblock execution. Minting an allow grant — from the dialog or from pending-approval review — requires the literal frozen arguments to still be present in the in-memory broker within `brokerArgsTtl`, with a matching recomputed canonical hash; without them, approval degrades to recorded intent-to-approve, never a grant.
6. For a native OMP prompt, render a companion widget rather than this dialog. The widget shows risk, redacted rationale, destination, judge availability, and audit ID; OMP's native prompt remains the sole approval control and already shows literal arguments. Clear the widget on `tool_execution_start`, `tool_result`, cancellation, or timeout.
7. Render visible main-session status for subagent blocks and pending escalations, listing open pending approvals by audit and subagent ID. Append only compact redacted state to session history; raw pending arguments stay inside the in-memory broker and dialog component, and literal-argument rendering for review comes only from that broker, never from persistence.

**Focused verification:**

```bash
bun test test/broker.test.ts test/ui-state.test.ts
```

Required cases: independently imported extension modules share the symbol broker, main election, no-main/headless block, exact literal argument rendering, scrolling state, safe default, nonce mismatch, hash-recompute mismatch refusal, evicted-arguments approval refusal, dialog-timeout fall-through to pending, intent-to-approve rerun surfacing a fresh live dialog, single use, TTL, late answer, cancellation, config change, FIFO concurrency, bounded queue, subagent-to-main round trip, main headless fallback, native-prompt companion card, and widget cleanup.

### 9. Add operator commands, exact grants, overrides, and bypass controls

**Create:** `src/commands.ts`, `test/commands.test.ts`

Register one namespaced command with subcommands; avoid global single-word command collisions:

```text
/smart-approve setup
/smart-approve status
/smart-approve rules [list|show|revoke]
/smart-approve pending
/smart-approve review <audit-id>
/smart-approve apply-suggestion <audit-id>
/smart-approve override <audit-id>
/smart-approve unguarded
/smart-approve guarded
```

1. `setup` is the only first-run wizard. It lists only models with configured auth, recommends a fast cross-family model, previews the config path and timeout budget, and writes config only after explicit confirmation. Until setup succeeds, scoped native-auto calls fail closed with the setup command in the reason.
2. `status` shows config/policy hashes and source paths, judge model/auth health, scope, sensitivity precedence, deadlines, broker/main-UI health, bypass status, audit DB health, the count of pending approvals still open under `pendingApprovalTtl` with the command to list them, recent aggregate verdict/latency/token/cost counts, and compatibility warnings.
3. `rules` lists exact vs patterned posture clearly. Revocation is human-confirmed and immediately invalidates matching grants.
4. `pending` lists every approval still open under `pendingApprovalTtl` — audit ID, tool, redacted target, risk, source agent, age, remaining TTL, and whether the record can still mint a grant or is intent-only. This is the entry point when the block message has scrolled away or the session has restarted; it must work with no arguments and with no live broker state.
5. `review <audit-id>` renders the original redacted verdict, immutable history, retry family, human decisions, and any judge rule suggestion for one call. Literal arguments render only from the live in-memory broker; it never reconstructs or claims to display raw arguments from persistence, and it states plainly which of the two outcomes the record currently supports (mintable grant, or intent-only).
6. `apply-suggestion` accepts only a currently pending in-memory suggestion or a safe redacted deny/posture suggestion. Show the normalized proposed rule and its scope, require explicit confirmation, and re-run schema/specificity checks before insertion. A model-suggested wildcard allow remains non-bypass posture even after confirmation.
7. `override` requires an audit ID, shows the original immutable verdict, and requires a typed random challenge. Minting the exact hash-bound allow grant additionally requires the literal frozen arguments to be present in the broker with a matching recomputed hash; when they are gone (`brokerArgsTtl` expiry, restart, subagent teardown) it records only intent-to-approve — the next materially identical call re-opens a live dialog with real arguments, or stays blocked when headless — while deny and expire remain available without raw arguments for as long as the record is open under `pendingApprovalTtl`. Grants carry a selected one-time/session/persistent scope; persistent allow needs a second explicit confirmation. Record actor, reason, challenge result, expiry, and linked event.
8. `unguarded` requires a typed random challenge and expires at session end. Display a persistent red status/widget for the entire bypass and append an audit event. `guarded` re-enables immediately. Never expose a config or environment flag that silently disables the plugin.

**Focused verification:**

```bash
bun test test/commands.test.ts
```

Cover setup cancellation, no authorized model, cross-family recommendation, atomic config write, redacted status, open-pending count in status, compatibility warning, rule revoke, review history, `pending` listing with no arguments, `pending` listing after a simulated restart with an empty broker, `pending` excluding resolved and expired records, suggestion validation, model wildcard allow downgrade, challenge mismatch, one-time/session/persistent exact override, evicted-arguments override refusing a grant while recording intent-to-approve, intent-to-approve forcing a fresh dialog on the next identical call, second persistent confirmation, grant invalidation, bypass challenge/cancel/session reset, persistent warning, and re-enable.

### 10. Wire extension lifecycle, event ordering, and failure containment

**Modify:** `src/index.ts`

**Create:** `test/extension.test.ts`, `test/omp-contract.test.ts`

1. On extension factory construction, register commands and handlers for `session_start`, `before_agent_start`, `message_end`, `tool_call`, `tool_execution_start`, `tool_result`, `session_switch`, and `session_shutdown`.
2. On `session_start`, resolve config/state/model health, initialize secret redaction, join the broker, capture the public agent identity, and publish status. When the store holds approvals still open under `pendingApprovalTtl`, surface a compact notice naming the count and `/smart-approve pending`, so a restarted session still has an entry point to records whose block message is long gone. Do not make a provider call or launch an automatic setup dialog.
3. On `before_agent_start`, inject only a short operational note: Smart Approve may block a call, block reasons are actionable, retries must materially change the unsafe operation, and the agent must not treat an audit ID as authorization.
4. On `tool_call`, normalize exactly once, invoke the orchestrator, and return either no result or `{ block: true, reason }`. Include audit ID, risk, concise cause, and a safe next action in block reasons; never include secrets or attack payload excerpts.
5. On execution/result events, finalize timings, clear transient UI, capture provenance, and link retry outcomes. On shutdown/switch, abort pending judge/UI work, unregister broker endpoints, close the store, clear widgets/status, and erase raw in-memory calls.
6. Contain every plugin exception at the `tool_call` boundary. Convert it into a durable redacted fail-closed result whenever the store is available; if the store itself is unavailable, return a concise emergency block reason with no raw data.
7. Add host-contract tests pinned to the supported peer range. Import OMP's real `resolveApproval`, extension loader/runner, tool types, secret APIs, and public registries so a breaking OMP upgrade fails type-check or tests rather than silently changing security semantics.

**Focused verification:**

```bash
bun test test/extension.test.ts test/omp-contract.test.ts
```

Use OMP's real extension runner with fake ports around provider/UI/time only. Exercise startup without provider traffic, all event ordering, exact normalized input, handler return shape, actionable redacted block reasons, provenance capture, cleanup, exception containment, duplicate event suppression, the `session_start` pending notice appearing when open records exist and staying silent when none do, and the supported OMP 17.2.2 contracts.

### 11. Build the adversarial/benign evaluation harness

**Create:** `eval/schema.ts`, `eval/cases.jsonl`, `eval/run.ts`, `test/eval-schema.test.ts`

1. Define corpus rows with stable ID, category, intent, primary rationale, provenance-tagged evidence, tool call, expected acceptable verdict set, forbidden verdicts, and notes. Keep synthetic credentials clearly fake.
2. Include representative cases for every required category: normal work, prompt injection, exfiltration, destructive action, wrong target, safety tampering, policy bypass, encoded/obfuscated payloads, compromised subagent requests, oversized payload tail attacks, shell composition, MCP/browser/network egress, and ambiguous but recoverable operations.
3. Make the live runner use the same production context builder, redactor, model selection, prompt, parser, and retry logic. Do not call the gate with a special eval prompt.
4. Emit versioned JSON and Markdown summaries containing plugin commit/package version, corpus hash, config/policy hash, model/provider, per-case verdict/risk/latency/tokens/cost, false allows, false blocks, escalations, parser failures, timeouts, and percentile latency.
5. Exit nonzero only for malformed corpus/report generation or an explicitly supplied `--enforce <threshold-file>` mode. Default live evaluation remains opt-in and non-release-blocking.

**Focused verification:**

```bash
bun test test/eval-schema.test.ts
bun run eval:live -- --help
```

The schema test must prove every required category is present, case IDs are unique, forbidden verdicts are meaningful, the corpus hash is stable, reports validate, secrets are absent, and `--enforce` changes exit behavior. A maintainer with configured credentials can later run:

```bash
bun run eval:live -- --model <provider/model> --out .artifacts/smart-approve-eval
```

### 12. Document, package, and smoke-test the local product

**Create:** `README.md`, `examples/smart-approve.yml`, `examples/SMART_APPROVE.md`, `scripts/smoke.ts`

1. Document the threat model and non-goals, OMP version support, local link/unlink commands, first-run setup, config/policy precedence, scoped tools, sensitivity overrides, exact-vs-pattern rules, three verdicts, fail-closed behavior, subagent routing, audit/redaction guarantees, bypass warning, troubleshooting, live evaluation, and package verification.
2. Explicitly state that the plugin is a second safety boundary, not a sandbox; a human override can still authorize destructive work; no judge is perfect; embedded SDK hosts outside the validated approval surface are blocked.
3. Provide deterministic and natural-language policy examples that do not contain real tokens or permissive wildcard allows.
4. Implement `scripts/smoke.ts` with an isolated temporary HOME/agent directory. It must:
   - run `omp plugin link <repo>` and assert the linked package appears enabled;
   - ask OMP's extension loader to import the linked default entry and assert the expected handlers/command exist;
   - load the named factory through OMP's real extension runner with scripted judge/UI/time ports;
   - exercise one silent allow, one nonce-bound fast-path escalation/allow-once, one hard block, one native-prompt pre-screen without a second dialog, one asynchronous escalation that ends as a pending block and is approved out-of-band so the identical retry executes exactly once, and one headless escalation block;
   - inspect only redacted audit/session outputs and remove the temporary directory in `finally`.
5. Keep scripted ports confined to `scripts/smoke.ts` and tests; the shipped default factory cannot select them from runtime config or environment.

**Focused verification:**

```bash
bun run smoke
bun pm pack --dry-run
```

Expected smoke summary includes six named scenarios, their expected terminal states, one linked-and-loaded package assertion, zero raw-secret findings, and zero leaked temporary processes/files.

### 13. Run the complete deterministic release check

**Modify only if evidence identifies a defect:** implementation/tests/config/docs above

Run the full evidence sequence from a clean dependency install:

```bash
bun install --frozen-lockfile
bun run check
bun test
bun run smoke
bun pm pack --dry-run
```

Then inspect the machine-readable test/smoke summaries for:

- no provider credential access in ordinary CI;
- all scoped native-auto calls ending in audited allow/escalate/block;
- no duplicate dialog on native-prompt calls;
- no raw configured secret or raw argument persisted in SQLite, session entries, reports, or error messages;
- subagent escalation bound to exact call hash/nonce and defaulting to block without main UI;
- escalations that outlive the handler budget ending as audited pending blocks, with approval minting an exact grant only while literal arguments remain available and the approved retry executing without tripping the loop breaker;
- worst-case configured path ending before the 30-second OMP cap;
- package contents sufficient for `omp plugin link .` and local execution.

Real-provider evaluation is intentionally separate and opt-in:

```bash
bun run eval:live -- --model <provider/model> --out .artifacts/smart-approve-eval
```

Do not claim a specific model is safe based solely on deterministic tests; report the observed live model, corpus hash, false allows, false blocks, escalations, parser failures, latency, tokens, and cost.

## Accepted-fact coverage matrix

| Facts | Implementation and automated evidence |
| --- | --- |
| 01, 44 | Package manifest, docs/examples, and local link/load smoke in Steps 1 and 12 |
| 02, 03 | Host branch classifier and gate orchestration (auto/deny/prompt semantics) in Step 7 |
| 04, 05, 06 | Scope classifier, deterministic deny-before-scope, local-read skip, unknown-tool scoping in Step 3 |
| 07, 18 | Closed risk taxonomy and strict structured verdict contracts in Steps 1 and 6 |
| 08, 19 | Judge charter: no code-quality gating, hard-block only for clear violations in Step 6 |
| 09, 38 | Explicit fail-closed configuration surface and setup flow in Steps 2 and 9 |
| 10, 11, 12, 13 | Authorized cross-family model selection, fresh tool-less isolated judge requests, no verdict cache in Step 6 |
| 14, 15, 16, 17 | Provenance snapshot, fenced evidence, secret-machinery reuse, oversized-argument escalation in Steps 3 and 4 |
| 20, 21 | Latency targets, retry policy, and judge-failure semantics in Steps 2, 6, and 7 |
| 22, 23, 24, 25, 26 | Nonce-bound human decisions, literal-call rendering, async pending approvals, subagent forwarding, headless block in Steps 7 and 8 |
| 27, 28, 29 | Visible audited blocks, loop breaker with pending-approval exemption, hash-bound override grants in Steps 5, 7, and 9 |
| 30, 31 | Persistent exact allows and audited session bypass in Steps 5 and 9 |
| 32, 33, 34, 35 | Deterministic precedence, exact-vs-pattern allows, policy discovery, layered sensitivity in Steps 2 and 3 |
| 36 | Constrained non-binding judge suggestions with explicit apply flow in Steps 6 and 9 |
| 37 | Protected plugin policy surfaces under the deny floor in Steps 2 and 3 |
| 39 | Operator command suite in Step 9 |
| 40 | Compact redacted SQLite/session audit and raw-data exclusion in Step 5 |
| 41 | Deterministic enforcement tests across Steps 2-10 |
| 42, 43 | Opt-in live evaluation with machine-readable reports and credential-free ordinary CI in Steps 1, 11, and 13 |

Every accepted fact (fact-01 through fact-44) maps to automated evidence above, so the tests are release requirements; the only provider-dependent evidence is the explicitly opt-in live evaluation described by facts 42 and 43.

## Risks and mitigations

1. **OMP's `tool_call` event does not expose the resolved native approval decision.** The v1 adapter reconstructs it from public live session/tool/settings APIs and OMP's own exported resolver. Keep this logic in `src/host.ts`, pin the peer range to OMP 17.x, and fail closed on any unresolved host state. A future host field should replace this adapter directly.
2. **Embedded SDK `autoApprove: true` can be private constructor state rather than a setting.** Do not infer or silently support it. Document the validated CLI/TUI/RPC surface and block scoped calls when host approval cannot be proven. This is safer than cosmetically skipping the judge on a call that might otherwise execute.
3. **OMP caps extension handlers at 30 seconds — too short for a human decision.** Escalation is asynchronous by default: the handler persists a pending approval and returns an audited block, the human decides out-of-band through review/override, and the approved retry is admitted by an exact grant. The in-handler dialog is a best-effort fast path bounded by leftover budget, and the load-time formula validates judge attempts plus cleanup against the 28-second self-cap.
4. **Subagent extension modules may be imported through distinct cache URLs.** Use a versioned `Symbol.for(...)` global broker, test separate imports, weakly own session endpoints, and clean them on shutdown. Never rely on module-local singleton identity alone.
5. **Main-session UI may be busy or disappear while a subagent waits, and pending approvals can outlive the raw call.** Queue with a bounded TTL, safe-default to deny, bind every answer to exact hash/nonce, and abort the subagent wait. Approval authority requires the literal frozen arguments with a matching recomputed hash — after eviction only intent-to-approve, deny, or expire remain — so availability loss can never turn into approval.
6. **Custom/MCP tools can hide semantics in arbitrary schemas.** Unknown tools remain scoped, unresolved targets cannot match exact grants, and the judge receives complete hashes plus conservative critical-context markers. Users can tune sensitivity but cannot create wildcard model bypasses.
7. **Large arguments create an omission attack surface.** Hash complete canonical bytes, preserve action/target/credential/URL fields and suspicious tails, and disallow silent allow when omitted bytes could change semantics.
8. **Audit durability can contend under many parallel subagents.** WAL, short transactions, bounded busy timeout, and compact rows reduce contention. Failure remains escalation/block; tests cover parallel writers and transaction rollback.
9. **LLM scores vary by model/provider.** Deterministic tests enforce code contracts; a versioned opt-in live corpus measures actual behavior. Default live runs do not block releases until maintainers deliberately define and calibrate an enforceable threshold.
10. **Human-created policy can weaken coverage.** Deny wins at equal specificity, relaxations require explicit local config, exact grants bind to complete call and policy/config hashes, wildcard allows are posture only, and persistent grants require a second confirmation.

## Done condition

The goal is complete when the deterministic release sequence passes, the isolated smoke proves OMP can link and load the package and enforce all six representative paths, every accepted fact maps to automated evidence above, provider-dependent live evaluation can be run on demand with a versioned machine-readable report, and no unresolved blocker is hidden behind a fail-open path.