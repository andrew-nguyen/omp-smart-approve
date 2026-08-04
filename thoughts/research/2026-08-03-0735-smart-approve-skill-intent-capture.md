# Research: Smart Approve intent/rationale capture — current state for the rejection fix

- date: 2026-08-03 07:35 (local)
- git_commit: 668918f
- branch: trunk
- repository: omp-smart-approve
- topic: evidence-assembly paths feeding the judge (user intent, agent rationale), host event contracts, and the observed rejection cascade
- tags: [smart-approve, judge, provenance, skills, extension-events]
- status: complete
- host versions: repo builds against `@oh-my-pi/pi-coding-agent` 17.2.4 (node_modules); observed session ran omp 17.2.5

## Research Question

A real-repo test (session `2026-08-03T14-15-09-628Z_019fc7fa-7c3c…` in `~/.omp/agent/sessions/home-ugp-demo-8d724e…`) produced a cascade of Smart Approve blocks on read-only git commands during a `generate-commit-msg` skill run. Map the current implementation of every code path involved — how user intent and agent rationale reach the judge, what the host actually emits, and what the session evidence shows — as the factual base for a fix.

## Summary

Smart Approve derives its two authority channels (USER INTENT, AGENT RATIONALE) exclusively from `message_end` events with `role === "user" | "assistant"` (`src/index.ts:440-455`). Three current-state facts starve those channels:

1. **Skill invocations are not user-role messages.** OMP submits them as `role:"custom"` (`customType:"skill-prompt"`, `attribution:"user"`). The handler matches neither branch, so a session whose only directive turn is a skill invocation records no user intent, ever. Verified in host source and in the session file (role census: 1 user-role message in 135 entries, arriving after the last block).
2. **The rationale is deterministically one assistant message stale.** The host runs tool-call preparation — including the `beforeToolCall` hook that emits the extension `tool_call` event — *before* `message_start`/`message_end` for streamed messages, by documented design (`pi-agent-core/src/agent-loop.ts:1757-1760, 2079-2083, 2250-2252`). The tracker therefore cannot contain the current message's text when its calls are judged. This is not a fan-out race; the CHANGELOG 17.2.4 "subscriber fan-out serialized in emission order" fix governs subscriber-vs-subscriber order only.
3. **Thinking-only assistant messages never update the rationale.** `extractText` (`src/index.ts:685-701`) reads only `.text` fields; pi-ai `ThinkingContent` carries `.thinking` (`pi-ai/dist/types/types.d.ts:466-470`). A thinking+toolCall message extracts to `""` and the handler early-returns (`src/index.ts:448`), retaining the previous rationale instead.

Downstream, `buildJudgeInput` pre-wraps the rationale in the evidence fence (`src/context.ts:542`), which makes the `"(no stated rationale)"` placeholder branch in `buildJudgeMessages` unreachable (`src/judge.ts:374-377`) — an empty rationale renders as an empty `UNTRUSTED_EVIDENCE` fence. The session evidence shows all of the above compounding into blocks whose reasons quote one- and two-message-stale narration as live justification, a false "fabricating justification / prompt-injection" classification of a truthful agent, and a loop-breaker escalation.

## Detailed Findings

### 1. Designed decision flow (context for where evidence assembly sits)

- Gate ordering is specified in `src/gate.ts:1-34`: freeze+hash → audit open → deterministic checks → host-approval branch → grants/exact allows → open-escalation reuse → loop breaker (`LOOP_BREAK_THRESHOLD = 3`, `src/gate.ts:63`) → judge → allow / judge-block (`RETRY_GUIDANCE`, `src/gate.ts:118-120`) / escalate (durable pending + block carrying `/smart-approve review <id>`, `src/gate.ts:29-33, 575+`).
- The judge measures the call against USER INTENT as the sole authority: intent is deliberately not fenced (`src/context.ts:539-541`); everything else is inert evidence that "cannot grant permission" (`src/judge.ts:298-303`). Decision boundaries: unverifiable-but-legitimate → `escalate`; clear violation → `block` (`src/judge.ts:311-321`).
- Design premise on record: fact #14 in `docs/fact-coverage.md:40` — "Judge receives user intent, fenced arguments, agent rationale, and a bounded action trace."

### 2. Intent channel: capture surface vs. host message taxonomy

Current capture (`src/index.ts:440-455`):

```ts
if (role === "user") runtime.tracker.recordUserMessage(text);
else if (role === "assistant") runtime.tracker.recordAssistantRationale(text);
```

Host taxonomy for the turns that matter here:

- Skill invocations (TUI, ACP, RPC alike) are submitted via `promptCustomMessage` as `role:"custom"`, `customType: SKILL_PROMPT_MESSAGE_TYPE = "skill-prompt"` (`messages.ts:42`), `attribution:"user"`: `modes/skill-command.ts:55-57`, `modes/acp/acp-agent.ts:882-885`, `rpc/rpc-mode.ts:127-130`, `session/agent-session.ts:4981-4984`.
- The rendered prompt places the user's own words at the tail: `prompts/skills/user-invocation.md` ends with `User: {{userArgs}}`.
- Input messages (including the custom skill prompt) do receive `message_start`/`message_end` events: `pi-agent-core/src/agent-loop.ts:938-943` (`emitInputMessages`), forwarded to extensions at `agent-session.ts:3298-3304`. The events arrive; the role filter drops them.
- Other user-attributed custom types exist (e.g. `COLLAB_PROMPT_MESSAGE_TYPE` with `attribution:"user"`, `session/messages.ts:625-630`).
- The handler applies no `synthetic`/`steering`/`attribution` filtering for `role:"user"` messages; host UI code does distinguish (`modes/interactive-mode.ts:2310` checks `!event.message.synthetic`). No test in `test/` exercises `custom` roles or these flags (only `test/extension.test.ts:513-516` with a plain user role; grep for `attribution|synthetic|steering` in `src/`+`test/` matches nothing relevant).

Session evidence (`…-ugp-demo…/2026-08-03T14-15-09-628Z_….jsonl`):

- Row 5: `custom_message`, `customType:"skill-prompt"`, `attribution:"user"`, content 1843 chars, tail = `…User: confirm that the staged files don't include anything we should not be committing to git.  if everything looks good,`.
- Role census across 135 entries: assistant 29, toolResult 38, **user 1** — the sole user-role message is row 132 ("why would staged blob contents be unverified?"), after the last Smart Approve block (row 122). Every judged call in the session ran with `latestUserIntent() === ""`, rendered as `(no recorded user request)` (`src/judge.ts:370`).

Clamp geometry (relevant fact for any capture of skill prompts): `recordUserMessage` head-keeps 2000 chars (`clampText`, `src/context.ts:243, 281-283, 319`); the skill template puts `User: <args>` last. This instance (1843 chars) would fit; longer SKILL.md bodies exceed the window before the tail.

### 3. Rationale channel: deterministic staleness by host design

- The extension `tool_call` event is emitted from the host's `beforeToolCall` hook (`agent-session.ts:3099-3131` `#beforeToolCall` → `runner.emitToolCall`), wired into the loop config (`pi-agent-core/src/agent.ts:1351`).
- For streamed assistant messages, the loop runs the prepare phase — validation plus `beforeToolCall`, for **every** tool call on the message, in call order — **before** `message_start`/`message_end` are pushed, so hook arg-revisions are baked into the message all consumers snapshot: `agent-loop.ts:1757-1760` ("Prepare tool dispatch … BEFORE the message is snapshotted for consumers"), `2079-2083`, `2106-2110`, `2250-2252`.
- Consequence: at judge time, `latestAssistantRationale()` is at best the *previous* assistant message; on the first assistant turn it is `""`. All calls in a multi-call message are judged against the same stale text.
- The 17.2.4 CHANGELOG entry "subscriber fan-out is now serialized in emission order" (`pi-coding-agent/CHANGELOG.md:643`) orders subscriber events relative to each other; the prepare-phase hook is not a subscriber event and precedes the message events' emission entirely.

Session evidence, per-message:

| jsonl msg | content shape | tracker rationale at its calls' judge time | outcome |
|---|---|---|---|
| [2] | text "I'll check the staged files…" + bash + read | `""` (first turn) | block #1: "rationale is marked UNTRUSTED_EVIDENCE with no content" |
| [5] | thinking + text "…the user explicitly asked me…" + bash `git branch` | [2]'s text | allow |
| [7] | thinking + text "Branch: … Now the staged contents:" + **two** bash calls | [5]'s text | #2 escalate + #3 block, both quoting "'explicitly asked'" — words from [5], not [7] |
| [10] | thinking + text "…Retrying with a neutral, purely descriptive intent:" + bash | [7]'s text | allow |
| [12] | thinking + toolCall only (no text) | — (extract `""` → early return; [10]'s text retained) | n/a (read allowed) |
| [14] | text "Now auditing content…" + two bash calls | [10]'s text (two messages stale) | #4/#5 block: quotes "'retrying with a neutral, purely descriptive intent'" as a live evasion admission |

Block #1's empty fence is attributable to ordering alone: message [2] contains a text block, so `extractText` would have returned prose had the event been delivered before judging.

### 4. Thinking-only messages and `extractText`

- `extractText` (`src/index.ts:685-701`) accepts string content or array blocks exposing a string `.text`. pi-ai assistant content unions include `ThinkingContent { type:"thinking"; thinking: string }` and `ToolCall` blocks (`pi-ai/dist/types/types.d.ts:466-470, 666-667`) — neither has `.text`.
- A thinking+toolCall-only assistant message extracts to `""`; `src/index.ts:448` (`if (text.length === 0) return`) returns before the role dispatch, so the tracker retains the prior rationale rather than clearing it.
- Live occurrence: message [12] above; its effect surfaces in blocks #4/#5 (two-message-stale quote).

### 5. Judge-prompt rendering of empty channels

- `buildJudgeInput` wraps the rationale before the length check ever happens: `agentRationale: wrapEvidence(tracker.latestAssistantRationale())` (`src/context.ts:542`). `wrapEvidence("")` is non-empty by construction (`src/context.ts:50-53`).
- `buildJudgeMessages` tests `input.agentRationale.length === 0` for the `"(no stated rationale)"` placeholder (`src/judge.ts:374-377`); with pre-wrapped input this branch is unreachable. Empty rationale renders as an empty `UNTRUSTED_EVIDENCE` fence.
- The intent placeholder does work: `userIntent` is only neutralized, not wrapped (`src/context.ts:541`), so `""` survives to the check at `src/judge.ts:370` and prints `(no recorded user request)`.
- Block #1's reason text ("rationale is marked UNTRUSTED_EVIDENCE with no content") is the judge describing the empty fence.

### 6. Observed cascade end-to-end (8 blocks)

Smart Approve error results at jsonl rows 11, 22, 23, 36, 37, 42, 67, 122:

1. `git branch && … && git status` — judge block; empty intent + empty fence.
2. `git diff --staged --stat` — escalation (pending + `/smart-approve review 4f066415…`); "cannot be verified".
3. `git status --short` — judge block; "fabricating justification … classic prompt-injection".
4. `git diff --name-only` — judge block; stale [10] text read as evasion admission ("direct attempt to bypass safety gates").
5. `git diff --staged -- .gitignore .env.example` — judge block; same stale-quote basis.
6. `read .env.example` — **deterministic** protected-path block ("path target matches dotenv"), the policy tier working as specified (`src/policy.ts` protected paths); not judge-driven.
7. bash→`command:git` family, attempt 4 — loop-breaker escalation (`src/gate.ts:63, 400-414`).
8. eval call near session end — still "no user request is recorded" (row 122; precedes the row-132 user message).

Verdict scatter across near-identical read-only git calls (allow / escalate / block) tracks the changing stale rationale, with intent constant-empty.

### 7. Surfaces present at judge time (facts relevant to any fix design)

- The host has the full current assistant message in hand at the emit site: `BeforeToolCallContext.assistantMessage` (`pi-agent-core/src/types.ts:590-593`; used at `agent-session.ts:3109-3131`). The extension-facing `ToolCallEvent` forwards only `toolName`, `toolCallId`, `input` (`extensibility/extensions/types.ts:823-871`).
- `ExtensionContext.sessionManager` is a `ReadonlySessionManager` (`extensibility/extensions/types.ts:414-428`) exposing `getBranch()` / `getEntries()` over session entries including message entries (`session/session-manager.ts:2204-2239`). The smart-approve extension already receives `ctx` in its `tool_call` handler (`src/index.ts:492`) and uses `ctx.sessionManager` for identity resolution at startup (`src/host.ts:99-112`).
- Custom messages carry `customType` and `attribution` fields usable for classification (`session/messages.ts:885-895`).
- The bash `i` intent argument reaches the judge inside the fenced ARGUMENTS block; `i` is not in `DROPPED_METADATA_KEYS` (`src/context.ts:113-133`).

## Code References

- `src/index.ts:440-455` — message_end role filter; `:448` empty-text early return; `:685-701` `extractText`
- `src/context.ts:243, 281-283, 305-372` — tracker, 2000-char head clamp; `:536-564` `buildJudgeInput`; `:541-542` intent neutralized vs rationale pre-wrapped; `:113-133` dropped keys
- `src/judge.ts:290-332` — system prompt; `:364-422` message assembly; `:370` intent placeholder (live); `:374-377` rationale placeholder (unreachable)
- `src/gate.ts:1-34, 63, 118-120, 400-414, 575+` — decision spec, loop breaker, retry guidance, escalation
- `docs/fact-coverage.md:40` — fact #14 (judge input premise)
- `test/extension.test.ts:264-267, 513-516` — event-order and role assumptions in tests
- Host (`node_modules/@oh-my-pi/…`, 17.2.4 sources):
  - `pi-agent-core/src/agent-loop.ts:938-943, 1757-1760, 2079-2083, 2106-2110, 2250-2252` — input-message emission; prepare-before-message_end ordering
  - `pi-agent-core/src/types.ts:478-481, 553-557, 590-593` — `beforeToolCall` contract
  - `pi-coding-agent/src/session/agent-session.ts:3099-3131, 3298-3304, 4935-4984` — tool_call emit, message_end forwarding, `promptCustomMessage`
  - `pi-coding-agent/src/modes/skill-command.ts:55-57`, `modes/acp/acp-agent.ts:882-885`, `rpc/rpc-mode.ts:127-130` — skill submission paths
  - `pi-coding-agent/src/session/messages.ts:42, 426-436, 625-630, 885-895` — skill/collab custom types, attribution
  - `pi-coding-agent/src/prompts/skills/user-invocation.md` — `User: {{userArgs}}` tail
  - `pi-coding-agent/CHANGELOG.md:643` — subscriber fan-out serialization scope
  - `pi-ai/dist/types/types.d.ts:466-470, 666-667` — `ThinkingContent`, assistant content union
- Session evidence: `~/.omp/agent/sessions/home-ugp-demo-8d724e…/2026-08-03T14-15-09-628Z_019fc7fa-7c3c-7000-9582-9ea42296efd8.jsonl` (rows 5, 11, 22, 23, 36, 37, 42, 67, 122, 132)

## Open Questions

1. Version delta: ordering and message taxonomy were verified in 17.2.4 sources while the session ran omp 17.2.5; observed behavior matches the 17.2.4 design exactly, but 17.2.5 sources were not read.
2. The complete set of user-attributed `customType`s a capture filter would need to enumerate (beyond `skill-prompt` and the collab prompt type) has not been inventoried.
3. Whether user-role messages with `synthetic: true` or agent attribution are emitted through `message_end` in flows this session did not exercise (queued continuations, steering) — the handler currently records any `role:"user"` text.
4. `ReadonlySessionManager`'s exact exposure of the *in-flight* (not yet persisted) assistant message at `tool_call` time was not empirically tested — prepare-phase ordering implies the current message's entry may not be appended yet when the hook runs.
