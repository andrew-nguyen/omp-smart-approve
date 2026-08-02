# Accepted-fact coverage

Every accepted fact from `goals/smart-approve/facts.md` (fact-01 … fact-44) and the
automated evidence that enforces it. Facts are numbered in file order.

Ordinary CI runs everything below with no provider credentials. The only
provider-dependent evidence is the opt-in live evaluation named by facts 42–43.

Run the whole sequence with:

```bash
bun install --frozen-lockfile && bun run check && bun test && bun run smoke && bun pm pack --dry-run
```

| Fact | Requirement (abbreviated) | Automated evidence |
| --- | --- | --- |
| 01 | Release-ready, locally installable OMP plugin that gates calls before execution | `test/package.test.ts` (manifest, files allowlist, entry imports), `test/omp-contract.test.ts` "extension loading", `scripts/smoke.ts` scenario "linked package loads under OMP" (runs the real `omp plugin link`) |
| 02 | Every call OMP would auto-approve, including yolo and `--auto-approve`, passes the full gate | `test/host.test.ts` "approval mode reconstruction", "auto-approve detection closes the private-flag gap"; `test/extension.test.ts` "after the host is caught auto-approving, a judge block becomes a real block" |
| 03 | OMP deny → preserve; OMP prompt → one pre-screen, hard-block on violation, otherwise a risk card and OMP's single native dialog | `test/gate.test.ts` "host branch semantics", "native prompt branch never opens a second dialog"; `scripts/smoke.ts` "native-prompt opens no second dialog" |
| 04 | Judge every write-tier, exec-tier, and network-capable call including URL reads and web searches | `test/policy.test.ts` "scope classification", "network-backed internal URIs are judged, not treated as local reads" |
| 05 | Deterministic deny runs before scope filtering; a successful local read otherwise skips the judge | `test/policy.test.ts` "deterministic precedence"; `test/gate.test.ts` "deterministic checks run before any model call", "a safe local read skips the judge entirely" |
| 06 | Every unknown custom or MCP tool is scoped unless provably a local read with no transmission | `test/policy.test.ts` "an unknown custom tool is scoped even at read tier", "an unknown MCP tool is scoped", "neverJudge cannot exempt a read that targets a url" |
| 07 | Versioned closed risk taxonomy | `src/contracts.ts` `RISK_CLASSES` + `TAXONOMY_VERSION`; `test/judge.test.ts` verdict parsing rejects an unknown risk |
| 08 | The judge does not gate code quality, architecture, style, or efficiency | `test/judge.test.ts` "the system prompt excludes ordinary code quality from the judge's remit" |
| 09 | Valid explicit configuration required; missing config fails closed with setup instructions, no auto wizard | `test/config.test.ts` "zero config fails closed and names the setup command"; `test/gate.test.ts` "an unconfigured plugin fails closed on the auto branch"; `test/extension.test.ts` "startup opens no dialog, so there is no automatic first-use wizard" |
| 10 | Fast authenticated model from an explicit allowlist, preferring a contrasting family | `test/model-selection.test.ts` (cross-family preference, same-family fallback, unauthorized provider never selected) |
| 11 | Uses OMP's registry and auth; fresh tool-less context and provider-session identity per decision; setup time counted | `test/judge.test.ts` "unique request identity", "no tools in the context", "latency spans the whole call, including model selection" |
| 12 | Fresh intent/provenance per judgment; no mutable state carried between judgments; no interleaving | `test/judge.test.ts` concurrent-judgment isolation; `test/context.test.ts` "carries exactly the judge contract fields and no judge history" |
| 13 | Verdicts are never cached | `test/judge.test.ts` "never caches a verdict: identical inputs each reach the provider" |
| 14 | Judge receives user intent, fenced arguments, agent rationale, and a bounded action trace | `test/context.test.ts` `buildJudgeInput` assembly; `test/judge.test.ts` `buildJudgeMessages` sections |
| 15 | Untrusted tool-output bodies are not copied wholesale; provenance is sent instead | `test/provenance.test.ts` (bounded ring, 200-char redacted summaries, source/trust labelling) |
| 16 | Reuses OMP's secret machinery before judge requests and audit | `test/context.test.ts` (configured secret never appears in judge input, input not mutated); `test/omp-contract.test.ts` "secret machinery"; `test/audit-redaction.test.ts` |
| 17 | Oversized argument fields cannot be silently allowed; scanners still read complete values | `test/context.test.ts` (`incompleteCriticalContext`, full-bytes hash, surviving tail); `test/judge.test.ts` "allow under incompleteCriticalContext is rejected" |
| 18 | Strict structured verdict; malformed output is a failure, not an allow | `test/judge.test.ts` "parseVerdict" (every malformed class rejected) |
| 19 | Hard block only for a clear violation; consequential and uncertain escalate | `test/judge.test.ts` system-prompt charter; `test/gate.test.ts` "native auto branch" |
| 20 | 5s target, 10s per-attempt timeout, one retry, configurable | `test/config.test.ts` "deadline invariant"; `test/judge.test.ts` retry policy; `test/deadline.test.ts` |
| 21 | On the auto branch every judge failure escalates then blocks; on the prompt branch it is shown and only OMP's prompt authorizes | `test/gate.test.ts` "every failure stage becomes escalation, never allow", "judge failure is shown in the card and still falls through" |
| 22 | Execution only after an exact per-call nonce from a real human; every other path blocks | `test/broker.test.ts` "decision binding"; `test/gate.test.ts` "a dialog approval with a wrong nonce is refused"; `test/ui-state.test.ts` |
| 23 | Interactive escalation shows the literal call, source agent, rationale, risk, and policy | `test/ui-state.test.ts` literal-argument rendering; `scripts/smoke.ts` fast-path scenario |
| 24 | Headless subagent forwards a frozen escalation to the main-session UI; single-use, nonce-protected, time-limited, exact-call bound | `test/broker.test.ts` "presentation routing" (subagent → main round trip), "grant authority requires the literal call" |
| 25 | Synchronous check for a live main handler; no handler blocks immediately and visibly | `test/broker.test.ts` `hasHumanChannel`; `test/gate.test.ts` "with no human channel it persists a pending record and blocks with the review command" |
| 26 | A headless main means the subagent blocks rather than degrading to allow | `test/broker.test.ts` "a headless main is not a human channel"; `scripts/smoke.ts` "headless escalation blocks" |
| 27 | Every hard block is visible in audit with agent/parent/tool-call/audit IDs, risk, rationale, timestamp, state | `test/store.test.ts` audit rows and events; `test/gate.test.ts` "audit durability" |
| 28 | Three blocked attempts in one retry family escalate the sequence; without a channel it stays blocked | `test/gate.test.ts` "exact grants and the loop breaker", "strike exemption is bounded independently of record actionability"; `test/policy.test.ts` "retry families" |
| 29 | Human override by audit ID and typed challenge; exact-call-bound, single-use, short-lived, invalidated by change | `test/commands.test.ts` override flow; `test/store.test.ts` atomic single-use grant consumption; `test/broker.test.ts` hash-recompute refusal |
| 30 | Persistent exact allow after a second confirmation, listable and revocable | `test/commands.test.ts` "a persistent grant needs a second explicit confirmation", rule listing and revocation |
| 31 | Session bypass needs typed confirmation, is session-only, persistently warned, and audited; the model cannot set it | `test/commands.test.ts` bypass challenge/cancel/re-enable; `test/gate.test.ts` "session bypass"; `test/package.test.ts` "no silent kill switch" |
| 32 | Ordered resolution: deny first, narrow exact allow may skip, broad allow only informs posture, rest are judged | `test/policy.test.ts` "deterministic precedence", "exact allow rules: only a fully specified call may skip the judge", "exact allow binds to a location"; `test/gate.test.ts` "exact allow rule end to end" |
| 33 | Only a fully specified canonical allow may skip; one wildcard makes it posture | `test/policy.test.ts` "wildcard allows never bypass the judge", "a wildcard target disqualifies even with a matching hash" |
| 34 | `SMART_APPROVE.md` discovered broadest to most specific and presented as authoritative policy | `test/config.test.ts` "discovery order"; `test/judge.test.ts` policy documents labelled AUTHORITATIVE |
| 35 | Layered sensitivity; narrowest wins; risk-specific stays strict for a permissive tool; never overrides a deny | `test/config.test.ts` "sensitivity precedence"; `test/gate.test.ts` "per-risk sensitivity tightens once a risk class exists" (including the one-directional property) |
| 36 | Judge suggestions are constrained, non-binding, previewed, and applied only after confirmation | `test/judge.test.ts` wildcard allow-exact suggestion rejected; `test/commands.test.ts` `apply-suggestion` validation and wildcard downgrade |
| 37 | Plugin config, policy files, and other active OMP safety-policy files are write-protected by default | `test/config.test.ts` "protected surfaces"; `test/policy.test.ts` "protected policy floor", "the protected floor follows symlinks"; `test/gate.test.ts` "a protected policy write blocks with no judge call" |
| 38 | Configuration exposes providers, sensitivity, scope, size thresholds, timeouts, escalation, rules, audit | `test/config.test.ts` (schema strictness across every section) |
| 39 | Commands for status, setup, rules, review, override, and bypass | `test/commands.test.ts` (all nine subcommands); `test/omp-contract.test.ts` "registers exactly one namespaced command" |
| 40 | Compact redacted audit metadata; no raw arguments, messages, or secrets duplicated | `test/audit-redaction.test.ts` (including a raw-file byte scan of the database and WAL, with a positive control); `test/gate.test.ts` "no raw argument value reaches the audit row"; `scripts/smoke.ts` redaction sweep. **The guard is runtime, not type-level** — see the note below. |
| 41 | Deterministic tests across scoping, precedence, model selection, isolation, redaction, oversized args, verdicts, fail-closed paths, UI defaults, brokering, nonce/TTL, loop breaking, overrides, bypass, audit redaction | The whole `test/` suite — 774 tests across 19 files |
| 42 | Opt-in live evaluation over a versioned adversarial/benign corpus with a machine-readable report | `test/eval-schema.test.ts`; `eval/cases.jsonl` (40 cases, 13 categories); `bun run eval:live -- --help` |
| 43 | Ordinary CI needs no credentials; live evaluation is opt-in | `test/package.test.ts` "ordinary CI scripts never reference a provider credential"; the release sequence runs green with every provider key unset |
| 44 | Docs, example deterministic and natural-language policies, and a local smoke check | `README.md`, `examples/smart-approve.yml`, `examples/SMART_APPROVE.md`, `scripts/smoke.ts` (12 scenarios) |

## How raw data is actually kept out of the store

Worth being precise, because the wrong mental model here is dangerous.

There is **no type-level brand**. `AuditRecord`'s text fields are ordinary
`string`, so `commitAudit({ ...record, targetSummary: JSON.stringify(rawArgs) })`
compiles. What actually protects the database is three layers, all runtime or
test-time:

1. **Structural separation.** `GateRequest` (which holds `rawArguments`) and
   `AuditRecord` are different types, so a caller cannot pass one where the other
   is expected. This stops the obvious mistake, not a determined one.
2. **`guardWrite`** (`src/store.ts`) runs on every write path. It rejects a
   forbidden **key name** — `rawArguments`, `content`, `command`, `arguments` —
   and scans every string value against credential shapes.
3. **A byte scan** (`test/audit-redaction.test.ts`) reads the database file plus
   its WAL and SHM sidecars and asserts no secret or raw-argument bytes are
   present. It is proven non-vacuous: bypassing `guardWrite` with raw SQL makes
   the identical scan report the secret.

**The residual, stated plainly:** layer 2 is name-based. A raw value copied into a
differently-named field that happens to contain no credential shape passes both
guards. So when adding a new persisted field, add its name to `FORBIDDEN_KEYS` if
it can carry model input — nothing will warn you otherwise.

## Deviations from the plan, and why

Three places where the implementation departs from `goals/smart-approve/plan.md`.
Each was a plan assumption that did not survive contact with OMP 17.2.4.

### 1. `--auto-approve` is not observable through settings

The plan's validated-contract list states that OMP applies `--auto-approve` and
`--yolo` to live session settings. It does not. Both set
`result.autoApprove = true` (`cli/args.ts`), which becomes private constructor
state on `AgentToolContext`; the tool wrapper reads
`context?.autoApprove === true ? "yolo" : settings.get("tools.approvalMode")`.
There is no public accessor.

Left alone, a session started with `--auto-approve` while
`tools.approvalMode: always-ask` would be classified as the prompt branch — so
Smart Approve would only pre-screen a call OMP was about to run silently. That is
a fail-open hole.

`AutoApproveDetector` (`src/host.ts`) closes it with two signals: an argv scan,
which covers every CLI/TUI/RPC session, and a retroactive latch that fires when a
call predicted to prompt begins executing without OMP ever emitting
`tool_approval_requested`. Evidence: `test/host.test.ts`,
`test/extension.test.ts`.

### 2. Config `allow-exact` rules needed an argument hash to be meaningful

The plan describes exact allow rules that may skip the judge, but a rule naming
only a tool and target leaves every other argument unspecified — a `write` rule
naming a path would authorize arbitrary content at that path, which fact-33
explicitly forbids ("or omitted argument").

An `allow-exact` rule now skips the judge only when all three hold:

- `argumentsHash` pins the literal call;
- `target` equals a resolved, non-dynamic target of that call;
- `cwd` resolves to the call's working directory.

The last two exist because the arguments hash is location-blind:
`write {path: "src/a.ts"}` and `bash {command: "scripts/x.sh"}` both hash
identically in every checkout, so a user-scoped rule without them would fire
everywhere. The `cwd` binding is what actually delivers fact-30's repository and
working-directory identity — the target check alone is not enough for command
tools, whose resolved target is the executable exactly as typed. An
`allow-exact` rule missing any of the three degrades to an advisory posture hint.
Evidence: `test/policy.test.ts` "exact allow binds to a location, not just an
arguments hash"; `test/gate.test.ts` "a pinned allow is bound to its working
directory".

### 3. Grants and audit rows needed working-directory identity

The audit database lives at the user-level agent directory and is shared by every
project. Grants were keyed on `(argumentsHash, policyHash)` alone — and two
checkouts with no project config resolve to the same `policyHash` — so a grant a
human approved in one repository would admit a byte-identical call in another.
For a 90-day persistent grant that is a wide hole: approve `scripts/deploy.sh` in
staging and the same command is admitted in production.

Migration 2 adds `cwd` to `audit_calls`, `pending_approvals`, `grants`, and
`rules`, and `consumeGrant`/`findGrant` now require a match.

Revocation deliberately has two scopes, because the two callers differ:

- `revokeGrantsForPolicy(policyHash, cwd)` runs automatically on every
  `session_start`. It is cwd-scoped, or one project would delete another's grants
  on every launch.
- `revokeAllGrants(now)` backs the explicit `rules revoke` command. It is global,
  matching what its confirm dialog tells the operator. Over-revoking costs one
  re-approval; under-revoking would leave a grant live in another checkout after
  the human revoked the rule they believed authorized it.

Both remove only LIVE grants. A consumed grant records what actually ran and an
expired one records what lapsed; both are audit history `listGrants` promises to
keep, and neither can admit anything, so deleting them would destroy evidence for
no security benefit. The reported count is therefore the number of grants that
could still have admitted a call — not the number of rows touched. A grant migrated in from an
older database has `cwd IS NULL`, which no equality check satisfies — inert
rather than portable, which is the fail-closed direction.

Evidence: `test/store.test.ts` "grants are bound to the working directory they
were approved from" (proven non-vacuous by neutering the check).

### 4. Per-risk sensitivity had to be applied after the verdict

`sensitivity.byRisk` cannot be resolved before judgment because the risk class
does not exist until the judge answers. The gate therefore gives the judge the
tool-level posture, then re-resolves once the verdict carries a risk class and
downgrades `allow` to `escalate` when the risk-specific level is stricter.

The tightening is one-directional by construction: a permissive per-risk override
can never turn a block or an escalation into an allow, and no sensitivity setting
overrides a deterministic deny. Evidence: `test/gate.test.ts` "per-risk
sensitivity tightens once a risk class exists".
