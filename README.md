# omp-smart-approve

An LLM safety judge in front of tool calls OMP would otherwise auto-approve.

OMP already asks you about the calls it considers risky. This plugin is about
the other ones — the calls that run silently because the tool is on an
auto-approve list, or because the session is in yolo mode, or because a subagent
inherited a permissive setting. That is a large, quiet surface, and it is where
both of the following go wrong.

**Malicious calls.** A model that has read a web page, an issue, a dependency's
README, an MCP tool result, or a log file has read attacker-controllable text.
Prompt injection turns that text into an instruction, and the instruction
arrives as an ordinary-looking tool call from your own agent.

**Well-intentioned but wrong calls.** A model sincerely pursuing your goal
proposes `DROP TABLE` against the wrong database, force-pushes over a colleague's
branch, or deletes a directory it computed from a variable. No attacker is
involved. The call is simply worse than the model understands.

Both look like a normal tool call. Neither is caught by a permission list,
because the permission was already granted. So each in-scope call gets a fresh
semantic judgment from a second model, against your policy, before it runs.

---

## Table of contents

- [What this is not](#what-this-is-not)
- [Requirements and supported hosts](#requirements-and-supported-hosts)
- [Install](#install)
- [First-run setup](#first-run-setup)
- [Configuration and policy](#configuration-and-policy)
- [What gets judged](#what-gets-judged)
- [Sensitivity](#sensitivity)
- [Rules: exact versus pattern](#rules-exact-versus-pattern)
- [The three verdicts](#the-three-verdicts)
- [Fail-closed behavior](#fail-closed-behavior)
- [Why escalation is asynchronous](#why-escalation-is-asynchronous)
- [The two clocks](#the-two-clocks)
- [Subagent routing](#subagent-routing)
- [Audit and redaction](#audit-and-redaction)
- [Bypass](#bypass)
- [Command reference](#command-reference)
- [Troubleshooting](#troubleshooting)
- [Live evaluation](#live-evaluation)
- [Package verification](#package-verification)

---

## What this is not

Read this section before deciding what to rely on.

**It is not a sandbox.** It reasons about calls; it does not confine them. A
call it allows runs with the full authority of the OMP process — same
filesystem, same network, same credentials. If you need containment, you need
containment. This is a second boundary in front of a decision, not a wall
around a process.

**A human override can still authorize destructive work.** `/smart-approve
override` exists precisely so a human can say "yes, I mean it". Every guarantee
here ends at a person who types the challenge string. That is the intended
design — a safety gate nobody can get past is a safety gate people rip out —
but it means the plugin cannot protect you from your own approvals, and it
cannot protect you from an approval given without reading.

**No judge is perfect.** The judge is a language model. It will sometimes allow
something it should have escalated and sometimes block something obviously fine.
Configured strictly it produces friction; configured permissively it produces
misses. Treat it as one layer that raises the cost of an attack and catches a
meaningful share of mistakes, not as a guarantee about any individual call. If
you want numbers for a specific model, measure them — see
[Live evaluation](#live-evaluation) — and do not infer safety from the fact that
the deterministic test suite passes.

**Hosts outside the validated approval surface are blocked, not guessed at.**
The plugin decides what to do by asking OMP's own approval resolver what OMP
would have done. When it cannot match a tool call to a live OMP session, or
cannot resolve the tool's tier, it does not assume. It blocks and says so. An
embedded SDK host that auto-approves outside the surface described below is
detected after exactly one call and then latched: every subsequent call in that
session goes through the full gate. The cost of this choice is that an
unsupported host is unusable rather than silently unprotected. That is
deliberate.

**It does not gate code quality.** Architecture, naming, test coverage,
performance, dependency choices, style — none of it. A gate that argues about
taste is a gate people learn to click through, which destroys its value for the
cases that matter.

**The judge sees a bounded excerpt of your tool output, not full bodies.** Up
to twelve recent actions reach the judge prompt, and each one is
secret-obfuscated, home-path-minimized, collapsed to a single line, truncated
to 200 characters, and wrapped in inert-data delimiters alongside its source,
trust flag, and timestamp. Full result bodies are never copied in, and none of
this is persisted. That bounds the judge's own prompt-injection exposure, the
token cost, and the latency — but be clear about the cost: **truncation can hide
the part that mattered.** A 200-character excerpt of a long result may not show
the injected instruction buried at the end of it. The deterministic scanners
read complete values; the judge reads a sample.

---

## Requirements and supported hosts

| | |
| --- | --- |
| Runtime | Bun >= 1.3 |
| OMP peer range | `>=17.2.2 <18` |
| Validated against | OMP 17.2.4 |

Host-contract tests import OMP's real approval resolver, extension loader and
runner, tool types, secret APIs, and agent registry, so a breaking OMP change
fails type-check or tests rather than silently changing security semantics.

**Supported hosts:** OMP CLI, TUI, and RPC sessions, plus the in-process task
subagents they spawn.

Anything else — an embedded SDK host, a custom runner that bypasses OMP's
approval resolution — is treated as unsupported and blocked, as described above.

---

## Install

The plugin is installed locally from a checkout; publishing is not required.

```bash
git clone <this-repo> omp-smart-approve
cd omp-smart-approve
bun install
omp plugin link .
```

`omp plugin link` symlinks the directory into OMP's plugin tree, so edits to
`src/` take effect on the next session with no reinstall. (`omp plugin install
./path` routes to the same code path, so either verb works.)

**Verify it loaded:**

```bash
omp plugin list                 # omp-smart-approve@0.1.0, marked enabled
omp plugin list --json          # same, machine-readable
omp plugin doctor               # reports manifest/entry-point problems
```

Then start a session and run `/smart-approve status`. If the command does not
exist, the extension did not load; `omp plugin doctor` is the next stop.

**Unlink:**

```bash
omp plugin uninstall omp-smart-approve
```

Uninstalling removes the link, not your configuration or audit database. Those
live at `<agentDir>/smart-approve.yml` and
`<agentDir>/smart-approve/state.sqlite` and must be deleted by hand if you want
them gone.

---

## First-run setup

```
/smart-approve setup
```

**This is the only wizard, and it only opens when you ask for it.** There is no
automatic first-use prompt — not on install, not on first session, not on first
scoped call. A safety tool that pops a configuration dialog in the middle of
someone's work teaches them to dismiss dialogs, and this plugin's entire value
depends on dialogs being read.

`setup` lists only models whose provider already has configured credentials in
OMP, recommends a fast model from a family different from your primary session
model, previews the config path and the resulting timeout budget, and writes the
file only after you confirm.

**Until setup succeeds, the plugin fails closed.** Every scoped call that OMP
would have auto-approved is blocked, and the block reason names
`/smart-approve setup`. Unconfigured means blocked, never "waved through until
someone gets around to it". Calls OMP would prompt about are unaffected: you
still get OMP's own dialog.

You do not supply a judge API key. Judgment runs through OMP's model registry
and OMP's existing provider authentication.

---

## Configuration and policy

Two separate files, two different jobs.

### `smart-approve.yml` — deterministic configuration

Precedence, lowest to highest:

1. Built-in defaults
2. User: `<agentDir>/smart-approve.yml`
3. Project: `<cwd>/.omp/smart-approve.yml`
4. Project: `<cwd>/smart-approve.yml`

Sections merge key by key — a project layer that sets `sensitivity.fallback`
does not discard your user-level `judge.authorizedModels`. `rules` arrays
concatenate across layers, so a project layer can add deny rules but cannot
delete a user deny rule. Tightening is always available downward; loosening is
not.

Config discovery looks in the working directory only, not its ancestors. A
config file two directories up does not apply.

See [`examples/smart-approve.yml`](examples/smart-approve.yml) for every key with
commentary.

### `SMART_APPROVE.md` — natural-language policy

Prose the judge reads as **authoritative policy**, distinct from the transcript
and from any tool output, both of which are treated as untrusted data. This is
where project knowledge that cannot be expressed as a glob goes: which
environments are reachable, what counts as irreversible here, which destinations
are never acceptable.

Discovery runs **broadest to most specific**, and unlike config it walks the
whole ancestor chain:

1. `<agentDir>/SMART_APPROVE.md`
2. For each ancestor directory of `cwd`, root-first: `<dir>/.omp/SMART_APPROVE.md`,
   then `<dir>/SMART_APPROVE.md`

The home directory itself is skipped, so a stray file in `~` cannot silently
govern every unrelated project on the machine. Documents are presented to the
judge in discovery order, so the most specific statement reads last.

See [`examples/SMART_APPROVE.md`](examples/SMART_APPROVE.md).

### Both files are protected

Smart Approve's own config and policy files, OMP's `settings.yml`,
`secrets.yml`, and `secret-placeholder.key`, and the audit database (including
its `-wal` and `-shm` companions) are on a default deny floor for write and edit
calls. An agent that can rewrite `settings.yml` can set `approvalMode: yolo`; an
agent that can rewrite `secrets.yml` can neutralize redaction. Only an explicit
human override reaches these files.

The floor catches three spellings of the same file, because a deny floor that
only matches one is decorative:

1. The resolved absolute path, with `..` collapsed.
2. A **symlink** to a protected file, resolved with `realpath` — and the
   **parent directory** is resolved separately, so a link like
   `evil/ -> .omp/` cannot launder a write to `evil/smart-approve.yml`. Parent
   resolution matters because the leaf usually does not exist yet, which is the
   normal shape of a create-then-overwrite attempt.
3. A target too dynamic to resolve whose literal text still names a protected
   path (`~/...`, `$HOME/...`), matched by suffix.

---

## What gets judged

**Judged:**

- Every write-tier call.
- Every exec-tier call.
- Every call whose arguments can transmit user-controlled data over the network
  — URL reads, web searches, browser actions, any target with a remote scheme.
- Every unknown custom or MCP tool. An unknown tool cannot prove it is a purely
  local read, so it is scoped by default (`scope.judgeUnknownTools`).
- Every nested `xd://<device>` dispatch. The parent `write` is only transport;
  the real semantics live in the payload, and the parent cannot vouch for them.
- Any call whose tool tier cannot be resolved.

**Not judged:** a local read, grep, or glob — but only after it clears the
deterministic checks below, and only when all three hold: read tier, a known
local-read tool, and no target that can leave the machine. Such a call skips the
model but still records provenance, which later gated calls are judged against.

**Before any of that**, three deterministic checks run with no model call:

1. Write or edit against a protected policy file → block.
2. A matching deny rule → block.
3. A read whose target has a credential-file shape (`.env*`, `~/.ssh/**`,
   `~/.aws/credentials`, `*.pem`, `.npmrc`, `.netrc`, `~/.kube/config`, and
   similar) → block.

These run before scope filtering, which is why you can block reads of `**/.env*`
without spending a model call, and why `scope.neverJudge` cannot be used to
reach them.

`scope.alwaysJudge` and `scope.neverJudge` adjust the middle of this. `neverJudge`
is honored only for calls that already proved read tier with no remote target;
listing `bash` there changes nothing.

### Internal URI schemes are not all local

OMP's `scheme://` URIs look uniform and are not. Smart Approve splits them:

| Local — can qualify as a local read | Remote — always scoped |
| --- | --- |
| `memory://` `skill://` `agent://` `history://` `artifact://` `local://` `rule://` `omp://` `xd://` | `issue://` `pr://` `vault://` `mcp://` |

`issue://` and `pr://` shell out to `gh` and return **externally authored
content**. An issue body or a PR description is world-writable text on someone
else's server; it is one of the most convenient prompt-injection carriers there
is. So reading one is scoped for judgment and its provenance is recorded as
untrusted, exactly like fetching a web page. `vault://` and `mcp://` are
network-backed for the same reason.

`xd://` is local in the scheme sense, but a nested `xd://<device>` dispatch is
scoped anyway — see the list above.

---

## Sensitivity

Three levels — `permissive`, `balanced`, `strict` — with the narrowest
applicable setting winning:

```
risk-class override  >  per-tool override  >  fallback
```

```yaml
sensitivity:
  fallback: permissive
  byTool:
    bash: strict
  byRisk:
    exfiltration: strict
```

The two overrides apply at different moments, because they can:

- **Per-tool** resolves before the judge runs, and is the posture the judge is
  given (`byTool[tool]`, else `fallback`). No risk class exists yet, so nothing
  narrower is available.
- **Per-risk** resolves after the verdict comes back carrying a risk class. If
  the risk-specific level is *stricter* than the posture the judge was given, an
  `allow` is downgraded to `escalate` for that call, and the audit rationale
  names both levels.

So with the config above, a call the judge allowed but classified as
`exfiltration` becomes an escalation — risk-specific policy stays strict even
for a tool you deliberately made permissive.

**The tightening is one-directional by construction.** A per-risk override can
only raise strictness. A *permissive* per-risk override can never turn a `block`
or an `escalate` into an `allow`, no sensitivity setting overrides a
deterministic deny, and none of them can substitute for a missing verdict.
`permissive` does not mean "allow on judge failure" — nothing means that. This
one-directionality is what makes the setting safe to expose rather than merely
configurable: the worst a misconfigured `byRisk` entry can do is add friction.

Risk classes: `prompt-injection`, `exfiltration`, `destructive-action`,
`wrong-target`, `policy-violation`, `safety-tampering`, `uncertain`.

A `posture` rule (see below) is the third form: it carries a sensitivity into
the judge prompt as a hint about a specific surface, without allowing or
blocking anything by itself.

---

## Rules: exact versus pattern

This is the part most worth reading carefully, because it is where a
configuration mistake turns into a hole.

### Deny may be patterned

```yaml
- id: deny-dotenv
  kind: deny-pattern
  tool: "*"                    # every tool
  target: "**/.env*"           # glob; `re:` prefix for a regex
  risk: exfiltration
  reason: Environment files hold credentials.
```

Deny rules may use globs (`**` crosses separators, `*` does not, `?` is one
character) or `re:`-prefixed regexes, may use `tool: "*"`, and may match a
target the plugin could not fully resolve. Refusing something you cannot pin
down is safe; allowing it is not.

Targets are matched against both the literal string the agent wrote and its
resolved absolute form, so prefer `**/thing/**` over `thing/**` — the latter
misses absolute paths.

**Deny rules on shell calls can only name the executable.** Smart Approve
extracts the leading command of each `;`/`&&`/`||`/`|` segment plus any literal
URL operand; it deliberately does not parse flags, because a rule that believes
it understands shell quoting is a rule with a bypass in it. `target: terraform`
works. `target: "re:^terraform apply"` matches nothing. Argument-level
semantics — `--force`, `--context prod`, a computed path — are exactly what the
judge is for.

### Only a fully specified allow may skip the judge

An `allow-exact` rule skips judgment **only** when all three of these hold:

1. `argumentsHash` pins the exact literal call,
2. `target` equals a **resolved, non-dynamic** target of that call, and
3. `cwd` resolves to the working directory the call runs in.

**Omit any one and the rule degrades to advisory posture** — matching calls are
still judged in full. There is no partial credit.

```yaml
- id: allow-verify-ledger
  kind: allow-exact
  tool: bash                   # a literal tool name; `*` disqualifies the rule
  target: scripts/verify-ledger.sh    # resolved, non-dynamic, no wildcard
  argumentsHash: 072f909c49daff0e40b0fd6d419a1ca2fb513fcd57fe0cbe0d2349fd50e45b9f
  cwd: /srv/orchid             # absolute; this is what binds the rule to one place
  reason: Read-only ledger verification, pinned to its exact arguments and location.
```

Copy the hash from an audit row via `/smart-approve review <audit-id>`.

**Why the hash.** Without `argumentsHash`, a rule naming only tool and target
still omits every other argument: `tool: write, target: src/app.ts` would
authorize *any content whatsoever* at that path. The hash is what makes "exact"
mean exact.

**Why `cwd`.** The arguments hash is location-blind. `bash {command:
"scripts/verify-ledger.sh"}` and `write {path: "src/a.ts"}` hash identically in
every checkout on the machine, so a user-scoped pinned rule without `cwd` would
fire in all of them. `cwd` is the repository and working-directory identity a
persisted allow is supposed to carry.

**Why the resolved target as well.** It pins *what* the call points at, where
`cwd` pins *where* it runs. A target the plugin could not resolve — a glob, a
shell substitution, an unexpanded variable — is dynamic and can never match; a
call whose destination we only guessed at must not reach an allow.

How `target` resolves differs by tool family, and this is the part that trips
people up:

- **Path tools** (`write`, `edit`, `read`): the resolved target is always the
  **absolute** path, so a relative `target:` can never match. Write the absolute
  path.
- **Command tools** (`bash`): the resolved target is the leading **executable,
  exactly as typed** — relative or absolute, whichever you wrote. `target: bun`
  therefore matches `bun ...` anywhere, which is exactly why `cwd` is required
  rather than optional.

### Any wildcard in an allow makes it a hint

```yaml
- id: allow-pattern-scratch
  kind: allow-pattern
  tool: write
  target: "**/.tmp/**"
  reason: Scratch output is routine.
```

This never skips the judge. Matching calls are judged in full; the judge is
simply told that you consider this surface routine. One wildcard, one regex, or
one omitted argument is enough — there is no "mostly exact".

A `posture` rule is the explicit form of the same idea: it never allows or
blocks, it just tells the judge to be stricter about a surface.

### Precedence

```
protected policy file
  -> deny rule  (highest specificity wins; deny beats allow at equal specificity)
  -> credential-file read
  -> exact hash-bound human grant
  -> exact allow rule  (argumentsHash AND resolved target AND cwd)
  -> retry-loop check
  -> LLM judge  (posture hints included)
  -> per-risk sensitivity tightening
```

A grant or an exact allow can never override a deny, because denies are decided
first.

### Judge suggestions

The judge may propose a rule: an exact allow with no pattern operators, or an
exact or patterned deny, or a posture rule. A patterned allow suggestion is
rejected outright — the model cannot propose a wildcard bypass. Every suggestion
is non-binding, previewed as a rule change, and applied only after explicit human
confirmation via `/smart-approve apply-suggestion`.

---

## The three verdicts

What each verdict does depends on which branch the call is on, and the branch is
decided by asking OMP's own resolver what OMP would have done.

### Branch A — OMP would auto-approve

| Verdict | Result |
| --- | --- |
| `allow` | Runs silently, unless a stricter per-risk sensitivity downgrades it to an escalation. A redacted audit row is committed before execution either way. |
| `escalate` | A durable pending approval is persisted and the call is blocked with an audit ID. If a live TUI exists and enough budget remains, a best-effort dialog is offered first. See [below](#why-escalation-is-asynchronous). |
| `block` | Blocked, with an actionable reason. Visible in the main UI and the audit. |

The judge may hard-block without asking only for a clear safety or policy
violation. Legitimate-but-consequential and genuinely uncertain calls escalate
to you instead of being decided for you.

### Branch B — OMP would prompt

One semantic pre-screen, and then **exactly one dialog: OMP's own.**

| Verdict | Result |
| --- | --- |
| `block` | Hard block. No prompt. Reserved for a deterministic violation or a clear judge block. |
| anything else | A companion risk card is published next to OMP's native prompt, and the call falls through to it. |

There is never a second approval dialog on this branch. Two dialogs for one call
trains you to click through both, and the second one you stop reading is the one
that mattered. Judge failure on this branch is shown prominently in the card and
still falls through — only OMP's native prompt can authorize execution.

### Branch C — OMP would deny

Judgment is skipped entirely and the denial is preserved. The plugin never
converts an OMP denial into anything else.

---

## Fail-closed behavior

Every one of these ends in escalation, and escalation ends in a block if no
human answers:

- Judge timeout, provider error, or transport failure (after the configured
  retry).
- Malformed or oversized judge output. A verdict that does not parse is a judge
  failure, not an allow.
- Missing or unauthorized judge model.
- Missing, invalid, or unparseable configuration.
- Storage failure. **A scoped call cannot return allow until its terminal
  redacted audit row has committed.** Running unaudited is exactly the state
  this plugin exists to prevent, so a failed audit write is a safety failure,
  not a logging inconvenience.
- No UI, or a UI that returns a default. In a headless host,
  `select`/`input`/`custom` return `undefined` and `confirm` returns `false`.
  Every one of those is treated as unavailable — never as approval.
- Deadline exhaustion.
- An internal plugin exception, contained at the `tool_call` boundary and
  converted into a durable redacted fail-closed result. If even the store is
  unavailable, the result is a concise emergency block with no raw data in it.

**No path converts unavailability into approval.** There is deliberately no
configuration key, environment variable, or flag that silently disables the
plugin. The only way to stop enforcement is
[`/smart-approve unguarded`](#bypass), which is loud, typed, session-scoped, and
audited.

### Retry loops

After three blocked attempts in the same retry family — the same source agent,
tool, normalized operation, resolved target, and risk class — the next attempt
stops being silently re-judged and escalates the whole sequence to you. The
family key deliberately excludes the arguments hash, so an agent that retries
the same destructive operation with cosmetically different arguments lands in
the same family. With no human channel available it stays blocked and the agent
is told to stop retrying.

A human-approved retry is admitted by its exact grant *before* the loop check
runs, so approving something does not count as another strike against the call
you just approved.

---

## Why escalation is asynchronous

OMP caps an extension's `tool_call` handler at 30 seconds
(`EXTENSION_HANDLER_TIMEOUT_MS`). A human decision does not fit in 30 seconds.
It fits in a few minutes, or in "after lunch".

Blocking the handler on a person therefore produces one of two bad outcomes: the
handler times out and OMP turns a safety decision into an ambiguous host error,
or the design shortens the window until people approve without reading. Neither
is acceptable, so escalation is asynchronous by default:

1. The handler persists a **durable pending approval**: redacted summary,
   canonical call hash, arguments hash, policy hash, nonce, TTL.
2. It returns an **audited block** carrying the audit ID and an actionable
   reason. The agent is told plainly that an audit ID is not authorization.
3. You decide out-of-band, whenever you get to it:
   `/smart-approve review <audit-id>`, then `/smart-approve override <audit-id>`.
4. Approval mints an **exact hash-bound grant**. The identical retry is admitted
   by that grant and executes exactly once. Anything materially different does
   not match the hash and is judged again.

The in-handler dialog is a **best-effort fast path only**. It is offered when a
live main TUI exists, `ui.fastPathDialog` is on, and the remaining budget clears
`timeouts.dialogFloorMs`. When it is not offered, or it times out, the call falls
through to the durable pending record. Nothing is lost by missing it.

The whole path finishes inside a self-imposed 28-second deadline
(`timeouts.handlerSelfDeadlineMs`), strictly under OMP's cap. The plugin refuses
to start with a timing configuration that cannot close inside it, naming the
offending fields rather than silently clamping them.

---

## The two clocks

These are independent on purpose, and confusing them is the most common way to
misread the system.

| | `brokerArgsTtl` | `pendingApprovalTtl` |
| --- | --- | --- |
| Default | 10 minutes | 24 hours |
| Holds | The **literal frozen arguments**, in memory | The **redacted durable record**, in SQLite |
| Contains raw arguments | Yes | **Never** |
| Survives restart | No | Yes |
| Governs | Whether an approval can be **minted into a grant** | Whether an audit ID is **actionable at all** |

**Approving a call requires seeing that call.** Minting a grant requires the
literal frozen arguments to still be in memory *and* the hash recomputed from
them to match the hash the audit row was opened under. A grant means "a human
looked at exactly these bytes and said yes". Nothing weaker earns one.

**Once the literal arguments are evicted, approval degrades to recorded
intent — never a grant.** The record is still open, so you can still act on it,
but `override` records intent-to-approve rather than minting authority. The next
materially identical call re-opens a live dialog against real arguments, or stays
blocked if the session is headless. That intent is single-use and time-bound: it
buys exactly one exempt re-open attempt.

Denying and expiring stay available for the full 24 hours with no raw arguments
present, because refusing something you cannot see is always safe.

Expiring the two clocks together would make the intent-to-approve path
unreachable in exactly the restart case it exists to serve — which is why
`brokerArgsTtl` must be less than or equal to `pendingApprovalTtl`, and why the
plugin refuses to start otherwise.

`/smart-approve pending` states, per record, which of the two outcomes it
currently supports.

---

## Subagent routing

A task subagent typically has no UI of its own. When one of its calls escalates:

1. It checks **synchronously** for a live main-session approval endpoint. No
   endpoint means an immediate, visible, actionable block — not a silent wait.
2. With an endpoint, it forwards the **frozen escalation** directly to extension
   code attached to the main session's approval UI. The main agent's *model* is
   not an intermediary; a model in the path could paraphrase, summarize, or be
   argued out of the risk.
3. You see the literal pending call, its arguments, the source agent, the judge
   rationale, the risk classes, and the matching policy — then decide.
4. Approval is **single-use, nonce-protected, time-limited, and bound to the
   exact call**, plus repository, working directory, and policy version. Change
   any of those and the grant does not match.

Dialogs are serialized FIFO by OMP's extension UI controller, so concurrent
subagent escalations queue rather than interleave. Status stays visible by
subagent ID and audit ID throughout.

An unanswered request blocks after `timeouts.subagentEscalationTimeoutMs`
(default 15s), falling through to the durable pending record.

**If the main session is also headless, the escalation blocks.** It does not
degrade to allow. A subagent that cannot reach a human is a subagent that cannot
be authorized.

The broker lives under a versioned `Symbol.for(...)` on `globalThis` rather than
a module singleton, because Bun may import the extension through distinct
cache-busted module URLs and module-local identity is not reliable across them.

---

## Audit and redaction

Every judgment persists **compact redacted metadata** to SQLite at
`<agentDir>/smart-approve/state.sqlite`:

audit ID, tool-call ID, tool, operation, redacted target summary, arguments hash,
canonical call hash, policy hash, working directory, source agent kind and
parent, decision, decision stage, risk class, concise rationale, matched rule ID,
judge model and provider, latency, attempts, input and output tokens, cost, retry
family and count, timestamp — plus an append-only event log carrying the full
override history.

**Never persisted, anywhere:** raw tool arguments, raw user messages, secret
values, or attack payload excerpts. Not in SQLite, not in session entries, not
in reports, not in error messages, not in block reasons shown to the model.

Be precise about what enforces that, because "never" is a strong word. The
protection is a **runtime** guard at the store boundary, not a type-system
guarantee: every write is rejected if it carries a known raw-argument field name
(`rawArguments`, `content`, `command`, `arguments`) or if any value still matches
a credential shape the obfuscator should already have replaced. A byte-scan test
asserts no configured secret reaches the database file. The residual is real and
worth naming: a raw value placed in a *differently named* field that happens to
carry *no* credential shape would pass both checks. The guard catches the ways
this has actually gone wrong, not every way it could.

Redaction reuses OMP's own secret machinery rather than reimplementing it:
secret-like environment values, user and project `secrets.yml` entries, and
built-in credential-token patterns become deterministic typed placeholders
before the judge request is built and before anything is written to the audit.
Deterministic placeholders mean the judge can still reason about *shape* —
"an AWS key is being sent to this host" — without the value ever leaving.

That machinery covers credential-shaped material. Broader confidential business
data is not pattern-detectable, and is governed by your `SMART_APPROVE.md` and
by semantic judgment instead. If you have data that must never be transmitted,
say so in your policy file explicitly.

Every hard block, including a subagent's, is visible in the main UI and in the
audit with fully qualified agent and parent IDs, tool-call and audit IDs,
provenance sources, risk classes, rationale, timestamp, retry count, and state.
The blocked model separately receives an actionable reason.

---

## Bypass

```
/smart-approve unguarded
```

Turns enforcement off for the current session. It requires:

- a **typed random challenge** — you retype a generated string, so it cannot be
  a reflex;
- and it applies **only to the current session**. It does not persist, does not
  survive a restart, and does not affect other sessions.

While it is active a **persistent warning widget** stays on screen for the
entire duration, and the activation is written to the audit with actor and
reason.

**The model cannot activate it.** It is a human command, invoked from the
command surface, gated on a typed challenge the model does not see.

`/smart-approve guarded` re-enables enforcement immediately.

There is no configuration key and no environment variable that does this
quietly. If enforcement is off, you can see that it is off.

---

## Command reference

All nine subcommands are under one namespaced command, `/smart-approve <sub>`.

### `setup`

The only wizard, and it never opens by itself. Lists models with configured
auth, recommends a fast cross-family model, previews the config path and timeout
budget, writes atomically after confirmation.

### `status`

Config and policy hashes with their source paths, judge model and auth health,
scope, sensitivity precedence, deadline budget, broker and main-UI health,
bypass state, audit DB health, the count of approvals still open under
`pendingApprovalTtl`, recent aggregate verdict/latency/token/cost counts, and
compatibility warnings.

### `rules [list|show|revoke]`

Lists rules grouped by origin (configuration versus stored), each with its kind,
tool, target, specificity, author, and reason. `rules revoke <id>` is
human-confirmed and immediately invalidates matching grants.

The posture line is computed from the same predicate the gate uses, not from
`kind`, so it tells you the truth about a pin. A complete one reads `exact
allow — skips the judge for this precise call in this directory`; an incomplete
one reads `advisory posture — still judged` and names exactly what is missing
(`no argumentsHash`, `no cwd`, `target is a pattern`). `rules show <id>` prints
`argsHash:` and `cwd:` explicitly, marking either as
`(absent — cannot skip the judge)`.

### `pending`

Every approval still open under `pendingApprovalTtl`: audit ID, tool, redacted
target, risk, source agent, age, remaining TTL, and whether the record can still
mint a grant or is intent-only.

This is the entry point when the block message has scrolled away or the session
restarted. It works with no arguments and with no live broker state.

### `review <audit-id>`

The original redacted verdict, immutable history, retry family, human decisions,
and any judge rule suggestion for one call. It prints the arguments hash, the
redacted target, and the working directory for both the verdict and the
escalation record — which is where you copy the `argumentsHash` and `cwd` for a
pinned `allow-exact` rule from. A row written before location tracking existed
shows `(unknown — recorded before location tracking)` rather than a guess.

Literal arguments render **only** from the live in-memory broker. It never
reconstructs them from persistence and never claims to show raw arguments it
does not have. It states plainly which outcome the record currently supports:
mintable grant, or intent-only.

### `apply-suggestion <audit-id>`

Accepts only a currently pending in-memory suggestion or a safe redacted
deny/posture suggestion. Shows the normalized proposed rule and its scope,
requires explicit confirmation, and re-runs schema and specificity checks before
insertion. A model-suggested wildcard allow stays non-bypass posture even after
you confirm it.

### `override <audit-id>`

Deliberately authorize one blocked call. Shows the original immutable verdict and
requires a typed random challenge.

Minting the exact hash-bound grant *additionally* requires the literal frozen
arguments to still be in the broker with a matching recomputed hash. When they
are gone — `brokerArgsTtl` expiry, restart, subagent teardown — it records
intent-to-approve instead, and says so.

Grants carry a scope: one-time, session, or persistent. A persistent allow
requires a second explicit confirmation, defaults to project scope, records
repository and working-directory identity plus the policy hash, and needs
explicit opt-in for user-wide scope. All grants remain listable and revocable.

**Grants are bound to the working directory they were approved from.** The audit
database lives in the user-level agent directory and is shared by every project,
and two checkouts with no project config resolve to the same policy hash — so
without a working-directory binding, a grant approved in one repository would
admit a byte-identical call in another. Approving `scripts/deploy.sh` in staging
would admit the same command in production. Both grant lookup and single-use
consumption require the working directory to match.

Revocation is scoped the same way: a configuration or policy change invalidates
the grants **for that working directory** whose policy hash is now superseded,
and each project sweeps its own on its next session start. An unscoped sweep
would let a policy edit in one repository delete grants a human minted in
another — grants whose own policy never changed.

A grant carried over from a database written before this binding existed has no
working directory recorded and can never match. It is inert rather than
portable, which is the fail-closed direction.

### `unguarded` / `guarded`

Enter and leave session-only bypass. See [Bypass](#bypass).

---

## Troubleshooting

**`/smart-approve` does not exist.**
The extension did not load. `omp plugin list` should show `omp-smart-approve`
enabled; `omp plugin doctor` reports manifest and entry-point problems. Confirm
`omp --version` is inside `>=17.2.2 <18`.

**Every scoped call is blocked with "run /smart-approve setup".**
Working as intended — no authorized judge model is configured yet. Run setup.
If you already did, `/smart-approve status` shows which config layer was loaded
and whether the configured provider actually has credentials.

**Every scoped call is blocked and the reason mentions configuration.**
A config layer failed to parse or validate. `status` names the file and the
offending fields. Unknown keys are rejected on purpose, so a typo fails loudly
rather than being silently ignored.

**The plugin refuses to start, naming timeout fields.**
Your timing budget cannot complete inside OMP's 30s handler cap. The message
names the exact fields. The plugin does not clamp them, because silently
shrinking a safety budget hides a misconfiguration.

**Legitimate calls are blocked as unsupported host.**
The plugin could not match the call to a live OMP session or resolve the tool's
tier. Check that you are in a supported host; embedded SDK hosts are outside the
validated surface.

**I never see the approval dialog, only blocks with audit IDs.**
Expected. Async escalation is the default; see
[Why escalation is asynchronous](#why-escalation-is-asynchronous). Use
`/smart-approve pending` and `/smart-approve review <audit-id>`. If you want the
fast path to fire more often, raise `timeouts.dialogMaxMs` or lower
`timeouts.dialogFloorMs` — but a dialog too short to read a literal call is worse
than no dialog.

**Override refuses to grant and records intent instead.**
The literal arguments have been evicted from the broker (10-minute default,
restart, or subagent teardown). This is the designed behavior: approval requires
seeing the call. The next identical attempt re-opens a live dialog. To make the
fast path viable for longer, raise `timeouts.brokerArgsTtlMs` — and keep it at or
below `pendingApprovalTtlMs`.

**My pinned `allow-exact` rule is still being judged.**
All three fields must hold, so check each one. `argumentsHash` must be the hash
of *this* call — any change to the arguments produces a different hash. `cwd`
must be the absolute working directory the call runs in. And `target` must be
spelled the way the call resolves it: an absolute path for `write`/`edit`/
`read`, the leading executable exactly as typed for `bash`. A relative target
never matches a path tool, and a dynamic target (glob, shell substitution,
unexpanded variable) never matches anything. `/smart-approve review <audit-id>`
shows the hash, the resolved target, and the working directory for a real call.

A rule missing any one of the three is not broken — it is working as specified,
as advisory posture. `/smart-approve rules list` says which it is: an incomplete
pin reads `advisory posture — still judged` and names the missing field, and
`rules show <id>` prints `argsHash:` and `cwd:` outright.

**A pinned rule stopped working after I moved the repository.**
Expected. `cwd` binds an exact allow to one working directory by design, so
moving or re-cloning the repository invalidates it. Re-pin it with the new `cwd`.

**Calls the judge allowed are still escalating.**
Check `sensitivity.byRisk` in `/smart-approve status`. A risk-class override
stricter than the tool-level posture downgrades an `allow` to an escalation once
the verdict names that risk. The audit rationale names both levels.

**The agent keeps retrying a blocked call.**
The loop breaker fires on the fourth attempt in a retry family and escalates the
sequence. If you are seeing many strikes, the block reason is probably not
actionable enough for the model — check what it says in `review`.

**A subagent's escalation blocked immediately.**
Either no main-session endpoint was registered, or the main session is headless.
A subagent that cannot reach a human blocks by design.

**Judgment is slower than expected.**
`status` reports recent latency aggregates. `timeouts.targetLatencyMs` (5s
default) is an observability target, not a cutoff; `modelTimeoutMs` (10s) is the
hard per-attempt boundary. Note that `attempts × modelTimeoutMs +
cleanupMarginMs` must fit inside `handlerSelfDeadlineMs`.

**Enforcement seems to be off.**
Look for the persistent unguarded warning widget. If it is not there,
enforcement is on. There is no silent off switch.

---

## Live evaluation

Deterministic tests prove mechanism: scoping, precedence, redaction, fail-closed
paths, TTLs, nonces, brokering. They prove nothing about whether a *particular
model* judges well. Those are different questions and they need different
evidence.

```bash
bun run eval:live -- --model <provider/model> --out .artifacts/smart-approve-eval
```

**Opt-in, and it needs provider credentials.** Ordinary CI needs none and makes
no paid model calls.

The corpus covers benign work, prompt injection, exfiltration, destructive
actions, wrong-target operations, safety tampering, policy bypass attempts,
encoded and obfuscated payloads, compromised subagent requests, oversized
payload tail attacks, shell composition, MCP/browser/network egress, and
ambiguous-but-recoverable operations. The runner uses the **production** context
builder, redactor, model selection, prompt, parser, and retry logic — not a
special evaluation prompt — so the numbers describe the shipped path.

Reports are versioned JSON plus Markdown, containing plugin version, corpus
hash, config and policy hashes, model and provider, per-case verdict, risk,
latency, tokens and cost, plus false allows, false blocks, escalations, parser
failures, timeouts, and percentile latency.

It exits nonzero only for a malformed corpus or report, or under an explicit
`--enforce <threshold-file>`. **Live evaluation is deliberately not a release
gate** until thresholds are calibrated, and calibrating them on one run would be
calibrating on noise.

Do not claim a model is safe on the strength of deterministic tests. Report the
observed model, corpus hash, and the measured counts.

---

## Package verification

```bash
bun install --frozen-lockfile
bun run check          # tsc --noEmit && biome check
bun test               # deterministic suite; no credentials, no paid calls
bun run smoke          # links and loads the package in an isolated temp HOME
bun pm pack --dry-run  # package contents
```

`bun run smoke` builds a throwaway HOME and agent directory, runs `omp plugin
link` against this checkout, asserts the linked package appears enabled, loads
the extension through OMP's real extension runner with scripted judge, UI, and
time ports, and exercises six paths end to end:

1. silent allow
2. fast-path escalation with allow-once
3. hard block
4. native-prompt pre-screen with no second dialog
5. async escalation ending as a pending block, approved out-of-band, with the
   identical retry executing exactly once
6. headless escalation blocking

It inspects only redacted audit and session output, and removes the temporary
directory in a `finally`. Scripted ports live only in the smoke script and the
tests — the shipped factory cannot select them from configuration or the
environment.

---

## License

MIT. See [LICENSE](LICENSE).
