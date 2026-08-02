# Goal: OMP Smart Approval

Ship a release-ready, locally installable OMP plugin that puts an LLM safety judge in front of tool calls OMP would otherwise auto-approve. It hard-blocks clear attacks and clear mistakes, escalates genuine uncertainty to a human, and leaves OMP's native approval dialog as the only prompt for calls OMP already asks about.

The two threats it exists to catch: **malicious calls** arriving through prompt injection or other untrusted content, and **well-intentioned but wrong calls** from a model sincerely pursuing your goal into something destructive or irreversible.

## Shared understanding

[`facts.md`](./facts.md) — 44 accepted, testable facts defining the behavior. Every fact has automated verification selected, so they are release requirements rather than aspirations.

Provenance: [`facts-review.json`](./facts-review.json) (bundle as presented) and [`facts-result.json`](./facts-result.json) (submitted result), with per-fact metadata in [`facts.meta.json`](./facts.meta.json).

## Execution plan

[`plan.md`](./plan.md) — approved. Thirteen ordered, test-first steps with per-step verification commands, a validated map of the OMP 17.2.2 host contracts it depends on, an accepted-fact coverage matrix, and ten named risks with mitigations.

Load-bearing design decisions worth knowing before you start:

- **Escalation is asynchronous by default.** OMP hard-caps tool-call handlers at 30s, which is too short for a human decision. Escalation persists a durable pending record and returns an audited block; the human decides out-of-band and the approved retry is admitted by an exact hash-bound grant. An in-handler dialog remains as a best-effort fast path when a live TUI and leftover budget allow.
- **Approval requires seeing the literal call.** Minting an allow grant requires the frozen arguments to still be in memory with a matching recomputed hash. Once evicted, approval degrades to recorded intent, never a grant.
- **Two independent clocks.** `brokerArgsTtl` (10m) governs whether a grant can be minted; `pendingApprovalTtl` (24h) governs whether an audit ID is actionable at all. Strike exemption for the loop breaker is bounded separately again, so a deliberating human never buys the agent an unbounded retry budget.
- **Fail closed everywhere.** Judge failure, config failure, storage failure, missing UI, and deadline exhaustion all end in escalation and then block. No path converts unavailability into approval.

## Done condition

The goal is complete when:

1. The deterministic release sequence passes from a clean install — `bun install --frozen-lockfile && bun run check && bun test && bun run smoke && bun pm pack --dry-run` — with no provider credentials required.
2. The isolated smoke proves OMP can `plugin link` and load the package and enforce all six representative paths: silent allow, fast-path escalation with allow-once, hard block, native-prompt pre-screen without a second dialog, async escalation approved out-of-band with the retry executing exactly once, and headless escalation blocking.
3. Every accepted fact (`fact-01`…`fact-44`) maps to automated evidence in the plan's coverage matrix.
4. No raw configured secret or raw argument appears in SQLite, session entries, reports, or error messages.
5. Opt-in live evaluation runs on demand and emits a versioned machine-readable report; it is deliberately not a release gate until thresholds are calibrated.
6. No unresolved blocker is hidden behind a fail-open path.
