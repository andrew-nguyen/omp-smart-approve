# Changelog

## Unreleased


### Features

* lead every escalation surface with a deterministic SBAR (Situation, Background, Assessment, Recommendation), so an operator can decide an override from what the agent was asked to do, what it said it was doing, and why it was stopped, instead of forensic data alone
* persist the redacted, clamped SBAR ingredients on the pending record, so `review` and `pending` still explain a held call after a restart
* notify the main session with one line when an escalation goes asynchronous, naming the call, the risk, and the `review` command that decides it
* show the verdict, risk, tool, and target on screen while `/smart-approve override` asks whether to deny, expire, or approve. The block was previously built but only printed in the transcript after the command finished, so the choice was made with nothing but an audit ID visible
* refuse to judge a request larger than `judge.maxPromptBytes` (96 KB default) instead of sending it. Nothing previously bounded the assembled prompt in aggregate, and an oversized one that reaches a provider may quietly succeed and return a verdict, including `allow`, formed on a prompt too large to have been read carefully. The refusal is a `input-too-large` judge failure, which escalates like every other


### Miscellaneous Chores

* rewrite the escalation, review, pending, and risk-card copy as plain sentences, pinned by a rendering test


### Bug Fixes

* escape control characters in target summaries and in the rationale shown beside an override, so a newline in a tool argument or a prompt-injected judge rationale cannot forge a row of decision support. Escaping is injective, so `a\nb.txt` and `a b.txt` remain distinct in the audit record
* bound the target summary and the override rationale when rendering, so an oversized value cannot swamp a block that has to be read before a decision. The durable record keeps the full summary, since literal arguments are never persisted
* quote, neutralize, and bound the `tool`, `operation`, and `requesting agent` fields in the judge prompt. `operation` is `${toolName}:${args.action}` for action-style tools, so it is agent-controlled; on a bare `key: value` line outside every evidence fence it could forge a `## AUTHORITATIVE POLICY` section, and unbounded it carried arbitrary bytes past the arguments-size budget into the model's window. Rule matching, retry hashing, and the audit row still see the raw value
* bound the judge prompt's targets section, which duplicates every extracted target outside the size-bounded arguments view. One 60 KB path previously added about 120 KB there, and because a 60 KB path stays under the preserved-field limit the request was not flagged as incomplete, so the judge could still answer `allow`. Targets are now capped in count and length, the omitted count is stated, and anything hidden forces incomplete-context semantics, which forbid `allow`

## [0.1.1](https://github.com/andrew-nguyen/omp-smart-approve/compare/v0.1.0...v0.1.1) (2026-08-03)


### Bug Fixes

* add repository metadata required for npm trusted publishing ([ee935fa](https://github.com/andrew-nguyen/omp-smart-approve/commit/ee935fa0275d72629dc8e2cca761b4a5ec740a5b))

## 0.1.0 (2026-08-03)


### Features

* add built-in deny floor and stricter exact-allow requirements ([d93c401](https://github.com/andrew-nguyen/omp-smart-approve/commit/d93c4013985ad2701e7acbd48b54d6b8f24396c0))
* Initial commit for omp-smart-approve plugin ([edf7635](https://github.com/andrew-nguyen/omp-smart-approve/commit/edf76351cefdc19af1dd41293ca87b66bb398919))


### Bug Fixes

* accept markdown-fenced JSON verdicts from models ([704f760](https://github.com/andrew-nguyen/omp-smart-approve/commit/704f7609b24dce6d041c13e1254a47401aa9ae1e))
* improve approval diagnostics and operator guidance ([57e3e50](https://github.com/andrew-nguyen/omp-smart-approve/commit/57e3e50f49a414760f8dfa979e39c1fcc08c3f16))
* widen built-in deny floor to all tools ([8025d57](https://github.com/andrew-nguyen/omp-smart-approve/commit/8025d57a3c826dea145f24858582a46235414482))


### Miscellaneous Chores

* release 0.1.0 ([276342f](https://github.com/andrew-nguyen/omp-smart-approve/commit/276342f9e013170f87ebe680a6d20931eb0b641d))
