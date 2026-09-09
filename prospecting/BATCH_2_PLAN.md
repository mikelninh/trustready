# Prospect Security Signal — Batch 2 plan

Goal: improve precision before outbound, not maximize finding count.

## What Batch 1 taught us

1. **Repo-wide keyword evidence is too weak for a sales claim.** A repo can contain action code and security controls in unrelated layers.
2. **Provider adapters are not effect executors.** Parsing `tool_calls` in an LLM adapter must not be treated like actually executing a tool.
3. **Tests/docs/examples create misleading controls and effects.** These paths must be excluded from production evidence.
4. **Generic words are dangerous heuristics.** `update`, `payment`, `publish`, etc. need execution-shaped context before they count as consequential effects.
5. **Same-path evidence is much stronger.** `model-selected tool call -> dispatch sink`, with or without a local independent authority check, is the most useful public-source signal so far.
6. **Human review is mandatory before outbound.** Automated classification is triage, not a vulnerability claim.
7. **Precision matters more than recall.** It is better to discard a real lead than contact a team with a weak or incorrect security claim.

## Batch 2 experiment

Scan a broader architecture set: general agent frameworks, MCP frameworks, coding agents, browser agents, and orchestration systems.

Two previously reviewed repos act as calibration controls:
- `superagentxai/superagentx` should remain a high-priority `PROOF_GAP` candidate.
- `browser-use/browser-use` must **not** regress back to a `PROOF_GAP` based only on provider-adapter parsing.

Every new `PROOF_GAP` must enter a human-review queue. No outbound is sent automatically.

## Metrics

- targets scanned
- scan failures
- `PROOF_GAP` rate
- `REVIEW_SIGNAL` rate
- weak/uncertain rejection rate
- human-reviewed true-signal rate
- false-positive categories
- outbound-approved rate
- reply / meeting / paid-validation conversion (later)

## Truth boundary

Passive public-source analysis only. No target execution, production testing, credential use, exploitation, or vulnerability claim without authorized runtime validation.
