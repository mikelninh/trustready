# Harness handoff

## Status
Ready for independent verification.

## Current step
Run the new harness check plus existing TrustReady CI and inspect the pull request.

## Evidence
- `AGENTS.md` maps TrustReady's authoritative docs and hard boundaries.
- `.harness/project.json` binds sensors, action classes and retry policy to the repository.
- `scripts/harness-check.mjs` mechanically rejects malformed tasks and unapproved A3/A4 actions in receipts.
- `.github/workflows/harness.yml` makes the minimum contract continuously testable.

## Decisions
- Keep TrustReady's existing trust kernel and legal promotion path authoritative.
- The harness coordinates work; it does not replace evidence or grant authority.
- Unknown/missing evidence remains fail-closed.
- Builder and Verifier remain separate for consequential claims and live-stage changes.

## Failures / uncertainties
CI has not yet produced evidence for this branch.

## Open risks
Harness v0.1 checks repository/process invariants, not substantive legal compliance or independent audit quality.

## Next owner
Verifier — run all gates, inspect for boundary regression, then record an accepted/partial/rejected receipt rather than relying on a summary message.
