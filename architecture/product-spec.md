# TrustReady — Product Spec

## Core workflow
1. Connect or upload evidence sources.
2. Hash/timestamp and preserve inspected evidence metadata.
3. Map evidence to versioned controls/readiness profile.
4. Run deterministic checks; allow AI only for bounded evidence discovery/triage.
5. Show readiness graph, gaps, unknowns and freshness.
6. Generate exact remediation actions.
7. Re-scan and compare what changed.
8. Export a buyer pack / trust centre / API result.
9. Monitor evidence expiry or material change where configured.

## User promise
For each control: **what is required → what was inspected → what was observed → what is unknown → what closes the gap**.

## Acceptance
A skeptical reviewer must be able to inspect/reproduce why a control is marked ready, partial or unknown.
