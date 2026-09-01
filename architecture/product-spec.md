<!-- paos:reviewed=2026-09-01 -->
# Product specification

## Product loop

```text
connect sources
  ↓
collect / hash / timestamp evidence
  ↓
deterministic control checks
  ↓
optional AI-assisted evidence discovery
  ↓
readiness graph + gaps
  ↓
remediation plan
  ↓
re-scan
  ↓
buyer pack / trust centre / API
  ↓
monitor freshness / expiry
```

## Workflow 1 — Evidence-backed readiness scan

A team connects the selected sources and readiness profile. TrustReady evaluates each control against inspectable evidence.

Acceptance:
- every result shows requirement, evidence, observation, unknowns, freshness and rule/profile version;
- deterministic checks remain distinguishable from AI-assisted discovery;
- absent evidence does not become a fabricated pass;
- each score/control state can be traced to evidence or authorised attestation.

## Workflow 2 — Gap → remediation → re-scan

The scan identifies a gap and the team needs an exact path to close it.

Acceptance:
- remediation is concrete and tied to the failed/unknown control;
- the system does not mark the control closed merely because advice was generated;
- a re-scan evaluates new evidence under the same or explicitly changed profile/rule version;
- history preserves the before/after evidence state.

## Workflow 3 — Buyer verification / expiry

A buyer receives a trust centre/buyer pack/API result and needs to verify it without trusting a black box.

Acceptance:
- evidence/rule provenance is reproducible;
- stale/expired evidence is visible;
- unknowns and authorised attestations remain distinguishable from independently observed evidence;
- a `100/100` score is scoped to the selected profile only;
- continuous monitoring can reopen a control when evidence expires or materially changes.

## Failure states

- score without evidence path;
- AI-generated assessment treated as final authority;
- stale evidence silently stays green;
- control closes without accepted evidence/authorised attestation;
- framework mapping marketed as certification;
- different rule versions produce a result without the version difference being visible.
