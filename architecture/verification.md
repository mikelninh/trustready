<!-- paos:reviewed=2026-09-01 -->
# Verification

## Evidence ladder

`DECLARED → STATIC → AUTOMATED → E2E → DOGFOOD → BUYER REVIEW → PILOT → PRODUCTION`

TrustReady itself must satisfy the same evidence discipline it asks of other systems.

## Verification principles

- every readiness state links to the evidence item(s) and rule/profile version that produced it;
- deterministic controls are tested independently from AI-assisted evidence discovery;
- authorised attestations remain distinguishable from independently observed evidence;
- expired/stale evidence can reopen a previously satisfied control;
- remediation only closes a control after accepted evidence is observed on re-scan;
- a public score never claims more than the selected profile and current evidence support.

## Golden-case verification

### GC1 — Reproducible readiness graph

- [ ] representative evidence sources are collected with source, scope, timestamp/freshness and fingerprint where appropriate;
- [ ] two independent runs over the same evidence + rule/profile version reproduce the material control state;
- [ ] every unknown/pass/fail can be traced to evidence or explicit attestation;
- [ ] AI discovery cannot grant a pass on its own.

### GC2 — Gap → remediation → re-scan

- [ ] at least one real repository starts with a meaningful failed/unknown control;
- [ ] TrustReady proposes a concrete remediation linked to that control;
- [ ] the team applies the change;
- [ ] re-scan records new evidence and a before/after state transition;
- [ ] the control remains open if the evidence is still insufficient.

### GC3 — Buyer verification / expiry

- [ ] buyer-pack or trust-centre output can be independently inspected without trusting a prose summary;
- [ ] profile/rule version is visible;
- [ ] one accepted evidence item is expired/changed in a fixture or dogfood run;
- [ ] affected control reopens and downstream output changes accordingly;
- [ ] no certification/government-approval claim is introduced by score language.

## First dogfood target

Use the systems we already own as adversarial fixtures rather than inventing a friendly toy repository.

Recommended sequence:

1. **Digital Worker Factory** — scan capability contracts, approval gates, production boundaries, tests and architecture pack.
2. **GitLaw Pro** — verify evidence for source integrity, professional-authority boundaries and pilot claims without ingesting confidential matter data.
3. **PrüfPilot** — test production-readiness evidence, tenant isolation, idempotency and human-approval claims.
4. **CareOS** — ensure the scanner preserves explicit blocked/unproven clinical claims instead of rewarding repository sophistication with an inflated readiness conclusion.

This sequence is valuable because the four products have deliberately different evidence levels.

## Current proof statement

The product contract and target trust model are strong. Do **not** describe all three golden cases as verified until the scanner/control engine, evidence graph, remediation/rescan and expiry behaviour have executable evidence linked from this repository.

## Next proof level

The best next milestone is a public, reproducible dogfood report showing:

`scan → evidence → gap → exact remediation → repository change → re-scan → changed control state`

on at least one real project, followed by a second reviewer reproducing the material result.
