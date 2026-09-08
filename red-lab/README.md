# TrustReady Controlled Vulnerability Research Lab

A deliberately bounded, **local synthetic-only** security research proof.

The lab exists to demonstrate a mature workflow for advanced authorized security work:

`explicit scope → controlled exploit validation → patch → regression proof → machine-readable evidence`

It is **qualification evidence only**. It does not claim Daybreak Red approval, production-security certification, or authorization to test third-party systems.

## Boundaries

- No public-network target is permitted.
- No production target is permitted.
- No third-party system is permitted.
- Current fixtures use only `lab://` synthetic targets.
- The public proof performs no network request, shell execution, credential collection, persistence, malware deployment, or service disruption.
- Any future expansion requires a new explicit authorization manifest and review.

## Golden cases

1. **RL-001 — synthetic injection semantics**: prove exploit-before-fix, then prove exact-match patch blocks the payload.
2. **RL-002 — synthetic authorization bypass**: prove the deliberately vulnerable fixture accepts an unauthenticated request, then prove the patch denies it.
3. **RL-003 — scope escape**: attempt to select an external target and prove the scope guard blocks it before any effect.

## Run

```bash
node --test red-lab/lab.test.mjs
node red-lab/run.mjs
```

The runner writes `red-lab/evidence/report.json`. CI uploads the report as evidence and fails closed if any golden case stops proving its expected boundary.
