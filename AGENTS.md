# AGENTS.md — TrustReady

## Mission
Build an evidence-first trust layer that controls what AI may see, what it may do, and what can be proven afterwards — without pretending engineering evidence is certification or legal authority.

## Start here
1. Read `README.md`.
2. Read `.harness/project.json`.
3. Read `.harness/active-task.json` and `.harness/HANDOFF.md`.
4. Load only the trust/legal docs needed for the current task.

## Source-of-truth map
- Product and promotion boundary: `README.md`
- End goal and trust model: `docs/ENDGOAL.md`, `docs/TRUST_MODEL.md`
- Legal product and Bao pilot: `docs/LEGAL_PRODUCT_GOAL.md`, `docs/BAO_PRODUCTION_PILOT_PLAN.md`
- Portal security: `docs/CLIENT_PORTAL_SECURITY_ARCHITECTURE.md`
- Deterministic trust logic: `core/`
- Evidence collection: `collectors/`
- Control profiles: `profiles/`
- Scanner benchmarks: `benchmarks/`
- Production-shaped legal infrastructure: `infra/`
- Current work state: `.harness/`
- CI truth: `.github/workflows/`

## Contract before work
Every substantial task must define goal, authoritative sources, outputs, constraints, done criteria, forbidden actions, risk class, retry budget, and next owner.

Do not silently redefine the task or upgrade an unknown into a supported claim.

## Roles
- Chief: triage, decompose, route, collect. Does not perform trust-sensitive execution.
- Scout: source/evidence collection. Read-only by default.
- Builder: implements checks, mappings, product flows or remediations.
- Verifier: independently checks evidence, tests and claims.
- Operator: performs approved external actions only after policy gates.

## Action classes
- A0 Observe — read/search/analyse. Automatic.
- A1 Local reversible — draft/test/edit isolated work. Automatic.
- A2 Shared reversible — branch, PR, preview, issue. Logged; normally automatic.
- A3 Consequential — deploy, send, publish, spend, write externally. Human approval required.
- A4 High-impact — sensitive-data egress, destructive production changes, legal/privacy authority claims. Explicit approval plus stronger independent verification.

Trust the action class, not the agent personality.

## Verification
Minimum harness check:
`node scripts/harness-check.mjs`

Core trust checks:
- `npm test`
- `npm run benchmark:scanner`
- `npm run audit:legal`
- `npm run readiness:bao`

Never claim a command passed unless it actually ran and the result is captured.

## Durable state
The conversation is not the system of record.
Keep current work in `.harness/active-task.json`.
Keep handoff context in `.harness/HANDOFF.md`.
Keep accepted run receipts in `.harness/receipts/`.

Preferences may live in memory; current evidence, deployment state, control results, pilot state, legal/privacy verdicts and permissions must be re-opened from authoritative sources.

## Handoffs
A handoff must state status, current step, evidence, decisions, failures/uncertainties, open risks, next owner and exact next action.

Do not pass consequential TrustReady work as chat-only context.

## Retries
Use bounded repair loops. Default maximum: 3 attempts.
If the same failure repeats twice, stop and improve the harness/check/evidence path or escalate.

## Failure upgrades
- missing evidence -> collector/source rule
- unsupported claim -> deterministic control/check
- stale evidence -> freshness rule
- repeated loop -> retry cap/escalation
- unsafe action -> permission gate
- lost decision -> durable state
- unknown failure -> tracing/evidence capture

A failure fix should reduce recurrence across future scans or pilots.

## Hard boundaries
- TrustReady must still be useful if the buyer does not trust TrustReady.
- The model may interpret; deterministic policy controls authority.
- Missing authoritative evidence is `unknown`/unsupported, never guessed.
- A lower promotion stage cannot self-promote to a higher one.
- Synthetic evidence is never production evidence.
- TrustReady does not grant itself legal, privacy, security-audit or certification authority.
- Real mandate data, email, beA, external writes and other irreversible actions require the explicit live-stage controls defined by the project.
- Secrets, credentials and sensitive client data never belong in repository harness state.

## Definition of done
Work is done only when the task's done criteria are evidenced, unknowns remain explicit, the promotion boundary is respected, rollback/next step is known, and all required human or independent approvals are recorded.
