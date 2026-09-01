<!-- paos:reviewed=2026-09-01 -->
# Golden cases

## Golden case 1 — AI system → reproducible readiness graph

**Starting situation:** a developer/buyer selects a readiness profile and connects evidence sources for an AI system.

**Expected outcome:** every control shows requirement, evidence inspected, observation, unknowns, freshness, reproducibility information and exact current state.

**Failure conditions:** opaque pass/fail; evidence-less score; AI discovery becomes final authority; stale evidence not surfaced; profile/rule version missing.

**Authority rule:** accepted evidence/control rules determine readiness; human procurement/compliance authority remains external.

**Current proof:** product contract established; each implemented scanner/control must link executable evidence before the case is marked verified.

---

## Golden case 2 — Gap → exact remediation → evidence-backed closure

**Starting situation:** one or more controls are failed/unknown.

**Expected outcome:** TrustReady explains the gap, proposes a concrete closing action, re-scans after the change and shows the evidence/state transition.

**Failure conditions:** generated advice automatically turns control green; remediation is vague/unreproducible; new evidence cannot be traced; historical state disappears.

**Authority rule:** control closes only under the selected rule/profile's accepted evidence semantics.

**Current proof:** core product direction; verification requires representative end-to-end remediation fixtures and real repository dogfooding.

---

## Golden case 3 — Buyer pack → independent verification → evidence expires

**Starting situation:** a buyer consumes a readiness result and later one important evidence item becomes stale or changes.

**Expected outcome:** buyer can independently inspect/reproduce the original result; expiry/re-scan reopens the affected control; downstream trust-centre/API output reflects the changed state.

**Failure conditions:** buyer must trust TrustReady's prose; expired evidence stays green; old score remains detached from current graph; certification/government approval is implied.

**Authority rule:** TrustReady informs procurement/approval; it does not become the approving institution.

**Current proof:** target architecture. Continuous monitoring/expiry must be backed by executable evidence before claiming this case verified.

## Release rule

Do not optimise for `100/100` screenshots. Optimise for **reproducible control state + exact path to close gaps + honest unknowns**.
