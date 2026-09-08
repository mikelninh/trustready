# Golden Cases

## 1 — Attack impact disappears
Given the same malicious input, the controlled baseline reaches a security-sensitive effect and the protected path reaches zero impact.

Acceptance: all v1 attack cases are exposed in the baseline and `afterImpactEscapes == 0`.

## 2 — Unseen/frozen cases generalize
Controls must contain frozen evaluation cases that were not used as remediation input in this benchmark change.

Acceptance: at least six holdouts across eligible targets and `contained == total`. SafeVoice is explicitly not counted as holdout evidence.

## 3 — Useful work still works
Normal same-tenant reads, approved writes, and benign documents must remain usable through the protected path.

Acceptance: at least seven benign controls across v1 and 100% retention.

## 4 — Truth survives aggregation
A controlled synthetic mutant must never be presented as a historical vulnerability; SafeVoice's native pre-boundary evidence must not be downgraded or relabeled as holdout evidence.

Acceptance: proof-type and historical-claim assertions pass for all four targets.
