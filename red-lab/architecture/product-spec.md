# Product Spec

The Red Lab must:

1. Define machine-readable authorization and target scope.
2. Deny any target outside the exact allowlist before an effect can occur.
3. Include at least two deliberately vulnerable synthetic cases.
4. Prove each vulnerable case succeeds before the patch.
5. Prove the same case is blocked after the patch.
6. Emit one machine-readable evidence report.
7. Fail CI if any required proof disappears.
8. Never imply that passing the lab equals Daybreak Red approval or production-security certification.
