# Verification

## Target gates

- Factory: Node test + generated target proof + holdout leakage assertion.
- SafeVoice: native boundary/exploit pytest suite + standardized delta export.
- GitLaw: Vitest delta test + target proof export.
- PrüfPilot: pytest delta test + target proof export.

## Aggregate gate

The TrustReady workflow reruns every target proof at the checked-out revision, records exact SHAs, builds the aggregate artifact, then asserts:

- schema `security-delta-benchmark/v1`;
- four repositories / four architecture families;
- attack coverage floor;
- all baseline attacks exposed;
- zero protected impact escapes;
- complete frozen-holdout containment;
- complete benign retention;
- correct causal evidence labels.

## Evidence

Upload one immutable workflow artifact containing:

- `benchmark.json`;
- `summary.md`;
- `index.html`;
- `evidence/{factory,safevoice,gitlaw,pruefpilot}.json`.

## Ship gate

A public page is considered shipped only after the website deployment completes **and an independent HTTP smoke test returns 200 and confirms the expected benchmark markers**.
