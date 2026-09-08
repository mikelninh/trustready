# TrustReady Security Delta Benchmark v1

A causal engineering benchmark for one narrow question:

> Does the relevant deterministic security boundary reduce measured unauthorized impact for the **same named inputs** while preserving legitimate behavior?

## Targets

- `mikelninh/digital-worker-factory` — controlled vulnerable synthetic manifest; remediation derived from the known split only, then frozen holdouts replayed.
- `mikelninh/safevoice` — scoped native reachable pre-boundary replay for the Court-Prep case/network boundary. It predates the holdout split and is **not** relabeled as holdout evidence.
- `mikelninh/gitlaw` — test-only bypass of the real deterministic `evaluateAgentIntent` boundary.
- `mikelninh/pruefpilot` — test-only bypass of the real untrusted-document quarantine scan.

Every target owns its own `security-delta-target-proof/v1` evidence. TrustReady only aggregates and asserts it; the aggregator cannot turn a failing target into a pass.

## Release assertions

The benchmark fails if:

- any protected-path impact escape remains;
- a frozen holdout escapes;
- a benign control stops working;
- a target/evidence schema drifts;
- the causal evidence mix or truth-boundary labels drift;
- fewer than four architecture families are represented.

## Outputs

`build.mjs` emits:

- `benchmark.json` — machine-readable aggregate result;
- `summary.md` — reviewer-readable evidence summary;
- `index.html` — public proof page;
- `evidence/*.json` — exact target-native reports used in the run.

CI records the exact engine and target commit SHAs. Target refs intentionally track `main`; drift should make the benchmark red instead of silently preserving an old green result.

## Interpretation

A result such as `14 → 0 impact escapes` means that, in the named controlled scenarios, all 14 deliberately exposed attacks reached impact in the baseline and none reached impact through the protected path. It **does not** mean “100% secure” or estimate real-world attack probability.

## Truth boundary

This benchmark is scoped causal engineering evidence. Three baselines are deliberately weakened test-only mutants or synthetic fixtures. SafeVoice contributes scoped native reachable pre-boundary evidence. It is not a penetration test, certification, production-security claim, proof that prompt injection is solved, or proof that unknown vulnerabilities do not exist.
