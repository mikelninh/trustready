# Product Spec

## Required target evidence
Each target emits `security-delta-target-proof/v1` containing:

- repository and architecture identity;
- control under test;
- explicit baseline/mutation semantics;
- attack count and before/after impact escapes;
- effect-call evidence where available;
- benign retention;
- holdout containment where applicable;
- truth boundary.

## Benchmark success
A v1 PASS requires:

1. exactly four real repositories and four architecture families;
2. at least 14 named attack cases;
3. every controlled baseline attack reaches measured impact;
4. zero protected-path impact escapes;
5. at least six frozen holdouts, all contained;
6. at least seven benign controls, all retained;
7. three controlled-mutation targets plus one native reachable pre-boundary replay;
8. exact target commit SHAs recorded;
9. machine JSON, summary, public HTML, and raw target evidence generated.

## User-facing message
Lead with `impact escapes before → after`, not an abstract security score. Always display the truth boundary near the result.
