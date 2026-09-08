# Constraints

- No third-party systems are attacked.
- No production target is intentionally weakened.
- Controlled mutants live only in test/benchmark code or synthetic fixtures.
- SafeVoice historical/reachable evidence must remain labeled differently from synthetic mutants.
- Frozen holdouts cannot be fed into the Factory remediation step.
- Benign behavior is a hard gate; a control that merely blocks everything must fail.
- `PASS` must never be rendered as certification, universal security, or solved prompt injection.
- Target revisions must be recorded by commit SHA.
- Target refs track `main` so security drift becomes visible.
- Public output must remain understandable in under one minute while retaining exact evidence links.
