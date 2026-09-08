# Architecture

## Layers

1. **Target-owned harnesses** create the counterfactual evidence inside each repository.
2. **Target-native CI** verifies those harnesses independently.
3. **TrustReady benchmark CI** checks out exact target revisions and reruns the target proofs.
4. **Aggregator** validates schemas and invariants; it never rewrites target outcomes.
5. **Artifact layer** publishes aggregate JSON, summary, HTML, and copied target evidence.

## Causal designs

- Factory: intentionally vulnerable synthetic manifest → remediation derived from known attacks only → frozen holdout replay.
- SafeVoice: native reachable pre-boundary raw-handler/network behavior → scoped production boundary.
- GitLaw: test-only bypass of `evaluateAgentIntent` → real deterministic control plane.
- PrüfPilot: test-only bypass of document quarantine → real `scan_security` path.

## Trust invariant
A benchmark PASS is possible only when every target-native evidence report independently passes its required assertions.
