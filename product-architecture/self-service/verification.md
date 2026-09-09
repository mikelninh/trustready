# Verification — TrustReady Self-Service v1

Automated gates:
- Node unit tests for source scanner and self-service engine.
- Connected-runner fixture proves fixed-recipe execution → emitted proof → validator → TECHNICAL_GO.
- Negative fixture proves arbitrary config command is not executed.
- CI syntax checks all self-service modules.
- Dogfood: run source preflight against TrustReady and validate existing Security Delta target proof fixtures where available.

Release requires all tests green on PR and main. Public UI requires independent browser/mobile QA plus external HTTP 200 marker check.
