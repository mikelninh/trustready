# Architecture — TrustReady Self-Service v1

1. `local-collector.mjs` snapshots bounded source files.
2. `agent-repo-scanner.mjs` builds source topology, reachable tools, blockers and attack plan.
3. `connected-runner.mjs` detects one of three fixed target-owned harness recipes and executes with `shell:false`.
4. Target emits `security-delta-target-proof/v1` JSON.
5. `self-service.mjs` validates evidence and gates release.
6. `cli.mjs` exposes scan/verify/run/init.

Trust boundary: TrustReady does not synthesize runtime success from source. The target harness owns attack execution/instrumentation; TrustReady owns evidence contract validation and release gating.
