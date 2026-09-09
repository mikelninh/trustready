# Product spec — TrustReady Self-Service v1

Flow: scan local/public source → show reachable agent/tool surface → generate named attack plan → require target-owned delta evidence → validate zero post-boundary impact escapes + full benign retention → GO/NO_GO.

Commands: `scan`, `verify`, `run`, `init`.

Supported connected recipes: `npm run security:delta`, `node security/security-delta.mjs`, `python security/security_delta.py`.

Acceptance: source-only never TECHNICAL_GO; arbitrary commands ignored; invalid proof fails closed; valid proof can GO; all outputs preserve truth boundary.
