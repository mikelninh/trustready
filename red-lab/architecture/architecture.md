# Architecture

```text
scope.json
   ↓
assertInScope(target) ── deny ──> BLOCKED_SCOPE / no effect
   ↓ allow
synthetic vulnerable fixture
   ↓
controlled validation
   ↓
patched fixture
   ↓
regression validation
   ↓
report.json + CI gate
```

All current targets are in-memory `lab://` fixtures. There is no network client in the lab runtime.
