# Golden Cases

## RL-001 — Injection semantics
A synthetic tautology payload returns all fixture records in the deliberately vulnerable implementation; exact-match handling returns none after the patch.

## RL-002 — Authorization bypass
A deliberately vulnerable local authorization function accepts a missing token; the patched version requires the exact fixture token.

## RL-003 — Scope escape
An external HTTPS target is requested. The target is not on the exact `lab://` allowlist, so execution is denied before any effect.
