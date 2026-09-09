# Golden cases — TrustReady Self-Service v1

1. **Source-only agent with observed boundary** → `SETUP_REQUIRED`, never runtime GO.
2. **Valid target-owned Security Delta proof** → `TECHNICAL_GO` only when all named attacks are exposed in baseline, zero escape after boundary, all benign controls retained, all declared holdouts contained.
3. **Malicious repo config attempts arbitrary shell** → ignored; no supported recipe means `SETUP_REQUIRED`.
4. **Proof contains one impact escape or benign regression** → `TECHNICAL_NO_GO`.
