# TrustReady Legal — External-Style Re-Audit v3

Date: 2026-09-02
Scope: PR #14 (`legal-trust-layer`) at security head `b48d8fbba97d1fe5e375b7d3889eb9c933e6b831`.
Auditor stance: adversarial pre-audit / readiness assessment. This is not independent assurance, certification, a legal opinion, a C5 attestation or an AIC4 attestation.

## Executive opinion

**Engineering opinion: PASS.**

**Real mandate shadow opinion: NOT READY — signed live operating, legal/privacy and independent evidence still missing.**

The five concrete code findings from the first pre-audit are closed and regression-covered. The audit pipeline itself was then hardened so that self-authored `verified:true` JSON cannot promote readiness. Runtime qualification, legal/privacy governance and independent assurance now require three separately signed evidence envelopes with externally pinned and mutually distinct trust-anchor fingerprints.

Latest verified engineering evidence on head `b48d8fb...`:

- full repository tests: **82/82 PASS**, 0 failures;
- scanner benchmark: 30 labelled cases, precision 1.0, recall 1.0, false-verified rate 0, exact-status accuracy 1.0, provenance completeness 1.0;
- GitHub CI run #105: **SUCCESS**;
- dogfood run #78: **SUCCESS**;
- `npm run audit:legal`: **SUCCESS**;
- audit schema: `trustready-legal-preaudit-v3`;
- `pre_audit_ready: true`;
- `real_mandate_shadow_ready: false`;
- `independently_assured: false`.

## Closed findings

### AUD-P1-01 — URL-safe / unpadded Base64 DLP bypass — CLOSED
The DLP layer normalises the URL-safe alphabet, restores valid padding, round-trip validates candidate encodings and recursively inspects decoded text. Regression coverage includes unpadded/Base64URL identifiers and secrets.

### AUD-P1-02 — inherited JavaScript zone names — CLOSED
Zone membership uses explicit own-property membership (`Object.hasOwn`) rather than `in`. Prototype names such as `toString` are denied before mandate-specific policy evaluation.

### AUD-P1-03 — stale provider passport after policy rotation — CLOSED
Provider passports use `trustready-provider-passport-v2`, require a signed `policy_version`, and are valid only when it exactly matches the active runtime/request policy version.

### AUD-P1-04 — unknown redirect state treated as safe — CLOSED
Network attestations require `redirected === false`. Missing, malformed or true redirect status fails closed.

### AUD-P2-01 — direct identifiers in evidence context — CLOSED WITH BOUNDARY NOTE
Evidence events/checkpoints/manifests enforce opaque identifier syntax for tenant/matter/actor context and reject obvious direct/human-readable identifiers. Syntactic opacity cannot prove semantic pseudonymisation; deployment governance must separately protect the token-to-identity mapping.

### AUD-META-01 — self-authored audit evidence could promote readiness — CLOSED
A local Boolean claim is no longer evidence. Claims require signed assurance envelopes, pinned public-key fingerprints, SHA-256 evidence digests, evidence levels and fresh observation/expiry timestamps.

### AUD-META-02 — one signer could impersonate multiple assurance roles — CLOSED
The promotion gate now separates:

1. `live_qualification` — runtime/security operator evidence;
2. `legal_privacy_assurance` — authorised legal/privacy evidence;
3. `independent_assurance` — independent review evidence.

The three trust-anchor fingerprints must be distinct before stronger readiness can become true. Technical key separation does not itself prove organisational independence; auditor governance must establish who controls each key.

## Automated audit gate

`npm run audit:legal` is a first-class CI step and separates engineering evidence from E3/E4 evidence.

### Runtime evidence
Requires:
- `TRUSTREADY_LIVE_EVIDENCE`
- `TRUSTREADY_LIVE_TRUST_KEY`
- `TRUSTREADY_LIVE_TRUST_FINGERPRINT`

Required E3/E4 claims: HSM, DLP, network enforcement, WORM lock, secrets manager, backup/restore, deletion test, incident drill, malware scan, SBOM/vulnerability evidence and deployed web/session checks.

### Legal/privacy evidence
Requires a separately pinned `TRUSTREADY_LEGAL_*` evidence/key/fingerprint set and E4 claims for AVV/DPA, BRAO §43e, subprocessors, transfer assessment, VVT, DPIA/DSFA, AI Act classification and AI-literacy evidence.

### Independent evidence
Requires a third separately pinned `TRUSTREADY_INDEPENDENT_*` evidence/key/fingerprint set and E4 claims for independent penetration testing, independent legal/privacy review and independent evidence-pack verification.

Unsigned JSON, wrong signatures, wrong purpose, fingerprint mismatch, stale claims, missing evidence hashes, insufficient evidence levels or reused trust anchors cannot promote readiness.

## Current blockers

### Live operating evidence
- deploy the dedicated GCP legal-shadow environment;
- collect live HSM/KMS + DLP + restricted-network evidence;
- deliberately enable and verify the irreversible WORM retention lock;
- prove production secrets-manager sourcing and rotation/revocation;
- run encrypted backup/restore, deletion and incident drills;
- add live upload-malware scanning;
- generate current SBOM/vulnerability evidence;
- run deployed web/session/security-header checks.

### Legal/privacy governance
- exact provider AVV/DPA;
- BRAO §43e assessment;
- subprocessor and transfer assessment;
- VVT;
- DPIA/DSFA;
- AI Act classification;
- AI-literacy/training evidence.

### Independent assurance
- independent penetration test;
- remediate all critical/high findings;
- independent German legal/privacy review for the exact Bao deployment;
- independent evidence-pack verification from a clean reviewer context.

## Gate decision

| Target | Re-audit v3 verdict |
|---|---|
| Repository engineering | **PASS** |
| Known code findings | **CLOSED + REGRESSION COVERED** |
| Audit-evidence provenance boundary | **PASS** |
| Three-role trust separation | **PASS (technical), organisational independence still to evidence** |
| Synthetic/public-data shadow | **PASS** |
| Pre-audit / evidence-room readiness | **PASS** |
| Real mandate-data external-AI shadow | **NOT READY — E3/E4 EVIDENCE MISSING** |
| Human-approved production actions | **NOT READY** |
| Autonomous mail/beA/case writes | **OUT OF SCOPE / BLOCKED** |
| Independent C5/AIC4/ISO assurance claim | **NOT ASSURED** |

## Product conclusion

TrustReady now implements the core of **always audit-ready**: a green build can prove engineering quality, but cannot impersonate operating effectiveness, legal approval or independent assurance. The audit itself is fail-closed and provenance-aware.

Promotion remains evidence-driven:

`PRE-AUDIT READY` → live deployment → signed E3 runtime evidence → separately signed legal/privacy E4 evidence → independent pentest/review → third-party signed E4 evidence → clean re-audit → `REAL MANDATE SHADOW READY`.
