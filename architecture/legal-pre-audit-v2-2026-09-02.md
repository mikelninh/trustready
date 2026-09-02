# TrustReady Legal — External-Style Re-Audit v2

Date: 2026-09-02
Scope: PR #14 (`legal-trust-layer`) after the audit-hardening sprint.
Auditor stance: adversarial pre-audit / readiness assessment. This is not independent assurance, certification, a legal opinion, a C5 attestation or an AIC4 attestation.

## Executive opinion

**Engineering opinion: PASS.**

**Real mandate shadow opinion: NOT READY — operating, legal/privacy and independent evidence still missing.**

The five concrete code findings from the first pre-audit have been closed and converted into regression tests. A second meta-audit then found that the first automated audit input could have trusted a self-authored JSON file containing `verified:true`; that promotion path has also been removed. Live and independent evidence must now be signed by separately trusted keys whose public-key fingerprints are pinned outside the evidence file.

The full repository test suite now passes **80/80** and the scanner benchmark remains exact on its 30 labelled cases. CI and dogfood are green. `npm run audit:legal` runs in CI and deliberately refuses to infer production readiness from repository evidence alone.

Latest automated pre-audit result:

- Engineering: `PASS`
- Regression findings closed: `true`
- Scanner verified precision: `1.0`
- Scanner verified recall: `1.0`
- Scanner false-verified rate: `0`
- Live runtime evidence: `MISSING_EVIDENCE`
- Legal/privacy governance evidence: `MISSING_EVIDENCE`
- Independent assurance: `MISSING_EVIDENCE`
- `pre_audit_ready`: `true`
- `real_mandate_shadow_ready`: `false`
- `independently_assured`: `false`

## Closed findings

### AUD-P1-01 — URL-safe / unpadded Base64 DLP bypass — CLOSED

The DLP layer now normalises the URL-safe alphabet, restores valid padding, round-trip validates candidate encodings and recursively inspects decoded text. Regression coverage includes unpadded/Base64URL identifiers and secrets.

Evidence: `core/legal-dlp.mjs`, `core/legal-runtime-fortress.test.mjs`.

### AUD-P1-02 — inherited JavaScript zone names — CLOSED

Zone membership now uses explicit own-property membership (`Object.hasOwn`) rather than `in`. Prototype names such as `toString` are denied before mandate-specific policy evaluation.

Evidence: `core/legal-runtime-fortress.mjs`; regression `prototype property zone names cannot bypass mandate controls`.

### AUD-P1-03 — stale provider passport after policy rotation — CLOSED

Provider passports now use schema `trustready-provider-passport-v2`, require a signed `policy_version`, and are valid only when it exactly matches the active runtime/request policy version.

Evidence: `core/legal-runtime-fortress.mjs`; regression `stale provider passport is revoked by active policy version`.

### AUD-P1-04 — unknown redirect state treated as safe — CLOSED

Network attestations now require `redirected === false`. Missing, malformed or true redirect state fails closed.

Evidence: `core/legal-network.mjs`; regression `network egress blocks wrong host, http, redirect, absent, unknown redirect or forged attestation`.

### AUD-P2-01 — direct identifiers in evidence context — CLOSED WITH BOUNDARY NOTE

Evidence events/checkpoints/manifests now enforce an opaque identifier syntax for tenant/matter/actor context and reject obvious email/human-readable values. This prevents common accidental direct identifiers at the evidence boundary.

Boundary note: syntactic opacity cannot prove that an upstream opaque token is semantically non-identifying. Deployment governance must still ensure pseudonymous IDs are generated and mapping tables are separately protected.

Evidence: `core/legal-evidence.mjs`; regression `evidence context rejects direct or human-readable identifiers`.

### AUD-META-01 — self-authored audit evidence could promote readiness — CLOSED

The initial audit CLI treated a local evidence JSON as an input source. Even with required fields, that would not establish provenance: the same operator could write the evidence and mark the claims verified.

The audit now requires signed assurance envelopes and an independently supplied/pinned public-key fingerprint. Runtime/legal qualification and independent assurance use separate signing purposes and separate trust-anchor inputs. Individual claims must carry an evidence level, a SHA-256 evidence digest and fresh observation/expiry timestamps. Unsigned JSON, a wrong signer, a fingerprint mismatch, an expired claim or the wrong evidence level cannot promote readiness.

Evidence: `core/legal-assurance-evidence.mjs`, `core/legal-assurance-evidence.test.mjs`, `scripts/legal-preaudit.mjs`.

Boundary note: the application can enforce cryptographic provenance, but organisational independence of the trust-anchor owner must itself be established by deployment/audit governance. TrustReady must not claim that a key is independent merely because it is technically separate.

## Automated audit gate

`npm run audit:legal` is a first-class CI step. It separates four evidence classes:

1. engineering/repository proof;
2. live runtime operating proof;
3. legal/privacy governance proof;
4. independent assurance.

The audit can PASS engineering while still returning `real_mandate_shadow_ready:false`. This distinction is mandatory and cannot be overridden by a score.

Promotion inputs are fail-closed:

- Live qualification requires `TRUSTREADY_LIVE_EVIDENCE`, `TRUSTREADY_LIVE_TRUST_KEY` and `TRUSTREADY_LIVE_TRUST_FINGERPRINT`.
- Independent assurance requires a separate `TRUSTREADY_INDEPENDENT_EVIDENCE`, `TRUSTREADY_INDEPENDENT_TRUST_KEY` and `TRUSTREADY_INDEPENDENT_TRUST_FINGERPRINT`.
- Runtime claims require cryptographically trusted E3/E4 evidence.
- Legal/privacy governance claims require E4 evidence in the promotion gate.
- Independent pentest/legal/privacy/evidence-verification claims require separately signed E4 evidence.

Supplying no evidence is safe: the audit remains Engineering PASS but reports all stronger evidence classes as `MISSING_EVIDENCE`.

## Current remaining blockers

### Live operating evidence

Still required from the actual dedicated deployment:

- live HSM/KMS posture and signing proof;
- live Sensitive Data Protection/DLP proof;
- live restricted network / VPC Service Controls proof;
- irreversibly locked WORM evidence bucket and signed qualification stored inside it;
- production secrets-manager sourcing plus rotation/revocation drill;
- encrypted backup + successful restore exercise;
- deletion test/receipt;
- incident/kill-switch exercise;
- upload malware scanning evidence;
- SBOM + current vulnerability report;
- deployed web/session/security-header evidence.

### Legal/privacy governance evidence

Still required for the exact Bao deployment/provider/model/use case:

- AVV/DPA;
- BRAO §43e assessment;
- subprocessor chain;
- international-transfer assessment where applicable;
- VVT/record of processing;
- DPIA/DSFA screening/result;
- AI Act use-case classification;
- AI-literacy/training evidence.

### Independent evidence

Still required:

- independent penetration test;
- remediation of all critical/high findings;
- independent German legal/privacy review of the exact deployment;
- independent evidence-pack verification from a clean reviewer context.

## Gate decision

| Target | Re-audit v2 verdict |
|---|---|
| Repository engineering | **PASS** |
| Known first-audit code findings | **CLOSED + REGRESSION COVERED** |
| Audit-evidence provenance boundary | **PASS — PINNED SIGNED INPUT REQUIRED** |
| Synthetic/public-data shadow | **PASS** |
| Pre-audit / evidence-room readiness | **PASS** |
| Real mandate-data external-AI shadow | **NOT READY — LIVE/GOVERNANCE/INDEPENDENT EVIDENCE MISSING** |
| Human-approved production actions | **NOT READY** |
| Autonomous mail/beA/case writes | **OUT OF SCOPE / BLOCKED** |
| Independent C5/AIC4/ISO assurance claim | **NOT ASSURED** |

## Product conclusion

TrustReady now enforces the core principle behind `always audit-ready`: a green build is evidence for engineering quality, not a substitute for operating effectiveness or independent assurance. Even the evidence fed into the auditor must have provenance and an external trust boundary.

The next promotion is evidence-driven:

`PRE-AUDIT READY` → deploy exact environment → collect signed E3 runtime evidence → complete authorised legal/privacy E4 evidence → independent pentest/review → independently sign/verify evidence → clean re-audit → `REAL MANDATE SHADOW READY`.
