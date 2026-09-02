# TrustReady Legal — External-Style Re-Audit v2

Date: 2026-09-02
Scope: PR #14 (`legal-trust-layer`) after the audit-hardening sprint.
Auditor stance: adversarial pre-audit / readiness assessment. This is not independent assurance, certification, a legal opinion, a C5 attestation or an AIC4 attestation.

## Executive opinion

**Engineering opinion: PASS.**

**Real mandate shadow opinion: NOT READY — operating, legal/privacy and independent evidence still missing.**

The five concrete code findings from the first pre-audit have been closed and converted into regression tests. The full repository test suite passes 74/74 and the scanner benchmark remains exact on its 30 labelled cases. CI and dogfood are green. The new `npm run audit:legal` command now runs in CI and deliberately refuses to infer production readiness from repository evidence alone.

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

## Automated audit gate

`npm run audit:legal` is now a first-class CI step. It separates four evidence classes:

1. engineering/repository proof;
2. live runtime operating proof;
3. legal/privacy governance proof;
4. independent assurance.

The audit can PASS engineering while still returning `real_mandate_shadow_ready:false`. This distinction is mandatory and must not be overridden by a score.

Optional live evidence is supplied through `TRUSTREADY_LIVE_EVIDENCE`; a missing live evidence file cannot silently promote a deployment.

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
| Synthetic/public-data shadow | **PASS** |
| Pre-audit / evidence-room readiness | **PASS** |
| Real mandate-data external-AI shadow | **NOT READY — LIVE/GOVERNANCE/INDEPENDENT EVIDENCE MISSING** |
| Human-approved production actions | **NOT READY** |
| Autonomous mail/beA/case writes | **OUT OF SCOPE / BLOCKED** |
| Independent C5/AIC4/ISO assurance claim | **NOT ASSURED** |

## Product conclusion

TrustReady is now able to enforce the core principle behind `always audit-ready`: a green build is evidence for engineering quality, not a substitute for operating effectiveness or independent assurance.

The next promotion must be evidence-driven:

`PRE-AUDIT READY` → deploy exact environment → collect signed E3 runtime evidence → complete legal/privacy E4 evidence → independent pentest/review → clean re-audit → `REAL MANDATE SHADOW READY`.
