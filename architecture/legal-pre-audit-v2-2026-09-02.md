# TrustReady Legal — External-Style Re-Audit v4

Date: 2026-09-02
Scope: PR #14 (`legal-trust-layer`) at verified security head `788371dd97f48a8a427055f11ffa34c55f1a1cb8` before this documentation commit.
Auditor stance: adversarial pre-audit / readiness assessment. This is not independent assurance, certification, a legal opinion, a C5 attestation or an AIC4 attestation.

## Executive opinion

**Engineering opinion: PASS.**

**Real mandate shadow opinion: NOT READY — signed live operating, legal/privacy and independent evidence still missing.**

The previously identified P1/P2 engineering findings have been closed or removed from executable scope and converted into adversarial regression tests. The security architecture now binds provider policy, release, scanner configuration, exact target URL, exact outbound request bytes, the actual restricted-VIP TLS socket, purpose-separated HSM keys and immutable evidence into one fail-closed mandate-shadow path. Production action execution is physically disabled until replay prevention and resource-version compare-and-write are service-owned, durable and atomic.

Verified engineering evidence on security head `788371d...`:

- full repository tests: **92/92 PASS**, 0 failures;
- selected legal/security audit suite: **72/72 PASS**, 0 failures;
- scanner benchmark: **30 labelled cases**, verified precision 1.0, verified recall 1.0, false-verified rate 0, exact-status accuracy 1.0 and provenance completeness 1.0;
- GitHub CI run **#139: SUCCESS**;
- dogfood run **#112: SUCCESS**;
- `npm run audit:legal`: **SUCCESS**;
- audit schema: `trustready-legal-preaudit-v4`;
- `regression_findings_closed: true`;
- `missing_regressions: []`;
- `production_actions_physically_blocked: true`;
- `pre_audit_ready: true`;
- `real_mandate_shadow_ready: false`;
- `independently_assured: false`.

## Closed engineering findings

### AUD-P1-01 — URL-safe / unpadded Base64 DLP bypass — CLOSED
The recursive DLP layer normalises URL-safe Base64, restores padding, round-trip validates candidate encodings and scans recursively decoded values. Unicode/zero-width and parser-depth/cycle cases also fail closed.

### AUD-P1-02 — inherited JavaScript zone names — CLOSED
Zone membership uses explicit own-property membership. Prototype names such as `toString` cannot bypass mandate controls.

### AUD-P1-03 — stale provider passport after policy rotation — CLOSED
Provider passports use `trustready-provider-passport-v2` and must match the active signed policy version.

### AUD-P1-04 — unknown redirect state treated as safe — CLOSED
Network attestations require `redirected === false`; absent, malformed or true redirect posture is denied.

### AUD-P1-05 — Cloud KMS ECDSA verification semantics — CLOSED
ECDSA P-256 verification now matches Cloud KMS `EC_SIGN_P256_SHA256`: SHA-256 is verified over the original canonical bytes rather than re-hashing a precomputed digest. The regression uses Cloud-KMS-equivalent signing semantics instead of a matching broken mock.

### AUD-P1-06 — DLP configuration drift and malformed successful responses — CLOSED
A 2xx response is safe only when the expected Google Sensitive Data Protection result structure exists. The exact inspect configuration has a deterministic fingerprint, is included in signed DLP attestations and must match the deployment-pinned runtime fingerprint.

### AUD-P1-07 — egress proof not bound to deployed release — CLOSED
Production requires an explicit release identity. The signed egress-enforcement attestation must carry the same release, so an attestation from an older rollout cannot authorize the new release merely because its policy version is unchanged.

### AUD-P1-08 — firewall proof could come from the wrong VPC — CLOSED
The protected VPC is derived from the actual subnetwork. Accepted allow/deny rules must belong to that exact network; an unrelated hardened network cannot satisfy the collector.

### AUD-P1-09 — target-scoped firewall rules treated as network-wide — CLOSED
Rules with target tags, target service accounts or resource-manager selectors cannot qualify as the network-wide deny-all/restricted-VIP controls.

### AUD-P1-10 — VPC Service Controls escape policies — CLOSED
The qualification collector rejects enforced perimeters containing ingress/egress escape policies and requires the expected restricted-service posture.

### AUD-P1-11 — independent project ID/project-number inputs could diverge — CLOSED
Terraform and the live collector derive the numeric project identity from `project_id`. The service perimeter no longer trusts a separately caller-supplied project number.

### AUD-P1-12 — qualification inspected only one HSM key — CLOSED
Infrastructure qualification requires four live HSM signers for DLP, egress enforcement, network attestation and evidence signing. All four must resolve to distinct CryptoKey identities and distinct key versions.

### AUD-P1-13 — network attestor could be a software key — CLOSED
The connection-bound restricted transport requires a hardware-backed signer with live HSM posture before it can create a network attestation.

### AUD-P1-14 — TLS probe was not the payload connection — CLOSED
The mandate-shadow path now prepares the exact provider request first, hashes the full target URL plus exact outbound bytes, resolves only restricted Google API VIPs, validates TLS/SNI/certificate/remote address, signs that transport proof with the network HSM and preserves the socket in module-private state. After Legal Egress ALLOW, the exact prepared bytes are sent through that exact socket. Socket substitution, DNS poisoning, redirect, path substitution and second-send replay are regression-tested and denied.

### AUD-P1-15 — proposal-only model boundary existed only in tests — CLOSED FOR SHADOW PATH
The GCP mandate-shadow path now invokes a fixed Vertex proposal-only adapter. It emits no tool/function declarations, disables action semantics through the request contract and accepts only one strict JSON proposal. Function/tool-shaped or executable-shaped responses are rejected before Evidence Vault commit.

### AUD-P1-16 — caller-owned replay / stale-resource assumptions in action execution — CLOSED BY REMOVING EXECUTION FROM SCOPE
TrustReady no longer treats caller-supplied `durable:true`, replay callbacks or resource-version claims as sufficient production security. Action approvals may be prepared for human-review UX, but `executeApprovedAction` cannot execute in either shadow or production. Shadow returns `SHADOW_LOCK`; production returns `PRODUCTION_ACTIONS_DISABLED`; caller replay stores and handlers are never reached. A future action kernel must provide service-owned atomic replay protection and compare-and-write semantics before execution can re-enter scope.

### AUD-P1-17 — evidence chain suffix truncation — CLOSED
A valid-looking chain prefix is no longer sufficient. `verifyEvidenceChainAgainstCheckpoint` compares the chain length and head hash with a trusted signed latest checkpoint, detecting deletion of trailing events.

### AUD-P2-01 — direct identifiers in evidence context — CLOSED WITH BOUNDARY NOTE
Evidence events/checkpoints/manifests require opaque pseudonymous context identifiers and reject obvious human-readable/direct identifiers. Syntactic opacity cannot prove semantic pseudonymisation; deployment governance must separately protect token-to-identity mappings.

### AUD-META-01 — self-authored audit evidence could promote readiness — CLOSED
A local Boolean claim is not evidence. Promotion requires signed assurance envelopes, pinned public-key fingerprints, SHA-256 evidence digests, evidence levels and fresh observation/expiry timestamps.

### AUD-META-02 — one signer could impersonate multiple assurance roles — CLOSED TECHNICALLY
Runtime/security, legal/privacy and independent assurance use separate signature purposes and must have three distinct pinned trust-anchor fingerprints. Technical separation does not by itself prove organisational independence; auditor governance must establish the actual owners and independence of those keys.

## Current mandate-shadow engineering path

The intended external-AI shadow path is now:

1. verify root-pinned identity, fresh matter authorization and current provider policy;
2. require exact active release and exact deployment-pinned DLP configuration;
3. inspect the exact mandate payload with local fail-closed DLP and separately signed Sensitive Data Protection evidence;
4. prove the exact workload VPC, restricted service perimeter and release-bound egress posture;
5. construct a fixed proposal-only Vertex request;
6. require the exact full provider request URL to be present in the signed provider passport;
7. prepare a restricted-VIP TLS connection and HSM-sign a fingerprint over that target URL plus exact request body;
8. run Legal Egress authorization against that exact transport proof;
9. only after ALLOW, send the exact prepared bytes through the exact attested TLS socket;
10. validate the provider response as a non-executable proposal;
11. HSM-sign the evidence manifest and commit verified evidence to the WORM evidence path;
12. only then return `CANDIDATE`.

This is engineering proof of the intended boundary. It is **not** proof that a real deployed environment currently operates this way.

## Automated audit gate v4

`npm run audit:legal` is a first-class CI step. Engineering PASS requires the security test set, the named adversarial regressions, required security modules, the scanner benchmark and a source-level assertion that production action execution remains physically blocked.

The audit still refuses to infer operating or legal readiness from repository evidence.

### Runtime evidence required
- live HSM/KMS posture and signing proof;
- live DLP/Sensitive Data Protection proof;
- live exact-network/VPC-Service-Controls proof;
- irreversible WORM retention lock and immutable receipts;
- production secrets-manager sourcing;
- backup + successful restore exercise;
- deletion test/receipt;
- incident and kill-switch drill;
- upload malware scanning;
- current SBOM/vulnerability evidence;
- deployed web/session/security-header checks.

### Legal/privacy evidence required
- exact provider AVV/DPA;
- BRAO §43e assessment;
- complete subprocessor chain;
- transfer assessment/safeguards where applicable;
- VVT / record of processing;
- DPIA/DSFA screening/result;
- EU AI Act use-case classification;
- AI-literacy/training evidence.

### Independent evidence required
- independent penetration test;
- remediation of all critical/high findings;
- independent German legal/privacy review for the exact Bao deployment;
- independent evidence-pack verification from a clean reviewer context;
- evidence of organisational independence for the assurance roles/trust anchors.

## Gate decision

| Target | Re-audit v4 verdict |
|---|---|
| Repository engineering | **PASS** |
| Known engineering findings above | **CLOSED + REGRESSION COVERED** |
| Audit-evidence provenance boundary | **PASS** |
| Purpose-separated HSM / transport design | **PASS AS ENGINEERING PROOF** |
| Proposal-only GCP shadow path | **PASS AS ENGINEERING PROOF** |
| Production action execution | **PHYSICALLY BLOCKED** |
| Synthetic/public-data shadow | **PASS** |
| Pre-audit / evidence-room readiness | **PASS** |
| Real mandate-data external-AI shadow | **NOT READY — E3/E4 EVIDENCE MISSING** |
| Autonomous mail/beA/case writes | **BLOCKED / OUT OF SCOPE** |
| Independent C5/AIC4/ISO assurance claim | **NOT ASSURED** |

## Product conclusion

TrustReady Legal now has a much stronger fail-closed engineering boundary and an audit system designed to catch false assurance rather than manufacture a score. The meaningful promotion threshold is no longer another repository feature.

Promotion remains evidence-driven:

`PRE-AUDIT READY` → deploy the exact dedicated environment → collect cryptographically attributable E3 runtime evidence → complete separately signed legal/privacy E4 evidence → independent pentest/legal/privacy/evidence verification → clean re-audit → `REAL MANDATE SHADOW READY`.

Until those external evidence classes exist, real mandate-data external-AI use remains blocked regardless of green CI, scanner scores or repository engineering quality.
