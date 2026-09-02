# TrustReady Legal — External-Style Re-Audit v5

Date: 2026-09-02
Scope: PR #14 (`legal-trust-layer`) at verified security head `8a8feb2ea8aa882b005e08526149c6faeee9698e` before this documentation commit.
Auditor stance: adversarial pre-audit / readiness assessment. This is not independent assurance, certification, a legal opinion, a C5 attestation or an AIC4 attestation.

## Executive opinion

**Engineering opinion: PASS.**

**Real mandate shadow opinion: NOT READY — signed live operating, legal/privacy and independent evidence still missing.**

The five P1 findings from the fresh review of the prior head are closed and regression-covered:

1. the real Node HTTPS path now uses a one-shot Agent whose only connection is the already-attested restricted-VIP socket;
2. prepared network evidence has an enforced send deadline and the complete Legal Egress decision is re-run immediately before transmission, including current kill-switch state;
3. network qualification consumes effective global, regional and exact-workload firewall views and rejects custom effective firewall-policy layers for the first pilot;
4. network posture is bound to the deployment-selected workload instance, zone and NIC, with exactly one NIC on the protected subnet;
5. the legal-shadow subnet and workload are explicitly IPv4-only and any external IPv4/IPv6 configuration fails closed.

Verified engineering evidence on security head `8a8feb2...`:

- full repository tests: **97/97 PASS**, 0 failures;
- selected legal/security audit suite: **77/77 PASS**, 0 failures;
- scanner benchmark: **30 labelled cases**, verified precision 1.0, verified recall 1.0, false-verified rate 0, exact-status accuracy 1.0 and provenance completeness 1.0;
- GitHub CI run **#150: SUCCESS**;
- dogfood run **#123: SUCCESS**;
- `npm run audit:legal`: **SUCCESS**;
- audit schema: `trustready-legal-preaudit-v5`;
- `regression_findings_closed: true`;
- `missing_regressions: []`;
- `production_actions_physically_blocked: true`;
- `pre_audit_ready: true`;
- `real_mandate_shadow_ready: false`;
- `independently_assured: false`.

## Latest P1 closures

### AUD-P1-18 — real Node HTTPS could ignore the attested socket — CLOSED
The former `agent:false` pattern was removed. The request now receives a dedicated one-shot `https.Agent` whose `createConnection` can return only the already-prepared socket and only once. A regression uses the real Node `https.request` implementation rather than a mock and proves that the exact prepared request bytes traverse the supplied socket.

### AUD-P1-19 — prepared socket / authorization could expire while idle — CLOSED
Prepared transport state includes an absolute expiry. Expired/closed prepared connections are destroyed before request construction. After provider-token acquisition, the pipeline re-runs `authorizeLegalEgress` using current time and current mutable runtime kill-switch state immediately before send. A changed kill switch and an expired network attestation both produce zero provider sends in regression tests.

### AUD-P1-20 — hierarchical/network firewall policy layers omitted — CLOSED FOR FIRST PILOT PROFILE
The GCP collector now consumes effective firewall views for the protected network, region and exact workload NIC. For the first mandate-shadow deployment it intentionally rejects active custom hierarchical/global/regional firewall-policy layers rather than trying to emulate every GCP policy-ordering interaction. Classic effective rules must still contain the expected network-wide restricted-VIP allow and deny-all controls.

### AUD-P1-21 — posture not bound to executing workload — CLOSED
The collector requires a deployment-selected workload instance, zone and NIC. That exact workload is fetched and must have exactly one NIC, on the exact protected VPC/subnetwork, with no external address configuration. An unrelated or empty workload set cannot qualify the deployment.

### AUD-P1-22 — unprotected IPv6 egress — CLOSED FOR FIRST PILOT PROFILE
The Terraform subnet explicitly sets `stack_type = "IPV4_ONLY"`. Runtime qualification requires both the subnet and the exact workload NIC to report IPv4-only posture and rejects `ipv6AccessConfigs`, dual-stack posture or external IPv4 configuration.

## Earlier engineering findings

The earlier audit closures remain enforced by regression tests: recursive Unicode/Base64URL DLP; prototype-safe zone checks; policy-versioned provider passports; explicit redirect denial; Cloud-KMS-correct ECDSA semantics; malformed-DLP fail-closed handling and scanner-config pinning; release-bound egress proof; exact-VPC and unscoped firewall rules; VPC-SC escape-policy denial; derived project identity; four separate HSM CryptoKeys; HSM-backed network attestation; exact URL/body transport fingerprinting; proposal-only Vertex integration; suffix-truncation-resistant evidence checkpoints; opaque evidence identifiers; cryptographically signed audit evidence; distinct runtime/legal/independent trust anchors; and physically disabled shadow/production action execution.

## Current mandate-shadow engineering path

1. verify root-pinned identity, fresh matter authorization and current provider policy;
2. require exact active release and exact deployment-pinned DLP configuration;
3. inspect the exact mandate payload and create separately signed DLP evidence;
4. prove exact workload/VPC/subnet/effective-firewall/VPC-SC posture;
5. construct the fixed proposal-only Vertex request;
6. require the exact provider URL in signed provider policy;
7. prepare a restricted-VIP TLS socket and HSM-sign the exact target + body fingerprint;
8. run Legal Egress authorization;
9. acquire provider authorization;
10. re-check transport expiry and run the full Legal Egress authorization again against current kill-switch/runtime state;
11. send the exact prepared bytes using a one-shot Agent that can use only the attested socket;
12. validate the provider response as a non-executable proposal;
13. HSM-sign the evidence manifest and commit verified evidence to WORM storage;
14. only then return `CANDIDATE`.

This is **engineering proof**, not evidence that a real deployed environment currently operates this way.

## Automated audit gate v5

`npm run audit:legal` is a CI release gate. It explicitly requires the real-Node socket regression, transport-expiry/pre-send-auth regressions, effective-firewall/workload-binding tests, IPv4-only IaC and all earlier security regressions.

The audit still refuses to infer operating or legal readiness from repository evidence.

### Runtime E3/E4 evidence still required
- live four-key HSM/KMS posture and signing proof;
- live exact-config DLP proof;
- live exact-workload / effective-firewall / VPC-SC / restricted-transport proof;
- irreversible WORM retention lock and immutable receipts;
- production secrets-manager sourcing and rotation/revocation;
- backup + successful restore exercise;
- deletion test/receipt;
- incident/kill-switch and credential-revocation drills;
- upload malware scanning;
- current SBOM/vulnerability evidence;
- deployed web/session/security-header checks.

### Legal/privacy E4 evidence still required
- exact provider AVV/DPA;
- BRAO §43e assessment;
- complete subprocessor chain;
- transfer assessment/safeguards where applicable;
- VVT / record of processing;
- DPIA/DSFA screening/result;
- EU AI Act use-case classification;
- AI-literacy/training evidence.

### Independent E4 evidence still required
- independent penetration test against the exact deployment;
- remediation of all critical/high findings;
- independent German legal/privacy review;
- independent evidence-pack verification;
- organisational independence evidence for assurance-role trust anchors.

## Gate decision

| Target | Re-audit v5 verdict |
|---|---|
| Repository engineering | **PASS** |
| Known P0/P1 engineering findings through this review | **CLOSED + REGRESSION COVERED** |
| Real Node connection-bound provider transport | **PASS AS ENGINEERING PROOF** |
| Effective firewall / exact-workload / IPv4-only boundary | **PASS AS ENGINEERING PROOF** |
| Audit-evidence provenance boundary | **PASS** |
| Production action execution | **PHYSICALLY BLOCKED** |
| Synthetic/public-data shadow | **PASS** |
| Pre-audit / evidence-room readiness | **PASS** |
| Real mandate-data external-AI shadow | **NOT READY — E3/E4 EVIDENCE MISSING** |
| Autonomous mail/beA/case writes | **BLOCKED / OUT OF SCOPE** |
| Independent C5/AIC4/ISO assurance claim | **NOT ASSURED** |

## Product conclusion

The meaningful next threshold is now deployment evidence, not another self-asserted architecture score. Promotion remains fail-closed:

`PRE-AUDIT READY` → exact dedicated deployment → signed E3 operating evidence → separately authorised legal/privacy E4 evidence → independent pentest/review/evidence verification → clean re-audit → `REAL MANDATE SHADOW READY`.

Until those external evidence classes exist, real mandate-data external-AI use remains blocked regardless of green CI or engineering quality.
