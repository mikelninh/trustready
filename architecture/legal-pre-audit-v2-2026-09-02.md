# TrustReady Legal — External-Style Re-Audit v12

Date: 2026-09-02
Scope: PR #14 (`legal-trust-layer`). The v12 security implementation was verified at `20d1e404cba4b1ef5eb53c31a366bd18d5726feb` before this documentation commit. This document does not self-declare the final exact-head benchmark: the immutable PR head carrying it must itself pass same-SHA CI, dogfood and adversarial Codex exact-head review.

Auditor stance: adversarial pre-audit / readiness assessment. This is **not** independent assurance, certification, a legal opinion, a C5 attestation, an AIC4 attestation, or proof that a live Bao deployment is ready for mandate data.

## Executive opinion

**Repository engineering implementation: PASS at verified v12 implementation head.**

**Final documented exact-head engineering benchmark: REQUIRES SAME-SHA CI + DOGFOOD + CODEX VERDICT.**

**Real mandate-data external-AI shadow: NOT READY.** Live E3 operating evidence, authorised legal/privacy E4 evidence and an independent external final assurance verdict remain missing.

Verified evidence on implementation head `20d1e404...`:

- full repository tests: **131/131 PASS**, 0 failures;
- existing selected legal/security audit suite: **98/98 PASS**, 0 failures;
- dedicated v12 authenticated-deployment regressions: **9/9 PASS**, 0 failures, no missing regressions;
- scanner benchmark: **30 labelled cases**, verified precision 1.0, verified recall 1.0, false-verified rate 0, exact-status accuracy 1.0, provenance completeness 1.0, 0 false positives and 0 false negatives;
- GitHub CI **#244: SUCCESS**;
- dogfood **#216: SUCCESS**;
- `npm run audit:legal`: **SUCCESS**;
- audit schema: `trustready-legal-preaudit-v12`;
- `pre_audit_ready: true`;
- `production_actions_physically_blocked: true`;
- `real_mandate_shadow_ready: false`;
- `independently_assured: false`;
- `external_final_verdict_required: true`.

## v12 trust-boundary closures

### AUD-P1-42 — root-signed keyring could remain trusted after root-keyring expiry — CLOSED
The rooted trust store retains the signed keyring expiry and checks it on **every subsequent key resolution**. A service that stays alive beyond `valid_until` can no longer continue accepting leaf signatures from the expired rooted keyring. Invalid or expired resolution time fails closed.

### AUD-P1-43 — mandate data could reach DLP before the executing GCP project was authenticated — CLOSED
Before any mandate payload is inspected by Google Sensitive Data Protection, the production pipeline authenticates the executing VM through the local GCE metadata endpoint and obtains the runtime project identity. DLP must be configured for that exact authenticated project. Network/VPC-SC qualification must independently describe the same executing workload and project before DLP receives mandate content.

### AUD-P1-44 — infrastructure qualification could combine DLP and network evidence from different projects — CLOSED
The infrastructure qualifier authenticates local GCE runtime identity first, requires DLP to match that project, validates the network collector against the same runtime, checks all four production HSM key versions against the authenticated project, and only then runs its DLP canaries. Caller-supplied `now` or `clock` is rejected so qualification freshness cannot be backdated.

### AUD-P1-45 — any locked WORM bucket could be substituted as evidence destination — CLOSED
The approved evidence bucket is pinned onto the dedicated gateway as GCE instance metadata provisioned directly from `google_storage_bucket.evidence.name`. Runtime code reads that value through authenticated local metadata. The WORM adapter must report that exact bucket, GCS bucket metadata must carry a concrete project number, and that project number must equal the project protected by the qualified VPC Service Controls perimeter. WORM posture is verified **before mandate DLP inspection**.

### AUD-P1-46 — runtime mandate path could use HSM keys from another GCP project — CLOSED
The mandate-data runtime applies the same project identity requirement used by the infrastructure qualifier: each of the four HSM key-version names for DLP, egress, network and evidence must resolve to the exact authenticated GCE runtime project. A real production HSM key in another project cannot satisfy the runtime path even if credentials or a broader perimeter could otherwise reach it. This check executes before signed network enforcement and before any mandate DLP call.

### AUD-P1-47 — successful external egress could become invisible if post-send WORM evidence failed — CLOSED
The runtime now uses a durable pre-send outbox pattern. After the exact request is DLP-approved, transport-bound and initially authorised — but **before provider credentials are retrieved and before any provider request can be submitted** — it builds an exact egress-intent record containing hashed matter identity, provider/use-case/release, initial decision hash, provider-passport hash, DLP/network/egress-attestation hashes, exact transport/request fingerprints and the qualified evidence resource identity.

That intent is signed with the qualified evidence HSM key and immutably written to the already-qualified WORM bucket. The receipt must prove the exact pinned bucket, protected GCP project, content hash and mandatory retention floor. Any signing, write, resource, retention or hash mismatch cancels the prepared request and blocks egress. The record is explicitly labelled `PREPARED_FOR_EGRESS_NOT_PROOF_OF_SEND`, so it cannot falsely claim that a send occurred.

The normal post-send evidence bundle still records the actual result and includes the signed pre-send intent plus its immutable receipt. Therefore a later WORM/bundle failure can leave an unresolved immutable **possible/attempted egress intent**, but cannot leave a sensitive provider egress with no durable pre-send evidence at all.

## v11 trust-boundary closures retained

- signed envelopes are strict immutable snapshots before signature verification; Proxy/accessor/custom-prototype/sparse/cyclic/ambiguous signed values fail closed;
- verification returns only the verified snapshot, not a caller-owned live body;
- production mandate pipeline rejects caller-controlled `now` or `clock`;
- provider passport is verified against rooted trust and active policy before target/use-case routing;
- production DLP is fixed to the approved legal minimum, `POSSIBLE` likelihood, max findings 1000 and EU location;
- DLP configuration fingerprint includes exact GCP `project_id` and `location`;
- production WORM retention floor remains 30 days;
- production HSM/DLP/runtime-identity/network/transport/WORM trust relies on exact private instance membership, not copyable brands.

## Earlier engineering controls retained

- offline-root-pinned signed key trust and leaf revocation/validity checks;
- four purpose-separated Cloud HSM CryptoKeys for DLP, egress, network and evidence;
- Google KMS `EC_SIGN_P256_SHA256` verification semantics aligned with KMS;
- strict single frozen request snapshot prevents getter/`toJSON`/prototype and scan-send representation divergence;
- identity and matter authorization bound to tenant/session/matter/operation/resource version with MFA for mandate access;
- provider policy and egress proof bound to active policy/release;
- recursive local DLP and independent exact-payload Google DLP attestation;
- proposal-only Vertex request with tools/functions/actions disabled;
- exact approved target URL + exact request bytes bound to the actual one-shot restricted-VIP TLS socket;
- DNS poisoning, redirect, socket substitution, target-path substitution and stale/replay paths fail closed;
- full Legal Egress authorization is synchronously re-run as the last gate immediately before provider submission;
- runtime identity is cross-checked to exact Compute instance ID/name, zone, VPC, subnet, NIC and service account;
- IPv4-only private workload with no external IP and deny-all egress except restricted Google API VIP TCP/443;
- global/regional/workload effective-firewall views and exact seven-service VPC-SC runtime allowlist are fail-closed;
- append-only evidence chain is anchored to signed checkpoints and detects mutation/reorder/deletion/truncation;
- evidence bundle hashes actual artifact bytes and writes signed manifest last as immutable commit marker;
- self-authored `verified:true` data cannot promote readiness;
- runtime/security, legal/privacy and independent assurance use separate evidence classes/trust anchors;
- local pre-audit cannot self-assert independent assurance or real-mandate readiness;
- autonomous production actions remain physically disabled; shadow remains proposal-only.

## Dedicated mandate-shadow engineering order

1. require production runtime state and exact production adapter instances;
2. reject caller-supplied production time and create an internal production timestamp;
3. convert the full request to one strict frozen JSON snapshot;
4. verify provider passport before routing and bind exact use case/region/target;
5. authenticate the executing GCE runtime through local metadata;
6. require DLP project = authenticated runtime project and WORM bucket = runtime-pinned evidence bucket;
7. verify four distinct production HSM key postures and require **all four HSM keys belong to the authenticated runtime project**;
8. collect and sign network enforcement; require it describes the exact authenticated runtime and project;
9. derive the protected project number from VPC-SC evidence;
10. verify locked WORM posture; require exact runtime-pinned bucket and exact protected project number;
11. only now inspect the exact frozen mandate payload with EU Google DLP and HSM-sign the DLP evidence;
12. build the fixed proposal-only Vertex request from the same frozen payload;
13. prepare and HSM-attest exact target URL, exact bytes and actual restricted-VIP TLS socket;
14. execute deterministic initial Legal Egress authorization;
15. HSM-sign and immutably commit the exact **pre-send egress intent** to the qualified WORM resource; any failure cancels the prepared request;
16. only after the durable intent exists, obtain the provider credential;
17. synchronously execute the complete fresh Legal Egress authorization as the final pre-send gate;
18. with no async boundary, send exact prepared bytes over the one-shot attested socket;
19. validate model response as non-executable proposal;
20. build, HSM-sign and verify the final evidence manifest, including pre-send intent/receipt and actual outcome evidence;
21. commit artifacts immutably to the pre-qualified WORM destination, manifest last;
22. only then may the engineering pipeline return `CANDIDATE`.

This sequence is repository engineering proof. It does **not** establish that a deployed environment currently satisfies it.

## Automated audit gate v12

`npm run audit:legal` executes the v12 fail-closed release gate. It inherits the v11 adversarial/legal suite and additionally requires all nine named v12 regressions:

1. root-keyring expiry enforced per resolution;
2. authenticated GCE runtime pins exact evidence bucket;
3. WORM posture requires concrete GCS project identity;
4. infrastructure qualifier rejects caller-controlled time;
5. qualifier authenticates runtime/network/WORM before DLP canaries;
6. mandate pipeline authenticates runtime/network/WORM before mandate DLP;
7. mandate pipeline binds all four HSM key projects to the authenticated runtime project before egress or DLP;
8. mandate pipeline commits immutable pre-send intent before provider credentials or send;
9. Terraform pins the provisioned evidence bucket onto the dedicated gateway metadata.

Dedicated helper tests additionally attack pre-send intent resource substitution, insufficient retention and WORM outages. A missing or failing v12 regression turns Engineering PASS into FAIL. The local audit still hard-codes `real_mandate_shadow_ready:false` and `independently_assured:false` unless external evidence/decision processes outside the local pre-audit exist.

## Runtime operating evidence still required

- provision the exact dedicated GCP legal-shadow environment;
- collect live four-key HSM/KMS posture and signing evidence;
- collect live exact-project/exact-config EU Sensitive Data Protection evidence;
- collect live GCE metadata identity, exact workload, effective firewall, exact VPC-SC and restricted-transport evidence;
- deliberately apply and verify irreversible WORM retention lock and persist immutable receipts;
- prove production secrets-manager sourcing plus rotation/revocation;
- add live upload malware scanning evidence;
- run encrypted backup + successful restore exercise;
- run deletion test/receipt;
- exercise incident/kill-switch and credential-revocation drills;
- generate deployed-release SBOM + vulnerability report;
- run deployed security-header/session-control checks.

**Important:** the irreversible GCS Bucket Lock is intentionally not activated by repository engineering alone. It requires an explicit operational decision on the real bucket.

## Legal/privacy evidence still required

- exact provider AVV/DPA;
- BRAO §43e assessment for the exact provider/model/use case;
- complete subprocessor chain;
- transfer assessment/safeguards as applicable;
- VVT / record of processing;
- DPIA/DSFA screening/result;
- EU AI Act use-case classification;
- AI-literacy/training evidence for pilot users.

## Independent / final-verdict evidence still required

- independent penetration test against the exact deployed environment;
- remediation of all critical/high findings;
- independent German legal/privacy review for the exact deployment;
- independent evidence-pack verification;
- externally evidenced organisational independence;
- final assurance verdict issued outside the local TrustReady pre-audit process.

## Gate decision

| Target | Re-audit v12 verdict |
|---|---|
| Repository engineering implementation at `20d1e404...` | **PASS** |
| Full repository test suite | **131/131 PASS** |
| Existing selected legal/security suite | **98/98 PASS** |
| Dedicated v12 regressions | **9/9 PASS** |
| Pre-send intent adversarial helper tests | **4/4 PASS** |
| Scanner benchmark | **PASS — 1.0 precision, 1.0 recall, 0 false verified** |
| v12 local pre-audit | **PASS** |
| Final documented exact-head benchmark | **REQUIRES SAME-SHA CI + DOGFOOD + CODEX VERDICT** |
| Known delayed P1 classes through review `5095025151` + internally found runtime HSM project and pre-send evidence gaps | **CLOSED + REGRESSION COVERED** |
| Production action execution | **PHYSICALLY BLOCKED** |
| Pre-audit / evidence-room readiness | **PASS** |
| Real mandate-data external-AI shadow | **NOT READY — LIVE E3/E4 + EXTERNAL VERDICT MISSING** |
| Autonomous mail/beA/case writes | **BLOCKED / OUT OF SCOPE** |
| Independent C5/AIC4/ISO assurance claim | **NOT ASSURED** |

## Product conclusion

TrustReady now treats **signed-object identity, time, executing workload, cloud project, HSM project, DLP deployment, evidence destination, durable pre-send intent, adapter identity, network path, exact payload and final assurance decision** as explicit trust boundaries rather than caller-controlled claims.

Promotion remains fail-closed:

`PRE-AUDIT READY` → exact dedicated live deployment → cryptographically attributable live E3 evidence → authorised legal/privacy E4 evidence → independent pentest/review/evidence verification + organisational-independence proof → **external final verdict** → `REAL MANDATE SHADOW READY`.

Until those external evidence classes and the external verdict exist, real mandate-data external-AI use remains blocked regardless of green CI, dogfood or repository engineering quality.
