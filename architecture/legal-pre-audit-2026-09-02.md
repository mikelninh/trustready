# TrustReady Legal — External-Style Pre-Audit

Date: 2026-09-02
Scope: PR #14 (`legal-trust-layer`) at head `e10a740a6951fd88f07dba808d2b84ec5bc65683`
Auditor stance: adversarial pre-audit / readiness assessment, not independent assurance, certification, legal opinion, C5 attestation or AIC4 attestation.

## Executive opinion

**Opinion: FAIL FOR PRODUCTION ASSURANCE / PRE-AUDIT READY.**

TrustReady Legal is materially audit-friendly: it has explicit controls, evidence requirements, fail-closed runtime gates, a reproducible evidence bundle, infrastructure-as-code and extensive adversarial tests. However, an external production audit would not pass today because operating effectiveness is not yet demonstrated for the real deployment and several mandatory controls have no evidence. The GCP reference documentation itself correctly says committed Terraform is static E2-style evidence only and that only live qualification stored in the locked evidence bucket may support the real-mandate shadow candidate label.

The current branch is appropriate for a **synthetic/read-only pre-production shadow exercise**, not for a claim of independent assurance or full production readiness.

## Audit criteria used

Primary internal criteria:
- TrustReady Legal 46-control matrix LT-001..LT-046.
- TrustReady Legal threat model and evidence-pack rules.

External lenses:
- BSI C5:2020 cloud security/control-system expectations and independent audit model.
- BSI AIC4 AI-specific lifecycle/security criteria; AIC4 treats classic cloud-service risks/C5 as a prerequisite for the full picture.
- ISO/IEC 27001:2022 cross-reference lens via the BSI C5 mapping.
- BRAO §§ 43a/43e confidentiality and service-provider requirements.
- GDPR security, processor governance, records, DPIA and incident-response requirements as applicable.
- OWASP agentic-AI threat lenses for prompt/tool/identity/supply-chain/runtime abuse.

## Evidence sampled

- Latest GitHub CI: SUCCESS.
- Latest TrustReady dogfood: SUCCESS.
- 71/71 Node tests passing on latest CI.
- 30-case scanner benchmark: precision 1.0, recall 1.0, false-verified rate 0, exact-status accuracy 1.0, provenance completeness 1.0.
- Legal runtime modules: identity/matter ABAC, DLP, provider passports, network gate, typed action approvals, replay protection, proposal-only model boundary, evidence chain.
- GCP reference IaC: restricted egress, VPC Service Controls, HSM keys, evidence bucket retention configuration.
- Evidence-manifest verification and WORM pipeline tests.

## Known blocking security findings observed in current head

### AUD-P1-01 — DLP misses unpadded / URL-safe Base64 identifiers
`legal-dlp.mjs` only recognises standard Base64 strings whose length is a multiple of four. An encoded identifier such as unpadded `YWxpY2VAZXhhbXBsZS5jb20` can therefore avoid the recursive decoded-content inspection. This is a known prior review finding and remains visible in the current implementation.

Impact: direct identifier leakage through an allowed free-text field.

Required: normalise URL-safe alphabet and padding before bounded decode; add positive/negative regression corpus.

### AUD-P1-02 — Data-zone validation uses inherited object properties
`authorizeLegalEgress` still checks `request.zone in ZONES`. JavaScript's `in` includes inherited properties; an invalid name such as `toString` can satisfy the initial membership check while not behaving as a mandate zone.

Impact: malformed zone can bypass mandate-specific gates.

Required: explicit enum Set / `Object.hasOwn` and negative regression test.

### AUD-P1-03 — Provider passport is not bound to active policy version
The runtime verifies the request's policy version against runtime state, but the signed provider passport itself has no required policy-version binding to that active version.

Impact: a still-unexpired older passport can retain regions/endpoints/fields after policy tightening.

Required: signed passport schema/version + active policy version binding; rotation/revocation regression test.

### AUD-P1-04 — Redirect status is not fail-closed
`legal-network.mjs` rejects `redirected === true`, but does not require `redirected === false`.

Impact: missing/unknown redirect observation can be treated as safe.

Required: explicit false requirement and malformed-attestation regression test.

### AUD-P2-01 — Evidence top-level identifiers are not pseudonymisation-enforced
Evidence metadata is scanned, but top-level `tenant_id`, `matter_id` and `actor_id` are written without an explicit opaque/pseudonymous identifier validator.

Impact: the evidence vault can accidentally become a second store of direct mandate identities.

Required: opaque-ID schema / pseudonymous references at the event boundary.

## 46-control audit snapshot

Legend:
- **PASS** = sufficient repository-level design/test evidence for this pre-audit criterion.
- **PARTIAL** = control exists or is designed, but required live/operating/organisational evidence is missing.
- **FAIL** = required control/evidence absent or a known defect prevents reliance.

| ID | Result | Pre-audit observation |
|---|---|---|
| LT-001 | PARTIAL | Zones/classification exist; no live classification-event population sampled. |
| LT-002 | PARTIAL | Matter ABAC + fresh authorization tests exist; real IdP/policy-store operating evidence absent. |
| LT-003 | PARTIAL | Deny-all/restricted egress IaC + tests exist; real deployed network qualification absent. |
| LT-004 | PASS | Signed provider passport is mandatory; separate stale-policy binding finding remains. |
| LT-005 | FAIL | No real AVV/DPA contract-register evidence sampled. |
| LT-006 | FAIL | No signed external/legal §43e vendor assessment sampled. |
| LT-007 | PARTIAL | Provider governance status exists; real complete subprocessor chain not sampled. |
| LT-008 | PARTIAL | Explicit third-country classification enforced; real transfer assessment evidence not sampled. |
| LT-009 | PARTIAL | Training-on-customer-data must be false in passport; provider contractual/runtime proof absent. |
| LT-010 | PARTIAL | Retention bounded in policy; provider deletion/retention operating test absent. |
| LT-011 | FAIL | Structural minimisation exists, but known Base64 DLP bypass prevents reliance for mandate egress. |
| LT-012 | FAIL | Detection exists; deterministic pseudonymisation/redaction workflow/evidence is incomplete. |
| LT-013 | PARTIAL | TLS and restricted-route probes are implemented/tested; live production proof absent. |
| LT-014 | PARTIAL | HSM/storage IaC exists; live encryption-at-rest evidence absent. |
| LT-015 | FAIL | IaC keys are purpose-separated, not demonstrated tenant-separated keys as required by matrix. |
| LT-016 | FAIL | Approved production secrets-manager sourcing is not demonstrated in sampled IaC/runtime evidence. |
| LT-017 | PARTIAL | Runtime requires MFA; IdP configuration/account-class coverage evidence absent. |
| LT-018 | PARTIAL | ABAC/least privilege implemented; periodic access-review evidence absent. |
| LT-019 | PARTIAL | Evidence metadata guards exist; real production log-redaction scan/canary proof absent. |
| LT-020 | PARTIAL | Hash chain, signed manifests and WORM adapters exist; live locked storage/anchor absent. |
| LT-021 | PASS | Outbound high-risk actions require approval and are shadow-locked in tests. |
| LT-022 | PASS | Typed irreversible writes are gated and shadow-restricted. |
| LT-023 | FAIL | Exact provider/model/material configuration version is not fully bound/recorded as a release gate. |
| LT-024 | PASS | AI output is proposal-only/untrusted and cannot directly gain tools/network/actions. |
| LT-025 | PARTIAL | Matter authorization exists; full retrieval/RAG cross-matter operating test in real stack absent. |
| LT-026 | PARTIAL | Injection/tool boundaries are implemented; broader real-document/PDF/OCR/HTML/RAG corpus evidence incomplete. |
| LT-027 | FAIL | No production upload malware/content-scanning evidence sampled. |
| LT-028 | FAIL | No encrypted backup operating evidence sampled. |
| LT-029 | FAIL | No dated restore exercise evidence sampled. |
| LT-030 | PARTIAL | Retention policies exist in design/IaC; live enforcement evidence absent. |
| LT-031 | FAIL | No end-to-end deletion receipt/test for applicable data sampled. |
| LT-032 | PASS | Kill-switch behavior is fail-closed and tested. |
| LT-033 | PASS | Key/credential revocation behavior is tested; production IdP credential drill still advisable. |
| LT-034 | FAIL | No exercised breach-response runbook evidence sampled. |
| LT-035 | FAIL | No current VVT/record-of-processing artifact sampled. |
| LT-036 | FAIL | No completed/signed DPIA/DSFA screening sampled. |
| LT-037 | PARTIAL | Architecture/data-flow artifacts exist; live/deployment-current attestation absent. |
| LT-038 | PARTIAL | Purpose is carried in requests, but necessity/purpose governance evidence is incomplete. |
| LT-039 | FAIL | No signed AI Act use-case classification artifact sampled. |
| LT-040 | FAIL | No user AI-literacy/training completion evidence sampled. |
| LT-041 | PARTIAL | CI/tests/benchmark pass; dedicated SAST/dependency/container/IaC vulnerability evidence not complete. |
| LT-042 | FAIL | No SBOM + current vulnerability report sampled. |
| LT-043 | FAIL | No deployed security-header/session-control test evidence for the production user surface sampled. |
| LT-044 | FAIL | No independent penetration test/remediation report. This is an explicit RELEASE GATE. |
| LT-045 | PASS | Provider review expiry is enforced through `valid_until`. |
| LT-046 | PARTIAL | Reproducible signed bundle and tamper tests exist; independent production verification/live anchor not yet sampled. |

Because readiness is binary on mandatory controls, the number of passing controls is not a production score: **one failed BLOCK/RELEASE GATE is sufficient for NOT READY.**

## Operating-effectiveness gap

The largest audit gap is no longer architecture. It is **operating evidence**.

The repository contains a strong GCP reference configuration, but its own README correctly states:
- committing Terraform does not prove resources exist or are correctly deployed;
- the evidence bucket lock is deliberately not enabled by default because it is irreversible;
- only live qualification against real resources, with the qualification result stored in the locked bucket, can support the real-mandate shadow-candidate label.

Therefore this pre-audit cannot treat IaC tests as E3 runtime evidence.

## External-assurance gap

AIC4/C5-style assurance is not self-issued. TrustReady can prepare and continuously validate evidence, but a real independent assurance statement requires an eligible external auditor/reviewer and the applicable audit process. The BSI describes C5 audits as independently commissioned/performed and notes that a C5 attestation is not a BSI certification.

For TrustReady Legal, independent review should additionally include German legal-profession/privacy specialists for the specific deployment, especially §43e service-provider arrangements, processing records, DPIA screening, international transfers and mandate-specific consent questions where applicable.

## Audit verdict by target

| Target | Verdict |
|---|---|
| Repository engineering quality | **PASS WITH FINDINGS** |
| Synthetic/public-data shadow | **PASS WITH FINDINGS** |
| Pre-audit / evidence-room readiness | **PASS WITH FINDINGS** |
| Real mandate-data external-AI shadow | **FAIL TODAY** |
| Human-approved production actions | **FAIL TODAY** |
| Autonomous mail/beA/case writes | **FAIL / OUT OF SCOPE** |
| C5/AIC4/ISO independent assurance claim | **FAIL — no independent audit** |

## Fastest path to a clean real-mandate shadow pre-audit

P0/Audit blockers:
1. Fix AUD-P1-01..04 and AUD-P2-01; add regressions.
2. Deploy the dedicated GCP environment and run live HSM/DLP/network qualification.
3. Deliberately review then lock the WORM evidence bucket; store the live signed qualification result there.
4. Implement/verify approved secrets-manager sourcing.
5. Produce provider contract/AVV/§43e/subprocessor/transfer evidence for the exact provider/service/model.
6. Produce VVT + DPIA/DSFA screening + AI Act use-case classification.
7. Add upload malware scanning, backup/restore test, deletion test and incident exercise.
8. Generate SBOM + vulnerability scan and run deployed web/session/security-header checks.
9. Commission independent penetration test; remediate all critical/high findings.
10. Run the complete evidence pack from a clean auditor account and independently verify all signatures/hashes.

Only after those steps should TrustReady use **REAL MANDATE SHADOW PILOT — READY**.

## Product lesson

This pre-audit validates the core TrustReady product thesis: CI being green is not the same as being audit-ready. The product should automatically detect exactly these distinctions — claim vs document vs configuration vs runtime proof vs independent assurance — and refuse to promote a control beyond the strongest evidence actually observed.
