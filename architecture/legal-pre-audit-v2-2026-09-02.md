# TrustReady Legal — External-Style Re-Audit v10

Date: 2026-09-02
Scope: PR #14 (`legal-trust-layer`) at verified security head `868f9cde6e4361f203171f166c83bc0dfea6ca6d` before this documentation commit.
Auditor stance: adversarial pre-audit / readiness assessment. This is not independent assurance, certification, a legal opinion, a C5 attestation or an AIC4 attestation.

## Executive opinion

**Engineering opinion: PASS.**

**Real mandate shadow opinion: NOT READY — cryptographically attributable live operating evidence, authorised legal/privacy evidence and an external independent assurance verdict are still missing.**

The latest hardening loop closes the P1 findings from Codex reviews through `5094038228` and adds an additional internally identified DLP project/residency confused-deputy guard. All are regression-covered and mandatory in Audit v10.

Verified engineering evidence on exact security head `868f9cde...`:

- full repository tests: **115/115 PASS**, 0 failures;
- selected legal/security audit suite: **95/95 PASS**, 0 failures;
- scanner benchmark: **30 labelled cases**, verified precision 1.0, verified recall 1.0, false-verified rate 0, exact-status accuracy 1.0 and provenance completeness 1.0;
- GitHub CI run **#209: SUCCESS**;
- dogfood run **#181: SUCCESS**;
- `npm run audit:legal`: **SUCCESS**;
- audit schema: `trustready-legal-preaudit-v10`;
- `regression_findings_closed: true`;
- `missing_regressions: []`;
- `production_actions_physically_blocked: true`;
- `pre_audit_ready: true`;
- `candidate_for_external_assurance: false` without E3/E4 evidence;
- `external_final_verdict_required: true`;
- `real_mandate_shadow_ready: false`;
- `independently_assured: false`.

## Latest trust-boundary closures

### AUD-P1-33 — adapter brands could be inherited or copied — CLOSED
Production trust no longer relies on readable/copyable Symbol properties. HSM signers, DLP scanners, GCE runtime-identity providers, network collectors, restricted transports and WORM stores are accepted as production adapters only when the exact object instance was constructed by the corresponding production factory and is present in a private module WeakSet. Prototype inheritance, symbol copying and lookalike wrapper objects cannot become production adapters.

### AUD-P1-34 — DLP scan and provider send could observe different payloads — CLOSED
The production mandate pipeline now normalises the entire request into one strict immutable JSON snapshot before security I/O. It rejects functions, `toJSON`, accessors/getters, custom object or array prototypes, symbol properties, sparse arrays, non-index array properties, cycles, non-finite numbers, excessive nesting and excessive node counts. DLP, deterministic policy authorisation, Vertex request construction and evidence generation consume this same frozen snapshot, removing scan/send representation divergence and post-scan mutation.

### AUD-P1-35 — production DLP configuration could be weakened — CLOSED
The production Google Sensitive Data Protection adapter has a fixed legal minimum profile:

- the complete approved legal info-type set;
- `POSSIBLE` minimum likelihood;
- `maxFindingsPerRequest = 1000`;
- production location fixed to `eu`;
- native module-captured Google client only.

Caller attempts to reduce the info-type set, raise the likelihood threshold, lower the finding limit, select `us`/`global`, or inject a test backend are rejected at construction.

### AUD-P1-36 — production WORM retention floor could be lowered — CLOSED
The production GCS Bucket Lock adapter enforces a non-reducible minimum retention requirement of **30 days (2,592,000 seconds)**. Caller values below the floor are rejected. The underlying bucket must still prove permanently locked retention, uniform bucket-level access, public-access prevention and immutable create-only object generation receipts.

### AUD-P1-37 — real DLP could run in the wrong protected project — CLOSED
Before any mandate payload is inspected, the production pipeline requires the DLP scanner project to equal the exact production GCP project represented by the trusted network collector. The DLP attestation carries `scanner_project_id`, and the signed network enforcement posture carries the same project identity. A real Google DLP service in a different project cannot act as a confused deputy for the protected Bao gateway.

## Earlier engineering findings — still closed and regression-covered

- root-pinned offline-signed key trust; self-asserted rooted booleans denied;
- four purpose-separated production Cloud HSM keys for DLP, egress, network and evidence;
- Cloud KMS `EC_SIGN_P256_SHA256` verification semantics aligned with Google KMS;
- fresh identity and matter authorisation bound to tenant/session/matter/operation/resource version;
- provider passport bound to active policy version and exact release;
- URL-safe/unpadded Base64, Unicode/zero-width and recursive DLP evasions fail closed;
- prototype/inherited data-zone bypass blocked;
- exact proposal-only Vertex request with tools/functions/actions disabled;
- full target URL + exact request bytes bound to the actual one-shot restricted-VIP TLS socket;
- DNS poisoning, redirects, socket substitution, target-path substitution and replay fail closed;
- final full Legal Egress authorisation is synchronous and immediately precedes request submission;
- production DNS/TLS/HTTPS implementations are not caller-injectable;
- runtime identity derives from the local GCE metadata endpoint and is cross-checked to exact Compute instance ID/name, zone, VPC, subnet, NIC and service account;
- exact effective-firewall views required; malformed classic/policy rules and policy rules without `match` fail closed;
- IPv4-only private workload with no external IPv4/IPv6;
- deny-all egress except restricted Google API VIP TCP/443;
- exact seven-service VPC Service Controls runtime allowlist; escape policies and malformed policy state denied;
- exact DLP scanner configuration and payload fingerprint bound into signed DLP evidence;
- append-only evidence chain anchored to the trusted latest signed checkpoint;
- verified evidence bundle artifacts hashed against actual bytes before immutable commit;
- self-authored `verified:true` evidence cannot promote readiness;
- runtime/security, legal/privacy and independent assurance use separate trust purposes/anchors;
- local TrustReady pre-audit can never self-assert `independently_assured` or `real_mandate_shadow_ready`;
- production actions remain physically disabled (`PRODUCTION_ACTIONS_DISABLED`); shadow returns `SHADOW_LOCK`.

## Dedicated mandate-shadow engineering path

1. require a production runtime state and internally verified rooted key trust;
2. require exact production HSM/DLP/network/transport/WORM adapter instances;
3. require DLP EU location and exact DLP project = protected gateway project before mandate-data inspection;
4. normalise the entire request to one strict frozen JSON snapshot;
5. verify the active release, policy, provider target and fixed DLP configuration;
6. verify four distinct Cloud HSM key postures;
7. DLP-scan the exact frozen mandate payload and HSM-sign its exact fingerprint/project/config evidence;
8. collect local GCE runtime identity and cross-check exact workload, VPC, subnet, NIC and service account;
9. validate global/regional/workload effective-firewall views and exact VPC-SC posture;
10. HSM-sign release-bound egress-enforcement evidence;
11. build the fixed proposal-only Vertex request from the same frozen payload;
12. prepare and HSM-attest the exact approved target URL, exact request bytes and actual restricted-VIP TLS socket;
13. execute deterministic Legal Egress authorisation;
14. obtain the provider credential;
15. synchronously execute the complete fresh Legal Egress authorisation as the last gate;
16. with no async boundary, send the exact prepared bytes over the one-shot attested socket;
17. validate the response as a non-executable proposal;
18. build, HSM-sign and verify the evidence manifest against actual artifact bytes;
19. commit artifacts immutably to the locked WORM namespace, with the signed manifest written last as the commit marker;
20. only then may the engineering pipeline return `CANDIDATE`.

This is **engineering proof**. It does not prove that a live Bao deployment currently satisfies these controls.

## Automated audit gate v10

`npm run audit:legal` is a CI release gate. It requires all named P0/P1 regressions above and refuses to turn repository engineering into operating, legal or independent readiness.

Audit v10 currently reports:

- Engineering: **PASS**
- production actions physically blocked: **true**
- exact-instance adapter trust required: **true**
- strict request snapshot required: **true**
- production DLP minimum fixed: **true**
- production DLP location: **eu**
- production DLP project bound to gateway: **true**
- production WORM retention floor: **30 days**
- local pre-audit can issue final assurance verdict: **false**

### Runtime E3/E4 evidence still required

- deploy the exact dedicated GCP legal-shadow gateway environment;
- live four-key HSM/KMS posture and signing proof;
- live exact-project/exact-config EU Sensitive Data Protection proof;
- live runtime-metadata identity / exact-workload / effective-firewall / exact seven-service VPC-SC / restricted-transport proof;
- deliberately apply and verify irreversible WORM retention lock and persist immutable receipts;
- production secrets-manager sourcing + rotation/revocation;
- encrypted backup + successful restore exercise;
- deletion test/receipt;
- incident/kill-switch and credential-revocation drills;
- upload malware scanning evidence;
- current deployed-release SBOM + vulnerability report;
- deployed web/session/security-header checks.

### Legal/privacy E4 evidence still required

- exact provider AVV/DPA;
- BRAO §43e assessment for the exact provider/model/use case;
- complete subprocessor chain;
- transfer assessment/safeguards as applicable;
- VVT / record of processing;
- DPIA/DSFA screening/result;
- EU AI Act use-case classification;
- AI-literacy/training evidence for pilot users.

### Independent E4 / final-verdict evidence still required

- independent penetration test against the exact deployed environment;
- remediation of all critical/high findings;
- independent German legal/privacy review;
- independent evidence-pack verification;
- externally evidenced organisational independence;
- final assurance verdict issued outside the local TrustReady pre-audit process.

## Gate decision

| Target | Re-audit v10 verdict |
|---|---|
| Repository engineering | **PASS** |
| Known P0/P1 findings through Codex review 5094038228 + internal DLP project/residency finding | **CLOSED + REGRESSION COVERED** |
| Exact-instance production adapter boundary | **PASS AS ENGINEERING PROOF** |
| Strict single request snapshot / scan-send binding | **PASS AS ENGINEERING PROOF** |
| Fixed EU production DLP minimum + protected-project binding | **PASS AS ENGINEERING PROOF** |
| Production WORM 30-day minimum | **PASS AS ENGINEERING PROOF** |
| Restricted same-socket network / exact workload / VPC-SC boundary | **PASS AS ENGINEERING PROOF** |
| Production action execution | **PHYSICALLY BLOCKED** |
| Synthetic/public-data shadow | **PASS** |
| Pre-audit / evidence-room readiness | **PASS** |
| Real mandate-data external-AI shadow | **NOT READY — E3/E4 + EXTERNAL VERDICT MISSING** |
| Autonomous mail/beA/case writes | **BLOCKED / OUT OF SCOPE** |
| Independent C5/AIC4/ISO assurance claim | **NOT ASSURED** |

## Product conclusion

TrustReady now treats the **adapter instance, data representation, cloud project, DLP policy, network path, evidence store and final assurance decision** as explicit trust boundaries rather than configuration claims.

Promotion remains fail-closed:

`PRE-AUDIT READY` → exact dedicated live deployment → cryptographically attributable E3 runtime evidence → authorised legal/privacy E4 evidence → independent pentest/review/evidence verification + organisational-independence proof → **external final verdict** → `REAL MANDATE SHADOW READY`.

Until those external evidence classes and the external verdict exist, real mandate-data external-AI use remains blocked regardless of green CI, dogfood or repository engineering quality.
