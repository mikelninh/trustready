# TrustReady Legal — External-Style Re-Audit v11

Date: 2026-09-02
Scope: PR #14 (`legal-trust-layer`) at verified security head `2696dda7643e79861a7997abbafa5fe270c6cd37` before this documentation commit.
Auditor stance: adversarial pre-audit / readiness assessment. This is not independent assurance, certification, a legal opinion, a C5 attestation or an AIC4 attestation.

## Executive opinion

**Engineering opinion: PASS.**

**Real mandate shadow opinion: NOT READY — cryptographically attributable live operating evidence, authorised legal/privacy evidence and an external independent assurance verdict are still missing.**

This hardening loop closes the delayed Codex P1 findings from review `5094888004` that remained applicable after v10, while preserving all earlier fail-closed controls. The new mandatory regressions cover signed-envelope TOCTOU/Proxy attacks, caller-controlled production time, verified provider routing, and DLP project/location configuration identity.

Verified engineering evidence on exact security head `2696dda...`:

- full repository tests: **118/118 PASS**, 0 failures;
- selected legal/security audit suite: **98/98 PASS**, 0 failures;
- scanner benchmark: **30 labelled cases**, verified precision 1.0, verified recall 1.0, false-verified rate 0, exact-status accuracy 1.0 and provenance completeness 1.0;
- GitHub CI run **#217: SUCCESS**;
- dogfood run **#189: SUCCESS**;
- `npm run audit:legal`: **SUCCESS**;
- audit schema: `trustready-legal-preaudit-v11`;
- `regression_findings_closed: true`;
- `missing_regressions: []`;
- `production_actions_physically_blocked: true`;
- `signed_envelope_snapshot_required: true`;
- `production_time_internally_controlled: true`;
- `provider_passport_verified_before_routing: true`;
- `production_dlp_config_fingerprint_bound_to_project_location: true`;
- `pre_audit_ready: true`;
- `candidate_for_external_assurance: false` without E3/E4 evidence;
- `external_final_verdict_required: true`;
- `real_mandate_shadow_ready: false`;
- `independently_assured: false`.

## Latest trust-boundary closures

### AUD-P1-38 — signed envelope bodies could change after signature verification — CLOSED
Signed envelopes are no longer verified against a caller-owned live object and then returned by reference. TrustReady now creates one strict immutable JSON snapshot of the envelope before signature verification and returns only that verified snapshot.

The signed-envelope snapshot rejects:

- Proxy-wrapped values;
- getters/accessors and non-enumerable fields;
- functions and unsupported non-JSON values;
- symbols;
- custom object/array prototypes;
- sparse or malformed arrays;
- cycles;
- non-finite numbers;
- excessive nesting or node counts.

Signed bodies produced by TrustReady are also deep-frozen before signing. A caller cannot expose low-privilege values during verification and then swap in MFA, matter permissions, provider policy, evidence claims or other higher-privilege values afterward.

### AUD-P1-39 — production freshness could use caller-controlled historical time — CLOSED
`runGcpMandateShadowPipeline` no longer accepts caller-controlled `now` or `clock`. Supplying either causes `CALLER_TIME_DENIED` before any trust decision or external security I/O.

Production time is obtained from an internally captured clock path. Identity expiry, matter-authorisation freshness, provider validity, HSM/DLP/network attestations, socket preparation expiry, final synchronous pre-send authorisation and evidence timestamps therefore cannot be backdated by the pipeline caller.

### AUD-P1-40 — DLP project/location were not fully part of configuration identity — CLOSED
Production DLP remains fixed to the Google Sensitive Data Protection EU location and must execute in the same protected GCP project as the gateway. Audit v11 additionally includes the exact `project_id` and `location` in the deployment-pinned DLP configuration fingerprint.

The signed DLP attestation carries scanner project, location, version and configuration fingerprint. A scanner in another project or in `us`/`global` cannot satisfy the production configuration identity.

### AUD-P1-41 — provider routing could read the signed passport before verification — CLOSED PROACTIVELY
Before selecting network profile, region-specific target URL or use-case routing, the production pipeline verifies the provider passport against rooted trust and the active policy version. Routing uses only the verified immutable passport snapshot. The later full Legal Egress gate independently verifies the same signed provider evidence again at decision time.

## Earlier engineering findings — still closed and regression-covered

- exact private WeakSet membership required for production HSM/DLP/runtime-identity/network/transport/WORM adapters;
- root-pinned offline-signed key trust; self-asserted rooted booleans denied;
- four purpose-separated production Cloud HSM keys for DLP, egress, network and evidence;
- Cloud KMS `EC_SIGN_P256_SHA256` verification semantics aligned with Google KMS;
- strict frozen request snapshot prevents `toJSON`, getter, prototype and scan/send representation divergence;
- fresh identity and matter authorisation bound to tenant/session/matter/operation/resource version;
- provider passport bound to active policy version and exact release;
- URL-safe/unpadded Base64, Unicode/zero-width and recursive DLP evasions fail closed;
- prototype/inherited data-zone bypass blocked;
- production DLP minimum cannot be weakened and remains fixed to EU;
- production DLP project must equal the protected gateway project before mandate-data inspection;
- production WORM minimum cannot be lowered below 30 days;
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
- append-only evidence chain anchored to the trusted latest signed checkpoint;
- verified evidence bundle artifacts hashed against actual bytes before immutable commit;
- self-authored `verified:true` evidence cannot promote readiness;
- runtime/security, legal/privacy and independent assurance use separate trust purposes/anchors;
- local TrustReady pre-audit can never self-assert `independently_assured` or `real_mandate_shadow_ready`;
- production actions remain physically disabled (`PRODUCTION_ACTIONS_DISABLED`); shadow returns `SHADOW_LOCK`.

## Dedicated mandate-shadow engineering path

1. require a production runtime state and internally verified rooted key trust;
2. reject caller-supplied production time and obtain an internal production timestamp;
3. require exact production HSM/DLP/network/transport/WORM adapter instances;
4. require DLP EU location and exact DLP project = protected gateway project before mandate-data inspection;
5. normalise the entire request to one strict frozen JSON snapshot;
6. verify the provider passport before routing and use only its immutable verified snapshot;
7. verify the active release, policy, approved target and project/location-bound DLP configuration;
8. verify four distinct Cloud HSM key postures;
9. DLP-scan the exact frozen mandate payload and HSM-sign its exact fingerprint/project/location/config evidence;
10. collect local GCE runtime identity and cross-check exact workload, VPC, subnet, NIC and service account;
11. validate global/regional/workload effective-firewall views and exact VPC-SC posture;
12. HSM-sign release-bound egress-enforcement evidence;
13. build the fixed proposal-only Vertex request from the same frozen payload;
14. prepare and HSM-attest the exact approved target URL, exact request bytes and actual restricted-VIP TLS socket;
15. execute deterministic Legal Egress authorisation using verified immutable signed-envelope snapshots;
16. obtain the provider credential;
17. synchronously read internally controlled fresh time and execute the complete Legal Egress authorisation as the final gate;
18. with no async boundary, send the exact prepared bytes over the one-shot attested socket;
19. validate the response as a non-executable proposal;
20. build, HSM-sign and verify the evidence manifest against actual artifact bytes;
21. commit artifacts immutably to the locked WORM namespace, with the signed manifest written last as the commit marker;
22. only then may the engineering pipeline return `CANDIDATE`.

This is **engineering proof**. It does not prove that a live Bao deployment currently satisfies these controls.

## Automated audit gate v11

`npm run audit:legal` is a CI release gate. It requires all named P0/P1 regressions above and refuses to turn repository engineering into operating, legal or independent readiness.

Audit v11 reports:

- Engineering: **PASS**
- selected legal/security tests: **98/98 PASS**
- production actions physically blocked: **true**
- exact-instance adapter trust required: **true**
- strict request snapshot required: **true**
- signed-envelope snapshot required: **true**
- production time internally controlled: **true**
- provider passport verified before routing: **true**
- production DLP minimum fixed: **true**
- production DLP location: **eu**
- production DLP project bound to gateway: **true**
- DLP configuration fingerprint bound to project/location: **true**
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

| Target | Re-audit v11 verdict |
|---|---|
| Repository engineering | **PASS** |
| Known P0/P1 findings through delayed Codex review 5094888004 | **CLOSED + REGRESSION COVERED** |
| Signed-envelope snapshot / Proxy / post-verification mutation boundary | **PASS AS ENGINEERING PROOF** |
| Internally controlled production freshness clock | **PASS AS ENGINEERING PROOF** |
| Verified provider-passport routing | **PASS AS ENGINEERING PROOF** |
| Exact-instance production adapter boundary | **PASS AS ENGINEERING PROOF** |
| Strict single request snapshot / scan-send binding | **PASS AS ENGINEERING PROOF** |
| Fixed EU production DLP minimum + protected-project/location fingerprint binding | **PASS AS ENGINEERING PROOF** |
| Production WORM 30-day minimum | **PASS AS ENGINEERING PROOF** |
| Restricted same-socket network / exact workload / VPC-SC boundary | **PASS AS ENGINEERING PROOF** |
| Production action execution | **PHYSICALLY BLOCKED** |
| Synthetic/public-data shadow | **PASS** |
| Pre-audit / evidence-room readiness | **PASS** |
| Real mandate-data external-AI shadow | **NOT READY — E3/E4 + EXTERNAL VERDICT MISSING** |
| Autonomous mail/beA/case writes | **BLOCKED / OUT OF SCOPE** |
| Independent C5/AIC4/ISO assurance claim | **NOT ASSURED** |

## Product conclusion

TrustReady now treats **signed-object identity, time, adapter instance, data representation, provider policy, cloud project/location, network path, evidence store and final assurance decision** as explicit trust boundaries rather than caller-controlled configuration claims.

Promotion remains fail-closed:

`PRE-AUDIT READY` → exact dedicated live deployment → cryptographically attributable E3 runtime evidence → authorised legal/privacy E4 evidence → independent pentest/review/evidence verification + organisational-independence proof → **external final verdict** → `REAL MANDATE SHADOW READY`.

Until those external evidence classes and the external verdict exist, real mandate-data external-AI use remains blocked regardless of green CI, dogfood or repository engineering quality.
