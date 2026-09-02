# TrustReady Legal — External-Style Re-Audit v7

Date: 2026-09-02
Scope: PR #14 (`legal-trust-layer`) at verified security head `7ec9760e06666ad24e28db24e1c8709cf4cbd99c` before this documentation commit.
Auditor stance: adversarial pre-audit / readiness assessment. This is not independent assurance, certification, a legal opinion, a C5 attestation or an AIC4 attestation.

## Executive opinion

**Engineering opinion: PASS.**

**Real mandate shadow opinion: NOT READY — signed live operating, legal/privacy and external independent evidence still missing.**

The five P1 findings from Codex review `5093172274` of exact prior head `8c3f75373b071d79bd44c3977c4f6413f1704e74` are now closed and regression-covered:

1. production restricted transport no longer accepts caller-supplied DNS/TLS/HTTPS implementations; Node implementations are captured at module initialisation and custom transport dependencies exist only behind an explicit test-only constructor that is rejected outside `NODE_ENV=test`;
2. GCE runtime identity uses a module-captured fetch implementation, so replacing `globalThis.fetch` after module load cannot become the trusted metadata path;
3. every classic and policy effective-firewall rule is schema-validated before posture evaluation; malformed individual rules fail closed;
4. malformed `ingressPolicies` or `egressPolicies` fields fail closed and non-empty VPC-SC escape policies remain denied;
5. the service perimeter `restrictedServices` set must exactly equal the audited seven-service runtime/qualification allowlist; missing, duplicate or additional APIs fail closed.

Verified engineering evidence on security head `7ec9760e...`:

- full repository tests: **110/110 PASS**, 0 failures;
- selected legal/security audit suite: **90/90 PASS**, 0 failures;
- scanner benchmark: **30 labelled cases**, verified precision 1.0, verified recall 1.0, false-verified rate 0, exact-status accuracy 1.0 and provenance completeness 1.0;
- GitHub CI run **#176: SUCCESS**;
- dogfood run **#149: SUCCESS**;
- `npm run audit:legal`: **SUCCESS**;
- audit schema: `trustready-legal-preaudit-v7`;
- `regression_findings_closed: true`;
- `missing_regressions: []`;
- `production_actions_physically_blocked: true`;
- `pre_audit_ready: true`;
- `candidate_for_external_assurance: false` without E3/E4 evidence;
- `external_final_verdict_required: true`;
- `real_mandate_shadow_ready: false`;
- `independently_assured: false`.

## Latest P1 closures

### AUD-P1-28 — production transport dependencies could be substituted — CLOSED
The production restricted-Google-API transport captures the native Node DNS resolver, TLS connector, HTTPS request implementation and HTTPS Agent at module initialisation. The production constructor exposes no dependency-injection surface for these functions. A separate `createRestrictedGoogleApiTransportForTest` exists only for deterministic tests and refuses construction outside `NODE_ENV=test`. Regression coverage proves caller-supplied production transport functions cannot become the trusted send path.

### AUD-P1-29 — runtime metadata fetch could be monkeypatched after startup — CLOSED FOR THE DEDICATED GCE PILOT PROFILE
The runtime-identity module captures its fetch implementation once at module initialisation and uses that pinned reference as the default metadata client. A later replacement of `globalThis.fetch` cannot become the trusted metadata source. Explicit alternative fetch implementations remain test-only. The metadata result is still cross-checked against exact Compute API instance ID/name, zone, VPC, subnet, NIC and service-account evidence.

### AUD-P1-30 — malformed individual effective-firewall rules could be ignored — CLOSED
All classic effective firewall rules and all firewall-policy rules are individually schema-validated before security predicates execute. Invalid direction/action/priority, malformed selector collections, invalid layer-4 configurations or malformed allow/deny structures return NOT READY. The allow/deny matchers are total and cannot crash or silently discard the legitimate opposite rule type.

### AUD-P1-31 — malformed VPC-SC ingress/egress policy state could behave as absent — CLOSED
If `status.ingressPolicies` or `status.egressPolicies` is present, it must be an array. Any other type is unknown security state and fails closed. Non-empty arrays remain rejected for the first mandate-shadow profile because no escape policies are approved.

### AUD-P1-32 — extra restricted Google APIs enlarged the exfiltration surface — CLOSED
The VPC-SC `restrictedServices` collection must exactly equal the deployment-approved seven-service set used by the runtime and qualification path:

- `accesscontextmanager.googleapis.com`
- `aiplatform.googleapis.com`
- `cloudkms.googleapis.com`
- `cloudresourcemanager.googleapis.com`
- `compute.googleapis.com`
- `dlp.googleapis.com`
- `storage.googleapis.com`

Missing services, duplicate entries or additional services such as BigQuery fail closed. Terraform encodes the same exact runtime perimeter set; additional APIs used only for provisioning are not automatically added to the mandate-shadow runtime perimeter.

## Dedicated mandate-shadow engineering path

1. verify root-pinned identity, fresh matter authorization and current provider policy;
2. require exact release and deployment-pinned DLP configuration;
3. collect local GCE runtime identity from the executing gateway using the module-pinned metadata client;
4. cross-check exact instance ID/name, service account, zone, VPC, subnet and NIC against Compute API evidence;
5. require individually valid effective-firewall rules across global, regional and exact-workload views;
6. prove IPv4-only deny-by-default egress with only restricted Google API VIP TCP/443 allowed;
7. require enforced VPC Service Controls, no ingress/egress escape policies, explicit `RESTRICTED-SERVICES` accessible-services restriction and the exact seven-service audited perimeter allowlist;
8. scan the exact mandate payload and sign DLP evidence with its dedicated HSM key;
9. construct the fixed proposal-only Vertex request;
10. prepare and HSM-attest the exact target URL, request bytes and actual restricted-VIP TLS socket using production-pinned Node networking implementations;
11. obtain the provider credential;
12. synchronously re-read final time and execute complete Legal Egress authorization as the last gate;
13. with no async boundary, submit the exact prepared bytes over the one-shot attested socket;
14. validate the response as a non-executable proposal;
15. sign and commit the verified Evidence Bundle to WORM storage;
16. only then may the engineering pipeline return a `CANDIDATE` result.

This is **engineering proof**. It is not proof that a real deployed Bao environment currently operates this way.

## Automated audit gate v7

`npm run audit:legal` is a CI release gate and requires the latest Codex findings as named mandatory regressions. Audit v7 reports **90/90** selected legal/security tests passing and refuses to promote repository engineering into operating or legal readiness.

Even if future supplied evidence makes all local evidence classes complete, this local process cannot emit `REAL MANDATE SHADOW READY` or `INDEPENDENTLY ASSURED`. The final assurance verdict remains an external trust boundary.

### Runtime E3/E4 evidence still required
- deploy the exact dedicated GCP gateway environment;
- live four-key HSM/KMS posture and signing proof;
- live exact-config Sensitive Data Protection proof;
- live module-pinned runtime-metadata identity / exact-workload / effective-firewall / exact seven-service VPC-SC / restricted-transport proof;
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

### Independent E4 / final-verdict evidence still required
- independent penetration test against the exact deployment;
- remediation of all critical/high findings;
- independent German legal/privacy review;
- independent evidence-pack verification;
- externally evidenced organisational independence;
- final assurance verdict issued outside the local TrustReady pre-audit process.

## Gate decision

| Target | Re-audit v7 verdict |
|---|---|
| Repository engineering | **PASS** |
| Known P0/P1 engineering findings through Codex review 5093172274 | **CLOSED + REGRESSION COVERED** |
| Production transport dependency boundary | **PASS AS ENGINEERING PROOF** |
| Module-pinned GCE runtime identity boundary | **PASS AS ENGINEERING PROOF** |
| Individual effective-firewall schema / fail-closed boundary | **PASS AS ENGINEERING PROOF** |
| VPC-SC escape-policy shape boundary | **PASS AS ENGINEERING PROOF** |
| Exact restricted-service perimeter | **PASS AS ENGINEERING PROOF** |
| Production action execution | **PHYSICALLY BLOCKED** |
| Synthetic/public-data shadow | **PASS** |
| Pre-audit / evidence-room readiness | **PASS** |
| Real mandate-data external-AI shadow | **NOT READY — E3/E4 + EXTERNAL VERDICT MISSING** |
| Autonomous mail/beA/case writes | **BLOCKED / OUT OF SCOPE** |
| Independent C5/AIC4/ISO assurance claim | **NOT ASSURED** |

## Product conclusion

The engineering boundary is materially stronger after this loop: production transport dependencies, runtime metadata identity and the effective network/perimeter evidence are no longer allowed to become caller-defined or ambiguously broader than the audited deployment.

Promotion remains fail-closed:

`PRE-AUDIT READY` → exact dedicated deployment → cryptographically attributable E3 runtime evidence → authorised legal/privacy E4 evidence → independent pentest/review/evidence verification + organisational-independence proof → **external final verdict** → `REAL MANDATE SHADOW READY`.

Until those external evidence classes and the external verdict exist, real mandate-data external-AI use remains blocked regardless of green CI, dogfood or repository engineering quality.
