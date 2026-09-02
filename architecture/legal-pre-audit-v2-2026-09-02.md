# TrustReady Legal — External-Style Re-Audit v6

Date: 2026-09-02
Scope: PR #14 (`legal-trust-layer`) at verified security head `a0bdc47c1b04620091aa9606479e18c3a45b4db2` before this documentation commit.
Auditor stance: adversarial pre-audit / readiness assessment. This is not independent assurance, certification, a legal opinion, a C5 attestation or an AIC4 attestation.

## Executive opinion

**Engineering opinion: PASS.**

**Real mandate shadow opinion: NOT READY — signed live operating, legal/privacy and external independent evidence still missing.**

The five P1 findings from Codex review `5092840841` of the prior head are now closed and regression-covered:

1. final full Legal Egress authorization is synchronous and is the last gate before request submission; async clock/auth gates fail closed;
2. network qualification derives the executing workload identity from the local GCE metadata server and cross-checks project, instance ID/name, zone, VPC, subnet, NIC and service account against Compute API evidence;
3. `vpcAccessibleServices` is mandatory and must explicitly allow only `RESTRICTED-SERVICES`;
4. missing or malformed `firewallPolicys` / effective-firewall collections fail closed;
5. local TrustReady pre-audit can never self-assert `independently_assured` or `real_mandate_shadow_ready`; even complete local E4 evidence can only become a candidate for a final external verdict.

Verified engineering evidence on security head `a0bdc47...`:

- full repository tests: **106/106 PASS**, 0 failures;
- selected legal/security audit suite: **86/86 PASS**, 0 failures;
- scanner benchmark: **30 labelled cases**, verified precision 1.0, verified recall 1.0, false-verified rate 0, exact-status accuracy 1.0 and provenance completeness 1.0;
- GitHub CI run **#163: SUCCESS**;
- dogfood run **#136: SUCCESS**;
- `npm run audit:legal`: **SUCCESS**;
- audit schema: `trustready-legal-preaudit-v6`;
- `regression_findings_closed: true`;
- `missing_regressions: []`;
- `production_actions_physically_blocked: true`;
- `pre_audit_ready: true`;
- `candidate_for_external_assurance: false` without E3/E4 evidence;
- `external_final_verdict_required: true`;
- `real_mandate_shadow_ready: false`;
- `independently_assured: false`.

## Latest P1 closures

### AUD-P1-23 — authorization could become stale after the final clock read — CLOSED
The critical send section is now synchronous. It performs the final clock read, validates transport freshness/socket state, executes the full authorization callback synchronously, constructs the request and calls `req.end` without an awaited or promise boundary. Async clocks and async authorization callbacks are denied before any provider request. A regression asserts the order `clock → authorize → https_request → req_end`.

### AUD-P1-24 — posture could prove a hardened decoy instead of the executing gateway — CLOSED FOR THE DEDICATED GCE PILOT PROFILE
A dedicated private GCE gateway is now part of the Terraform reference deployment. Runtime qualification obtains project, instance name, instance ID, zone, network, subnet and service-account identity from `169.254.169.254` using `Metadata-Flavor: Google`, then cross-checks them against Compute API workload evidence. Caller-supplied instance names/zones no longer select the qualifying workload. Production construction of the runtime identity provider rejects custom fetch injection.

### AUD-P1-25 — missing VPC accessible-services restriction could pass — CLOSED
`status.vpcAccessibleServices` is mandatory. Qualification requires `enableRestriction === true` and the exact single `RESTRICTED-SERVICES` allow value. Absence, malformed data or a broader allowlist fails closed.

### AUD-P1-26 — malformed effective firewall policy collection could become an empty safe set — CLOSED
Every effective-firewall view must contain array-shaped `firewalls` and `firewallPolicys`; every policy must contain an array-shaped `rules` collection. Missing or malformed structures are unknown security state and return NOT READY rather than being normalized to empty arrays.

### AUD-P1-27 — three distinct keys did not prove organisational independence — CLOSED BY MOVING THE FINAL VERDICT OUTSIDE THE LOCAL TRUST BOUNDARY
Independent evidence now explicitly requires an `organizational_independence` E4 claim in addition to independent pentest, legal/privacy review and evidence verification. More importantly, the local pre-audit cannot issue the final independent verdict at all: `real_mandate_shadow_ready` and `independently_assured` are hard false locally. A complete package can only be marked `candidate_for_external_assurance`, after which an external independent process must issue the final verdict.

## Dedicated mandate-shadow engineering path

1. verify root-pinned identity, fresh matter authorization and current provider policy;
2. require exact release and deployment-pinned DLP configuration;
3. collect local GCE runtime identity from the executing gateway via the metadata server;
4. cross-check exact instance ID/name, service account, zone, VPC, subnet and NIC against Compute API evidence;
5. require strict effective firewall response shapes, deny unsafe policy layers and prove IPv4-only restricted-VIP egress;
6. require enforced VPC Service Controls plus explicit `RESTRICTED-SERVICES` accessible-services restriction;
7. scan exact mandate payload and sign DLP evidence with its dedicated HSM key;
8. construct the fixed proposal-only Vertex request;
9. prepare and HSM-attest the exact target URL, request bytes and actual restricted-VIP TLS socket;
10. obtain the provider credential;
11. synchronously re-read final time and execute the complete Legal Egress authorization as the last gate;
12. with no async boundary, submit the exact prepared bytes over the one-shot attested socket;
13. validate the response as a non-executable proposal;
14. sign and commit the verified Evidence Bundle to WORM storage;
15. only then may the engineering pipeline return a `CANDIDATE` result.

This is **engineering proof**. It is not proof that a real deployed Bao environment currently operates this way.

## Automated audit gate v6

`npm run audit:legal` is a CI release gate and includes the five new Codex findings as named mandatory regressions. The audit intentionally distinguishes repository engineering from externally observable readiness.

Even if future supplied evidence makes all local evidence classes complete, this process cannot locally emit `REAL MANDATE SHADOW READY` or `INDEPENDENTLY ASSURED`. The final assurance verdict is an external trust boundary.

### Runtime E3/E4 evidence still required
- deploy the exact dedicated GCP gateway environment;
- live four-key HSM/KMS posture and signing proof;
- live exact-config Sensitive Data Protection proof;
- live runtime-metadata identity / exact-workload / effective-firewall / VPC-SC / restricted-transport proof;
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

| Target | Re-audit v6 verdict |
|---|---|
| Repository engineering | **PASS** |
| Known P0/P1 engineering findings through Codex review 5092840841 | **CLOSED + REGRESSION COVERED** |
| Final synchronous send authorization | **PASS AS ENGINEERING PROOF** |
| Runtime-bound workload identity | **PASS AS ENGINEERING PROOF** |
| Effective firewall / VPC accessible-services fail-closed boundary | **PASS AS ENGINEERING PROOF** |
| Local false-assurance prevention | **PASS** |
| Production action execution | **PHYSICALLY BLOCKED** |
| Synthetic/public-data shadow | **PASS** |
| Pre-audit / evidence-room readiness | **PASS** |
| Real mandate-data external-AI shadow | **NOT READY — E3/E4 + EXTERNAL VERDICT MISSING** |
| Autonomous mail/beA/case writes | **BLOCKED / OUT OF SCOPE** |
| Independent C5/AIC4/ISO assurance claim | **NOT ASSURED** |

## Product conclusion

TrustReady now treats the final assurance decision itself as a security boundary. A local operator cannot promote the system to independent assurance merely by supplying keys and evidence files.

Promotion remains fail-closed:

`PRE-AUDIT READY` → exact dedicated deployment → cryptographically attributable E3 runtime evidence → authorised legal/privacy E4 evidence → independent pentest/review/evidence verification + organisational-independence proof → **external final verdict** → `REAL MANDATE SHADOW READY`.

Until those external evidence classes and the external verdict exist, real mandate-data external-AI use remains blocked regardless of green CI, dogfood or repository engineering quality.
