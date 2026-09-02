# TrustReady Legal — External Review Request

## Scope

Review the exact **read-only / proposal-only Shadow Pilot** before any real mandate data is admitted.

The pilot may:
- read from one explicitly authorised source with least privilege;
- propose matter assignment, task/deadline/risk extraction and a draft;
- record privacy-minimised utility/safety metrics;
- require a human lawyer to accept, edit or reject proposals.

The pilot may **not** autonomously:
- send email;
- send beA messages;
- write to a case file;
- create/alter a binding deadline;
- complete tasks or trigger irreversible external actions.

A repository test or self-authored statement is not sufficient authority for real mandate data. The final decision must be issued against the exact deployed environment and contracts.

---

## Reviewer A — German legal / privacy review

Please issue an explicit finding for each item as `PASS`, `FAIL`, `NOT_APPLICABLE`, or `NEEDS_EVIDENCE`, with the evidence inspected and any required remediation.

### Professional secrecy / service-provider use

1. Does the exact provider/service chain satisfy the requirements relevant to anwaltliche Verschwiegenheit under § 43a(2) BRAO?
2. For § 43e BRAO, is access by each service provider limited to what is necessary for the service?
3. Has each relevant service provider been carefully selected and is there a documented termination/revocation path if requirements are no longer met?
4. Is the required service-provider contract in text form and does it contain the confidentiality, necessity and subprocessor obligations required for the exact setup?
5. If any service is performed abroad, is the required comparable protection / transfer analysis documented for the exact service chain?
6. Does the exact use constitute a service directly serving an individual mandate under § 43e(5), and if so what consent is required for this pilot scope?
7. Are § 203 StGB risks and obligations for participating persons/service providers addressed in the exact contractual and operational design?

Official sources:
- https://www.gesetze-im-internet.de/brao/__43e.html
- https://www.gesetze-im-internet.de/brao/BJNR005650959.html
- https://www.gesetze-im-internet.de/stgb/__203.html

### GDPR

8. Identify controller / processor roles for TrustReady, the law firm, model provider and any subprocessors.
9. Does the exact Article 28 processor agreement and subprocessor chain provide sufficient guarantees and instructions?
10. Are Article 32 technical/organisational measures appropriate for the real processing risks?
11. Is the processing purpose, lawful basis, data minimisation, retention/deletion and transfer position documented?
12. Is a VVT / record of processing required and complete for the exact pilot?
13. Is a DPIA/DSFA required? If not, record the screening and reasoning; if yes, complete it before mandate data.

Official source:
- https://eur-lex.europa.eu/legal-content/DE/TXT/?uri=CELEX:32016R0679

### EU AI Act

14. Classify the exact Shadow Pilot use case under Regulation (EU) 2024/1689; do not infer high-risk status merely because it is used by lawyers.
15. Confirm the applicable provider/deployer obligations for this exact use case and date.
16. Confirm an appropriate AI-literacy measure for pilot users under Article 4.

Official source:
- https://eur-lex.europa.eu/eli/reg/2024/1689

### Required legal/privacy verdict

The reviewer should sign a compact attestation containing:
- exact deployment/release identifier;
- exact provider/model and region;
- exact reviewed use case;
- reviewed contract/document versions;
- findings and unresolved blockers;
- expiry/review date;
- reviewer identity and independence/authority;
- explicit statement whether **real mandate data may enter this read-only Shadow Pilot scope**.

---

## Reviewer B — Independent security / penetration review

Review the exact deployed environment, not only Terraform/source code.

Minimum scope:
1. authenticated runtime/workload identity and least privilege;
2. four purpose-separated HSM keys and key-access boundaries;
3. DLP configuration/project/location binding and fail-closed behaviour;
4. effective firewall policy, restricted Google APIs path, DNS/TLS binding and VPC Service Controls;
5. no public/external IP escape path for the gateway workload;
6. evidence bucket identity, immutable generation writes and locked retention policy;
7. secrets sourcing, rotation and revocation;
8. session/MFA/tenant/matter authorization boundaries;
9. action-gateway attempts, replay resistance and production physical action blocks;
10. prompt/tool injection attempts against the proposal-only model boundary;
11. dependency/SBOM and vulnerability findings;
12. malware/file-upload path if uploads are in scope;
13. logging/evidence privacy (no raw mandate database by accident);
14. kill-switch and credential-revocation drill;
15. backup/restore/deletion evidence where applicable;
16. web/session security for any pilot UI exposed to users.

All critical/high findings must be remediated or explicitly accepted by an authorised external decision-maker before mandate-data admission.

---

## Reviewer C — Evidence verification

Independently verify that the evidence pack can support its claims without trusting TrustReady itself:
- verify signer/trust-anchor identity;
- verify signed manifest;
- recompute artifact hashes;
- verify WORM/retention receipts against the real bucket/project;
- verify live observations are fresh and tied to the exact release/environment;
- confirm no lower evidence level self-promotes into external/legal authority;
- confirm missing evidence remains `UNKNOWN` / blocked rather than PASS.

Reference:
- `architecture/legal-evidence-pack.md`
- `scripts/legal-audit-request-pack.mjs`

---

## Final external gate

The real Shadow Pilot may proceed only when the exact environment has:
- live E3 operating evidence;
- authorised E4 legal/privacy evidence;
- independent security/evidence review;
- no unresolved critical/high finding;
- Bao / the pilot law firm explicitly authorises the least-privilege read-only source;
- an external final verdict authorising **this exact Shadow Pilot scope**, not a generic claim that TrustReady is "compliant".

This request is intentionally narrower than a certification or general legal opinion.