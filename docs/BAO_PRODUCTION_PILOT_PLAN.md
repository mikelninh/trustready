# Bao Golden Pilot — Production Readiness Plan

Goal: reach a real, measurable **read-only / human-approved shadow pilot** without silently promoting synthetic engineering proof into legal or production authority.

## Target user experience

### Client — Vietnamese first

1. Receives invitation link or QR code.
2. Completes second-factor verification.
3. Sees only the assigned matter and a Vietnamese checklist.
4. Uploads missing documents directly into the correct requirement slot.
5. Sees what is received, rejected, missing or still under review.
6. Gets one bundled Vietnamese follow-up instead of fragmented calls/emails.

### Intake team

1. Sees a structured matter dashboard in German/bilingual form.
2. Reviews completeness, formalities, contradictions and source evidence.
3. Resolves or escalates each explicit open item.
4. Marks the matter `READY_FOR_LAWYER` only when complete.

### Bao

1. Sees original evidence + translations + open/resolved issues.
2. Reviews the prepared matter.
3. Approves, requests correction or rejects.
4. During Shadow Pilot, approval ends at `LAWYER_APPROVED_SHADOW_ONLY`.
5. A later separately released mode may allow `approve & send` for narrowly typed actions after a fresh policy check and immutable evidence capture.

---

# Phase A — synthetic production-shaped pilot

**Can be completed before real mandate data.**

Must exist:

- Vietnamese-first client portal.
- German/bilingual staff view.
- Opaque invitation model.
- link/QR is not sufficient authentication.
- second-factor requirement.
- tenant + matter bound session.
- separate client/intake/lawyer roles.
- upload capability scoped to one matter + one document slot.
- MIME + size allowlist.
- quarantine state.
- malware-clean requirement before promotion.
- document SHA-256 provenance.
- intake cannot lawyer-approve.
- lawyer approval stays shadow-only.
- privacy-minimised pilot metrics.
- public demo remains no-egress.

Exit gate:

- all repository tests green,
- explicit client-portal regression suite green,
- no real client data used.

# Phase B — protected live environment

Provision dedicated pilot environment using the existing GCP legal-shadow reference profile.

Required live components:

- dedicated GCP project in intended EU organisation/billing boundary,
- Frankfurt/EU deployment profile,
- private gateway workload,
- restricted Google API path / VPC Service Controls,
- four distinct HSM keys,
- Sensitive Data Protection configuration,
- private protected document storage,
- separate quarantine storage/prefix,
- malware scanning service,
- protected PostgreSQL database or approved equivalent,
- Secrets Manager,
- immutable evidence storage,
- monitoring/alerting/kill switch,
- backups.

Portal-specific live proof:

- staff auth + MFA,
- client invite + second-factor flow,
- Secure/HttpOnly session cookie,
- session revocation,
- tenant/matter authorization,
- upload capability one-time/expiry,
- cross-tenant negative tests,
- quarantine cannot be read as accepted evidence,
- infected upload cannot promote,
- public access prevention,
- encryption/key binding,
- backup restore,
- deletion/retention test.

Exit gate:

`LIVE_ENVIRONMENT_QUALIFIED`, but **not yet real mandate ready**.

# Phase C — legal/privacy approval

Before real mandate data, qualified reviewers must decide the exact deployment is acceptable.

Checklist:

- data-flow inventory + VVT/records of processing,
- controller/processor roles,
- Art. 28 GDPR agreement where applicable,
- subprocessors,
- international transfer assessment where applicable,
- privacy notice in German and understandable Vietnamese,
- purpose limitation/minimisation,
- retention/deletion schedule,
- TOM/security measures,
- DPIA/DSFA decision and completion if required,
- lawyer-confidentiality assessment,
- BRAO §43e service-provider requirements,
- matter-specific consent question where §43e(5) is applicable,
- AI Act classification/literacy obligations as applicable.

Exit gate:

`LEGAL_PRIVACY_APPROVED_BY_QUALIFIED_REVIEWER`.

# Phase D — independent technical assurance

- external web/API penetration test,
- auth/session test,
- IDOR/cross-tenant test,
- upload parser/malware test,
- cloud/IAM/storage review,
- evidence verification,
- remediation of all P0/P1 findings.

Exit gate:

`INDEPENDENT_ASSURANCE_ACCEPTED`.

# Phase E — Bao Shadow Pilot

Duration: 5 real workdays.

Scope:

- preferably one narrow intake workflow first,
- Vietnamese-speaking clients,
- read/upload/review only,
- no autonomous outbound communication,
- no autonomous beA,
- no irreversible case write,
- lawyer remains final authority.

Measure:

- at least 20 work items,
- baseline manual handling time,
- assisted handling time,
- net minutes saved/day,
- number of calls avoided,
- number of follow-up emails avoided,
- first-submission completeness rate,
- matter/document classification accuracy,
- contradiction/formality detection precision,
- Vietnamese client completion rate,
- help requests,
- zero unauthorised external actions.

Target signal:

- ≥30 net minutes saved/day,
- materially less client/staff back-and-forth,
- zero unauthorised external actions,
- Bao/team want to continue.

# Phase F — first paid pilot / design partner

Only after successful Shadow Pilot:

- agree pilot price and support boundary,
- convert Bao or next firms into paid design partners,
- standardise onboarding,
- instrument ROI report,
- build repeatable integrations.

# Phase G — human-approved execution

This is a **separate release**, not an automatic continuation of Shadow Mode.

First candidate actions:

- approved email reply,
- approved client request for missing documents,
- approved internal task update.

Required immediately before execution:

`current identity → current matter authority → exact recipient → exact content hash → current policy → DLP → fresh human approval → immutable pre-send evidence → execute exactly once → post-send evidence`

beA and other higher-risk actions remain later, separately reviewed capabilities.

---

## What can be done without Bao / GCP credentials?

Already buildable in the repository:

- UI and bilingual flows,
- client security kernel,
- authorization state machine,
- database schema,
- infrastructure templates,
- synthetic golden cases,
- CI/security regressions,
- deployment runbooks,
- evidence request pack.

## What requires external access or authority?

Cannot be truthfully completed from repository code alone:

- provisioning Bao's actual approved cloud project,
- configuring his verified client contact channels,
- accepting real mandate data,
- locking irreversible production retention without review,
- legal/privacy sign-off,
- independent pentest/assurance,
- running 5 real workdays of work,
- deciding that Bao wants to pay/continue.

Those are the remaining real-world promotion gates, not missing software features.