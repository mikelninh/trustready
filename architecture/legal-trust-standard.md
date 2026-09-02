# TrustReady Legal Trust Standard

Status: draft architecture target for German/EU law firms. This is a technical and evidence standard, not a certification or legal opinion.

## Goal

Make AI-assisted legal workflows deployable with the strongest practical protection for client secrets, personal data and professional obligations, while producing evidence that can be inspected by a law firm, DPO, auditor, insurer or regulator.

The standard is designed around four invariants:

1. No unapproved external disclosure of mandate data.
2. Least data, least privilege, least retention.
3. No irreversible external action without explicit authorised approval unless a separately approved policy exists.
4. Every security-relevant decision produces tamper-evident evidence.

## Regulatory control map

Minimum mapping for Germany/EU:

- BRAO §43a: attorney confidentiality.
- BRAO §43e: use of service providers, careful selection, confidentiality commitments, subcontractor controls, foreign-service safeguards.
- StGB §203: protection of entrusted secrets.
- GDPR: Art. 5, 25, 28, 30, 32, 33/34, 35, 44 ff.
- EU AI Act: applicable provider/deployer duties, including AI literacy and use-case-specific obligations.
- BSI-aligned cloud/AI controls: C5 and AIC4 as control-reference frameworks where applicable.

## Reference architecture

```text
USER / LAWYER
    |
    v
IDENTITY + DEVICE TRUST
    |  MFA / SSO / session policy
    v
LEGAL TRUST GATEWAY
    |- tenant isolation
    |- matter-level authorisation
    |- data classification
    |- purpose/necessity check
    |- DLP / secret detection
    |- pseudonymisation/redaction
    |- provider allow-list
    |- retention policy
    |- action policy
    |- human-approval gate
    |
    +----> INTERNAL DATA VAULT
    |       |- mail
    |       |- documents
    |       |- matter metadata
    |       |- embeddings/indexes
    |       `- encrypted backups
    |
    +----> APPROVED AI/TOOLS
    |       `- only policy-approved minimum payload
    |
    +----> ACTION GATEWAY
    |       |- draft only by default
    |       |- explicit lawyer approval
    |       `- outbound mail/beA/write actions
    |
    `----> EVIDENCE VAULT
            |- policy decision
            |- actor + purpose
            |- data classes disclosed
            |- provider/model/version
            |- approval/rejection
            |- hashes, timestamps, deletion proof
            `- incident/security events
```

## Data zones

### Zone 0 — Public
Public legal sources and non-confidential data.

### Zone 1 — Internal
Operational information not tied to a mandate.

### Zone 2 — Personal
Personal data subject to GDPR.

### Zone 3 — Mandate confidential
All mandate information protected by attorney confidentiality, including the existence of a mandate where applicable.

### Zone 4 — Restricted mandate secret
Highly sensitive categories, criminal matters, health data, credentials, privileged strategy, identity documents, financial credentials or other specially designated material.

Default rule: Zone 3/4 cannot leave the controlled tenant boundary unless an explicit provider policy, necessity check and legal/vendor approval permit it.

## Provider policy

Every external processor/tool must have a machine-readable provider passport:

- legal entity
- processing role
- service purpose
- data categories permitted
- regions/data residency
- subprocessors
- AVV/DPA status
- §43e confidentiality terms status
- third-country transfer mechanism
- training use: prohibited/allowed
- retention duration
- administrative access conditions
- encryption controls
- deletion mechanism
- independent assurance reports
- incident obligations
- approved use cases
- expiry/review date

No valid passport = no mandate-data egress.

## Cryptographic baseline

- TLS 1.2+ in transit; prefer TLS 1.3.
- Strong encryption at rest.
- Per-tenant keys; prefer customer-specific envelope encryption.
- Keys held separately from application data.
- Managed KMS/HSM-backed key protection for production.
- Secrets only in a secrets manager; never source code or logs.
- Key rotation and emergency revocation procedures.
- Encrypted, tested backups with explicit retention.

## Identity and access

- MFA required for privileged and lawyer accounts.
- RBAC plus matter-level ABAC.
- Deny-by-default access.
- Short-lived sessions/tokens.
- Service accounts scoped to one purpose.
- Joiner/mover/leaver lifecycle.
- Privileged access separately logged.
- Periodic access review.

## AI rules

- No consumer AI accounts for mandate data.
- No training on customer content unless separately and explicitly authorised; production default is prohibited.
- Zero/minimum provider retention where technically available.
- Prompt/content logging disabled or minimised.
- Retrieval restricted to authorised matters.
- Model output is untrusted until validated.
- Citations/provenance required for factual legal research where supported.
- No autonomous external communication or irreversible case-management change by default.
- High-impact functions require human review and explicit action approval.

## Logging and evidence

Never log raw secrets by default.

Log:

- event type
- actor/service identity
- tenant + matter pseudonymous identifier
- policy version
- decision and reason
- provider/model/tool version
- input/output hashes where useful
- approval identity/time
- data classes involved
- retention/deletion event

Security logs must be append-only/tamper-evident and access-controlled.

## Mandatory kill switches

- Disable all external AI egress.
- Disable one provider/model.
- Disable one tenant.
- Disable outbound actions.
- Revoke integration credentials.
- Freeze evidence logs for incident handling.

## Deployment profiles

### SOVEREIGN
Private/on-prem or EU-controlled infrastructure; local/private model inference where practical; strongest default for highly sensitive firms.

### EU-PRIVATE
EU-region cloud with approved processors and strict provider passports; private networking and customer isolation.

### GATEWAY
Approved external AI providers may be used only through the Trust Gateway with field-level minimisation/redaction and explicit policy.

A law firm can prohibit the GATEWAY profile entirely.

## Definition of production-ready

A release handling real mandate data is blocked unless:

- threat model is current
- data-flow map is current
- provider passports are valid
- access model passes tests
- encryption/secrets controls pass
- DLP/egress tests pass
- no-secret logging tests pass
- backup/restore test is current
- incident drill is current
- VVT/control map is current
- DSFA/DPIA screening is completed
- human approval controls pass
- deletion test passes
- dependency/SAST/security scans pass
- evidence pack can be generated

No single green score overrides a failed mandatory control.
