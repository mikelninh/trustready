# Legal Trust Threat Model

## Protected assets

- mandate secrets and metadata
- personal/special-category data
- credentials, signing and integration tokens
- legal strategy and privileged work product
- matter indexes/embeddings
- audit/evidence records
- availability and integrity of deadlines/tasks

## Primary threat classes and required tests

### Cross-matter / cross-tenant leakage
Attack: a user, retrieval query or model obtains content from another matter/tenant.
Controls: tenant isolation, matter ABAC, separate indexes/namespaces, query-time enforcement.
Golden test: 100 adversarial cross-matter queries; zero unauthorised content disclosure.

### Prompt injection from documents/email/web content
Attack: malicious content instructs an agent to reveal secrets, call tools or change policy.
Controls: untrusted-content boundary, tool allow-list, policy engine outside model, no model authority to weaken policy.
Golden test: injection corpus cannot trigger forbidden egress/actions.

### Excessive AI disclosure
Attack: whole files/mailboxes sent when only small fields are needed.
Controls: purpose/necessity check, minimisation transform, payload diff, data-class limits.
Golden test: expected minimum payload enforced for each workflow.

### Provider misuse/retention
Attack: external provider retains or trains on mandate content contrary to policy.
Controls: approved provider passport, contract/config checks, retention/training prohibition, egress block on expired review.
Golden test: unapproved/expired provider cannot receive Zone 3/4 data.

### Log leakage
Attack: raw prompts, documents, secrets or credentials appear in logs/telemetry/error traces.
Controls: structured safe logging, field redaction, secret scanners.
Golden test: seeded canary secrets never occur in collected logs.

### Credential compromise
Attack: stolen API/integration token accesses mail, DMS or case system.
Controls: scoped short-lived credentials, vault, rotation, revocation, anomaly alerts.
Golden test: revoked token fails immediately; credentials never appear in repo/logs.

### Autonomous harmful action
Attack: AI sends mail/beA, changes deadlines or writes to case files without authorised review.
Controls: deterministic action gateway, human approval token, transaction scope and expiry.
Golden test: no external/irreversible action succeeds without a valid approval capability.

### Approval confusion
Attack: user approves one draft but system executes another.
Controls: approval binds cryptographic hash of exact payload/action/recipient.
Golden test: mutation after approval invalidates approval.

### Malicious insider / excess privilege
Attack: employee/admin browses matters without need.
Controls: least privilege, matter ABAC, privileged-access logging, periodic reviews, break-glass workflow.
Golden test: unauthorised admin/user reads are blocked and alerted.

### Supply-chain compromise
Attack: vulnerable dependency, CI/CD compromise or poisoned package.
Controls: lockfiles, SBOM, dependency scanning, signed/reviewed builds, protected branches/releases.
Golden test: critical known vulnerability blocks production release.

### Data deletion failure
Attack: deleted matter remains in backups, indexes, caches or provider stores indefinitely.
Controls: deletion orchestration + retention-aware backup strategy + provider deletion receipts.
Golden test: tombstoned canary is absent from active stores/indexes and deletion evidence exists.

### Evidence tampering
Attack: audit records are modified after an incident.
Controls: append-only/tamper-evident evidence chain, hashes, restricted writer identity.
Golden test: record modification is detectable by integrity verification.

### Availability / ransomware
Attack: operational data unavailable when deadline-sensitive work is due.
Controls: encrypted backups, tested restore, recovery objectives, degraded manual mode.
Golden test: restore drill meets documented RTO/RPO target.

## Non-negotiable principle

The LLM is never the security boundary. Authentication, authorisation, egress, approval, retention and provider policy are deterministic controls enforced outside the model.
