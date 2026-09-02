# Legal Trust Control Matrix

This matrix is the implementation checklist for law-firm deployments. It maps each requirement to evidence. A control can only be marked PASS when the stated evidence exists.

| ID | Control | Default | Evidence |
|---|---|---:|---|
| LT-001 | Mandate data classified before processing | BLOCK | classification event + tests |
| LT-002 | Matter-level authorisation | BLOCK | policy test + access log |
| LT-003 | External egress deny-by-default | BLOCK | egress policy + negative tests |
| LT-004 | Provider passport required | BLOCK | signed/versioned passport |
| LT-005 | DPA/AVV recorded where required | BLOCK | contract register reference |
| LT-006 | §43e confidentiality/service-provider assessment | BLOCK | legal/vendor review record |
| LT-007 | Subprocessor chain recorded | BLOCK | provider passport |
| LT-008 | Third-country transfer assessment | BLOCK | transfer record/safeguards |
| LT-009 | No model training on mandate data by default | BLOCK | contract/config evidence |
| LT-010 | Provider retention minimised | BLOCK | provider config + deletion test |
| LT-011 | Data minimisation before AI call | BLOCK | policy trace + payload diff |
| LT-012 | Pseudonymisation/redaction where feasible | WARN/BLOCK by class | redaction test corpus |
| LT-013 | Encryption in transit | BLOCK | TLS configuration/test |
| LT-014 | Encryption at rest | BLOCK | KMS/storage evidence |
| LT-015 | Tenant-separated keys | BLOCK | key mapping/config |
| LT-016 | Secrets manager; no secrets in repo/logs | BLOCK | secret scans |
| LT-017 | MFA for privileged access | BLOCK | identity configuration |
| LT-018 | Least-privilege RBAC/ABAC | BLOCK | policy + periodic review |
| LT-019 | Raw mandate content excluded from normal logs | BLOCK | log redaction tests |
| LT-020 | Tamper-evident security audit trail | BLOCK | integrity verification |
| LT-021 | Outbound mail/beA/action approval | BLOCK | approval event tests |
| LT-022 | Irreversible case-management writes gated | BLOCK | policy/integration tests |
| LT-023 | Provider/model version recorded | BLOCK | evidence event |
| LT-024 | AI output treated as untrusted | BLOCK | validation/human-review policy |
| LT-025 | Retrieval scoped to authorised matter | BLOCK | cross-matter isolation tests |
| LT-026 | Prompt injection/tool abuse controls | BLOCK | adversarial benchmark |
| LT-027 | Malware/content scanning for uploads | BLOCK | scan result/event |
| LT-028 | Backup encrypted | BLOCK | backup configuration |
| LT-029 | Restore tested | BLOCK | dated restore evidence |
| LT-030 | Retention schedule enforced | BLOCK | retention config + jobs |
| LT-031 | Deletion can be demonstrated | BLOCK | deletion receipt/test |
| LT-032 | Incident kill switch works | BLOCK | drill evidence |
| LT-033 | Credential revocation works | BLOCK | drill evidence |
| LT-034 | Breach response workflow documented | BLOCK | runbook + exercise |
| LT-035 | VVT/record of processing current | BLOCK | generated/exported record |
| LT-036 | DPIA/DSFA screening completed | BLOCK | signed screening/result |
| LT-037 | Data-flow map current | BLOCK | versioned map |
| LT-038 | Purpose and necessity recorded | BLOCK | policy event |
| LT-039 | AI Act use-case classification recorded | BLOCK | classification record |
| LT-040 | AI literacy/training evidence for users | WARN/BLOCK by role | training record |
| LT-041 | Secure SDLC scans pass | BLOCK | CI evidence |
| LT-042 | Dependency/SBOM available | BLOCK | SBOM + vulnerability report |
| LT-043 | Security headers/session controls pass | BLOCK | automated test |
| LT-044 | Independent penetration test current for production service | RELEASE GATE | report/remediation evidence |
| LT-045 | Vendor review expiry enforced | BLOCK | review timestamp |
| LT-046 | Evidence pack export reproducible | BLOCK | signed export manifest |

## Scoring rule

TrustReady may display a score for usability, but legal production readiness is binary for mandatory controls:

- READY: all applicable BLOCK/RELEASE GATE controls pass.
- LIMITED: only explicitly approved low-risk/synthetic/public-data workflows may run.
- NOT READY: mandate-data processing is blocked.

A 99/100 score never overrides one failed confidentiality, authorisation, egress, encryption or approval gate.
