# Legal Trust Evidence Pack

Every production tenant must be able to generate an evidence bundle for a chosen date/time and policy version. The bundle is designed to answer the questions a law firm, DPO, insurer, auditor or supervisory authority is likely to ask without exposing unrelated mandate content.

## Evidence bundle

1. System identity
   - product/release version
   - deployment profile
   - tenant identifier
   - policy bundle version

2. Data-flow evidence
   - current data-flow map
   - systems/integrations
   - data classes per flow
   - processing purpose
   - regions/locations

3. Vendor register
   - provider passports
   - subprocessors
   - AVV/DPA references
   - §43e review status
   - transfer safeguards
   - review/expiry date

4. Security controls
   - encryption/KMS posture
   - identity/MFA posture
   - RBAC/ABAC policy version
   - egress allow-list
   - secrets scan
   - dependency/SBOM scan
   - SAST/security scan
   - backup/restore evidence

5. AI controls
   - approved models/providers
   - training/retention configuration
   - AI Act use-case classification
   - human-review policy
   - retrieval isolation tests
   - prompt-injection/adversarial benchmark

6. Operational evidence
   - privileged-access events
   - provider/model calls as metadata/hashes, not raw secrets
   - approval events
   - blocked egress events
   - deletion receipts
   - retention jobs
   - kill-switch/incident drills

7. GDPR documentation
   - processing-record/VVT export
   - DPIA/DSFA screening or assessment reference
   - retention/deletion schedule
   - breach-response runbook
   - data-subject request process where applicable

8. Legal-professional controls
   - confidentiality policy
   - service-provider review
   - employee/contractor confidentiality controls
   - mandate-specific consent flag only where legally required/applicable

9. Assurance
   - penetration-test reference
   - remediation status
   - independent audit/certification references where available
   - BSI C5/AIC4 mapping where applicable
   - ISO 27001 mapping/certificate where available

## Manifest

Each export contains a machine-readable `manifest.json`:

```json
{
  "tenant": "pseudonymous-tenant-id",
  "generated_at": "ISO-8601",
  "release": "git-sha-or-version",
  "policy_version": "legal-policy-v1",
  "controls_total": 46,
  "controls_pass": 46,
  "controls_fail": 0,
  "mandatory_failures": [],
  "deployment_profile": "SOVEREIGN|EU-PRIVATE|GATEWAY",
  "artifacts": [],
  "manifest_hash": "sha256:..."
}
```

## Privacy rule

The evidence pack must prove controls without becoming a second database of client secrets. Raw prompts, emails, documents or privileged legal content are excluded by default. Evidence should rely on metadata, configuration snapshots, hashes, policy decisions and narrowly scoped excerpts only when explicitly needed.

## Auditor experience target

An auditor should be able to answer these questions in minutes:

- What data can leave the firm boundary?
- Which provider can receive it and why?
- On what contractual/legal basis?
- Where is it processed?
- Is it retained or used for training?
- Can one matter access another matter?
- Can the AI send or alter anything without approval?
- Who accessed the system?
- Can the firm disable external AI immediately?
- Can deletion and restore be demonstrated?
- Which exact policy and software version was active at a given time?

If TrustReady cannot produce evidence for a mandatory claim, the claim must not appear as PASS.
