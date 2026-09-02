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
   - identity/MFA posture, including every lawyer or other human account with mandate access
   - RBAC/ABAC policy version
   - egress allow-list
   - runtime/config evidence that production secrets are sourced from an approved secrets manager
   - repository/log secret scans
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

## Authenticated manifest

Each export contains a canonical machine-readable `manifest.json` and a detached signature. The manifest itself does not contain a self-referential hash. Every exported artifact is represented by a cryptographic digest; the canonical manifest bytes are signed with a dedicated evidence-signing key held separately from the application data store.

```json
{
  "schema": "trustready-legal-evidence-manifest-v1",
  "tenant": "pseudonymous-tenant-id",
  "generated_at": "ISO-8601",
  "release": "git-sha-or-version",
  "policy_version": "legal-policy-v1",
  "controls_total": 46,
  "controls_pass": 46,
  "controls_fail": 0,
  "mandatory_failures": [],
  "deployment_profile": "SOVEREIGN|EU-PRIVATE|GATEWAY",
  "artifacts": [
    {"path": "controls.json", "sha256": "..."},
    {"path": "provider-register.json", "sha256": "..."}
  ],
  "signer": {
    "algorithm": "Ed25519",
    "key_id": "evidence-signing-key-2026-01"
  }
}
```

The detached `manifest.sig` signs the canonical `manifest.json` bytes. An auditor must be able to verify the signature with a separately distributed/trusted public key and verify every artifact digest. Rotated/revoked signing keys remain traceable by key ID and validity interval.

A raw SHA-256 value alone is not accepted as provenance evidence because an attacker able to modify the bundle could recompute it.

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
- Was the exported evidence bundle altered after it was signed?

If TrustReady cannot produce evidence for a mandatory claim, the claim must not appear as PASS.
