const observed_at = '2026-08-31T12:00:00.000Z'

function snapshot(id, files) {
  return {
    subject: { id, name: id },
    repository_url: `https://github.com/trustready-benchmark/${id}`,
    revision: `rev-${id}`,
    observed_at,
    files,
  }
}

function golden(id, control_id, expected_status, files, note) {
  return { id, control_id, expected_status, snapshot: snapshot(id, files), note }
}

export const SCANNER_GOLDEN_CASES = [
  golden('purpose-dedicated', 'TR-GOV-001', 'verified', {
    'README.md': '# Acme Agent\n\nPurpose: prepare support replies for customer-service teams. Intended users are trained support operators. The workflow drafts responses and leaves consequential decisions with people. This repository documents the product boundary and operating workflow.',
  }, 'Substantive README with purpose/users should satisfy E1.'),

  golden('purpose-keyword-trap', 'TR-GOV-001', 'candidate', {
    'CHANGELOG.md': 'Rename purpose flag. Users may see faster builds. No product description lives here.',
  }, 'Keywords in unrelated file must not become verified.'),

  golden('model-inventory-dedicated', 'TR-AI-001', 'verified', {
    'MODEL_VENDOR_INVENTORY.md': '# Model inventory\nProvider: ExampleAI\nModel: reasoning-v3\nVersion: 2026-08\nPurpose: classify support intent\nData: redacted support text\nVendor owner: Platform team',
  }, 'Dedicated technical inventory should satisfy E2.'),

  golden('model-inventory-placeholder', 'TR-AI-001', 'candidate', {
    'MODEL_VENDOR_INVENTORY.md': '# Model inventory\nProvider: TODO fill me\nModel: TODO\nVersion: TBD\nPurpose: placeholder\nData: TODO',
  }, 'A generated-but-unfilled remediation template must never self-promote.'),

  golden('model-readme-mention', 'TR-AI-001', 'candidate', {
    'README.md': 'This LLM app can use OpenAI or another provider. Model choice may change.',
  }, 'Vendor/model mentions alone are discovery only.'),

  golden('limitations-explicit', 'TR-AI-004', 'verified', {
    'ASSURANCE.md': '# Assurance\nLimitations: synthetic evaluations are not production accuracy claims. The system does not make final medical, legal, employment, credit or public-benefit decisions. Non-goal: autonomous consequential action.',
  }, 'Explicit limitations artifact should satisfy E1.'),

  golden('limitations-changelog-trap', 'TR-AI-004', 'not_observed', {
    'CHANGELOG.md': 'Fix limitation in test runner. This does not change API output.',
  }, 'Incidental language outside discovery/promotion rules must remain not observed.'),

  golden('data-flow-dedicated', 'TR-DATA-001', 'verified', {
    'docs/DATA_FLOW.md': '# Data flow\nInput: uploaded PDF. Ingest extracts text. Storage: tenant-scoped Postgres. Processor: model provider receives minimised excerpts. Output: review memo. Retention: 30 days, then deletion.',
  }, 'Dedicated end-to-end data flow should satisfy E2.'),

  golden('data-flow-placeholder', 'TR-DATA-001', 'candidate', {
    'DATA_FLOW.md': '# Data flow\nInput: TODO\nStorage: TBD database\nProcessor: TODO\nOutput: TODO\nRetention: TODO',
  }, 'An incomplete generated data-flow template must remain candidate.'),

  golden('architecture-vague', 'TR-DATA-001', 'candidate', {
    'README.md': 'Architecture uses an input, database storage and output layer.',
  }, 'Architecture keywords without dedicated data-flow proof remain candidate.'),

  golden('subprocessors-dedicated', 'TR-DATA-002', 'verified', {
    'SUBPROCESSORS.md': '# Subprocessors\nVendor: Example Cloud\nService: EU compute\nPurpose: application hosting\nData: encrypted account metadata',
  }, 'Dedicated processor inventory should satisfy E2.'),

  golden('vendor-list-readme', 'TR-DATA-002', 'candidate', {
    'README.md': 'We use a cloud vendor and may add processors later.',
  }, 'Generic vendor language must not verify processor inventory.'),

  golden('security-intake-dedicated', 'TR-SEC-002', 'verified', {
    'SECURITY.md': '# Security\nReport a vulnerability or security issue to security@example.test. We acknowledge reports, triage severity and coordinate remediation before disclosure.',
  }, 'Dedicated vulnerability intake process should satisfy E2.'),

  golden('security-template-placeholder', 'TR-SEC-002', 'candidate', {
    'SECURITY.md': '# Security\nReport a vulnerability to TODO security contact. Contact: TODO. Security issue handling: TBD.',
  }, 'A security-policy template with no real contact/process must not verify.'),

  golden('security-marketing-trap', 'TR-SEC-002', 'candidate', {
    'README.md': 'Security is our priority. Report dashboards are beautiful and fast.',
  }, 'Marketing language must not verify vulnerability intake.'),

  golden('eval-ci-and-tests', 'TR-OPS-002', 'verified', {
    '.github/workflows/ci.yml': 'steps:\n  - run: node --test core/*.test.mjs\n  - run: node evals/adversarial.mjs',
    'core/runtime.test.mjs': 'test("blocks missing approval", () => {})',
    'evals/adversarial.mjs': 'export const cases = ["prompt injection", "missing evidence"]',
  }, 'CI plus concrete tests/evals should satisfy E2.'),

  golden('eval-readme-claim', 'TR-OPS-002', 'candidate', {
    'README.md': 'We test everything and run evals for failure modes and regression.',
  }, 'A claim about tests is not test evidence.'),

  golden('supply-lockfile', 'TR-SUPPLY-001', 'verified', {
    'package-lock.json': '{"name":"safe-app","lockfileVersion":3,"packages":{"":{"dependencies":{"example":"1.2.3"}}}}',
  }, 'Lockfile should satisfy repository-level E2 provenance.'),

  golden('supply-package-only', 'TR-SUPPLY-001', 'candidate', {
    'package.json': '{"dependencies":{"example":"^1.2.0"},"description":"dependency example"}',
  }, 'Unpinned dependency declarations alone are insufficient.'),

  golden('buyer-assurance-dedicated', 'TR-BUY-001', 'verified', {
    'TRUST_CENTER.md': '# Trust Center\nEvidence: CI run and source revision are linked for each control. Unknown: production recovery drill is not yet proven. Limitations and gaps remain visible to the buyer.',
  }, 'Buyer pack that cites evidence and unknowns should satisfy E2.'),

  golden('buyer-marketing-trust-page', 'TR-BUY-001', 'candidate', {
    'TRUST_CENTER.md': '# Trust Center\nWe are secure, compliant and trusted by everyone.',
  }, 'Trust-branded marketing without evidence/unknowns must not verify.'),

  golden('freshness-manifest', 'TR-BUY-002', 'verified', {
    'ASSURANCE_MANIFEST.json': '{"observed_at":"2026-08-31T10:00:00Z","valid_until":"2026-09-30T10:00:00Z","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}',
  }, 'Machine-readable observed/expiry/hash metadata should satisfy E2.'),

  golden('freshness-placeholder', 'TR-BUY-002', 'candidate', {
    'ASSURANCE_MANIFEST.json': '{"observed_at":"TODO","valid_until":"TBD","sha256":"placeholder"}',
  }, 'A generated freshness manifest with placeholders must not earn credit.'),

  golden('freshness-incomplete', 'TR-BUY-002', 'candidate', {
    'ASSURANCE_MANIFEST.json': '{"observed_at":"2026-08-31T10:00:00Z","status":"fresh"}',
  }, 'Missing expiry/hash must not verify freshness contract.'),

  golden('human-oversight-readme', 'TR-AI-002', 'candidate', {
    'README.md': 'Every consequential action requires human approval. Human oversight and final authority remain outside the model.',
  }, 'Repository language cannot prove runtime human-gate enforcement (E3).'),

  golden('retention-policy-only', 'TR-DATA-003', 'candidate', {
    'RETENTION_AND_DELETION.md': 'Retention is 30 days. Tenant deletion removes customer records.',
  }, 'Policy cannot prove technical deletion behaviour (E3).'),

  golden('tenant-code-only', 'TR-SEC-001', 'candidate', {
    'src/auth.js': 'export function authorize({tenant, role}) { return tenant && role === "admin" } // authentication authorization tenant RBAC',
  }, 'Static repository code cannot prove deployment tenant isolation (E3).'),

  golden('incident-plan-only', 'TR-SEC-003', 'candidate', {
    'AI_SECURITY_INCIDENT_RESPONSE.md': 'Incident response: containment, eradication, recovery and post-incident review. Exercise quarterly.',
  }, 'Plan alone cannot prove incident response was exercised (E3).'),

  golden('audit-code-only', 'TR-OPS-001', 'candidate', {
    'src/audit.js': 'export function audit(trace) { return { trace, replay: true } } // audit trace replay',
  }, 'Static implementation cannot prove production audit trace exists (E3).'),

  golden('monitoring-config-only', 'TR-OPS-003', 'candidate', {
    'monitoring.yml': 'monitoring: enabled\nalerts: regression-detection\n',
  }, 'Repository config cannot prove production monitoring is active (E3).'),

  golden('backup-doc-only', 'TR-OPS-004', 'candidate', {
    'RUNBOOK.md': 'Backup nightly. Restore procedure documented. Rollback to previous release.',
  }, 'Runbook cannot prove a restore/rollback capability has been exercised (E3).'),

  golden('role-assessment-doc', 'TR-GOV-002', 'candidate', {
    'AI_ACT_ROLE_ASSESSMENT.md': 'AI Act role: provider for this feature; deployer for third-party tooling. Risk classification reviewed internally.',
  }, 'Legal/role classification requires authorised attestation (E4).'),

  golden('owner-list-doc', 'TR-GOV-003', 'candidate', {
    'OWNERS.md': 'Accountable owner: Security Lead. Responsible owner: Product Lead.',
  }, 'Named accountability requires authorised attestation, not an unauthenticated file.'),

  golden('ai-disclosure-ui-source', 'TR-AI-003', 'candidate', {
    'src/ui.tsx': '<p>You are interacting with an AI system.</p> // ai disclosure',
  }, 'Source code cannot prove disclosure is deployed to the relevant user journey (E3).'),
]