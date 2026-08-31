import assert from 'node:assert/strict'
import test from 'node:test'
import { readFile } from 'node:fs/promises'

import {
  discoverCandidateEvidence,
  promoteRepositoryEvidence,
  scanRepositorySnapshot,
  validateEvidenceProvenance,
} from './scanner.mjs'
import { runScannerBenchmark } from '../benchmarks/run-scanner-benchmark.mjs'
import { SCANNER_GOLDEN_CASES } from '../benchmarks/scanner-golden.mjs'

const profile = JSON.parse(await readFile(new URL('../profiles/core-ai-procurement-2026.08.json', import.meta.url), 'utf8'))

function snapshot(files) {
  return {
    subject: { id: 'test-product', name: 'Test Product' },
    repository_url: 'https://github.com/example/test-product',
    revision: 'abc123def456',
    observed_at: '2026-08-31T12:00:00.000Z',
    files,
  }
}

test('keyword-only evidence is candidate and cannot earn verified credit', () => {
  const input = snapshot({ 'README.md': 'Security audit trace human approval model provider retention deletion monitoring.' })
  const candidates = discoverCandidateEvidence(input, profile)
  assert.ok(candidates.length > 0)
  assert.ok(candidates.every((item) => item.strength === 'E0' && item.candidate === true))

  const scan = scanRepositorySnapshot(input, profile)
  assert.equal(scan.evaluation.results.find((item) => item.control_id === 'TR-AI-002').status, 'candidate')
  assert.equal(scan.evaluation.results.find((item) => item.control_id === 'TR-SEC-001').status, 'candidate')
})

test('dedicated E2 artifact is promoted with immutable provenance', () => {
  const input = snapshot({
    'MODEL_VENDOR_INVENTORY.md': '# Models\nProvider: ExampleAI\nModel: reasoning-v3\nVersion: 3\nPurpose: classification\nData: minimised text',
  })
  const evidence = promoteRepositoryEvidence(input)
  const item = evidence.find((candidate) => candidate.control_ids.includes('TR-AI-001'))
  assert.ok(item)
  assert.equal(item.strength, 'E2')
  assert.equal(validateEvidenceProvenance(item).valid, true)
  assert.equal(item.provenance.source_revision, 'abc123def456')
  assert.match(item.source, /blob\/abc123def456\/MODEL_VENDOR_INVENTORY\.md$/)
})

test('repository scanner refuses to verify E3 runtime controls from static source', () => {
  const input = snapshot({
    'README.md': 'Human approval is mandatory. Authentication and tenant isolation are enforced. Audit trace and replay are available. Production monitoring and rollback are enabled.',
    'src/auth.js': 'export const tenantIsolation = true',
    'monitoring.yml': 'monitoring: enabled',
  })
  const scan = scanRepositorySnapshot(input, profile)
  for (const controlId of ['TR-AI-002', 'TR-SEC-001', 'TR-OPS-001', 'TR-OPS-003']) {
    const result = scan.evaluation.results.find((item) => item.control_id === controlId)
    assert.notEqual(result.status, 'verified', `${controlId} must require stronger runtime evidence`)
  }
})

test('gap explanation tells a reviewer exactly what proof is still needed', () => {
  const scan = scanRepositorySnapshot(snapshot({
    'AI_ACT_ROLE_ASSESSMENT.md': 'Provider/deployer role and risk classification reviewed.',
  }), profile)
  const role = scan.gaps.find((item) => item.control_id === 'TR-GOV-002')
  assert.equal(role.attestation_only, true)
  assert.equal(role.remediation_lane, 'human_legal_or_accountable_owner')
  assert.match(role.next_proof, /authenticated, named, authorised attestation/i)
  assert.equal(role.rule_profile, 'core-ai-procurement@2026.08')
})

test('30-case benchmark has zero false verified and full exact-status agreement', () => {
  const report = runScannerBenchmark(SCANNER_GOLDEN_CASES, profile)
  assert.ok(report.cases >= 20)
  assert.equal(report.metrics.false_verified_rate, 0)
  assert.equal(report.metrics.false_positives, 0)
  assert.equal(report.metrics.false_negatives, 0)
  assert.equal(report.metrics.verified_precision, 1)
  assert.equal(report.metrics.verified_recall, 1)
  assert.equal(report.metrics.exact_status_accuracy, 1)
  assert.equal(report.release_gate.provenance_complete, true)
})
