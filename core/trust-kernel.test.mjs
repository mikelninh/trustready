import assert from 'node:assert/strict'
import test from 'node:test'

import {
  buildAssuranceManifest,
  evaluateProfile,
  sha256,
  verifyAssuranceManifest,
} from './trust-kernel.mjs'

const now = new Date('2026-08-31T12:00:00Z')

function ev(overrides = {}) {
  const base = {
    evidence_id: 'ev-1',
    type: 'document',
    strength: 'E1',
    observed_at: '2026-08-31T10:00:00Z',
    valid_until: '2026-09-30T10:00:00Z',
    sha256: sha256('evidence'),
    control_ids: ['TR-1'],
  }
  return { ...base, ...overrides }
}

function profile(control = {}) {
  return {
    id: 'enterprise-ai-eu',
    version: '2026.08',
    controls: [{ id: 'TR-1', minimum_strength: 'E2', blocking: true, ...control }],
  }
}

test('candidate evidence never earns verified credit', () => {
  const evaluation = evaluateProfile({
    profile: profile(),
    evidence: [ev({ strength: 'E0', candidate: true })],
    now,
  })
  assert.equal(evaluation.results[0].status, 'candidate')
  assert.equal(evaluation.score, 0)
  assert.equal(evaluation.ready, false)
})

test('policy evidence cannot prove a control requiring technical proof', () => {
  const evaluation = evaluateProfile({ profile: profile(), evidence: [ev({ strength: 'E1' })], now })
  assert.equal(evaluation.results[0].status, 'partial')
  assert.deepEqual(evaluation.blocking_findings, ['TR-1'])
})

test('accepted technical evidence verifies deterministic rule', () => {
  const evaluation = evaluateProfile({ profile: profile(), evidence: [ev({ strength: 'E2' })], now })
  assert.equal(evaluation.results[0].status, 'verified')
  assert.equal(evaluation.score, 100)
  assert.equal(evaluation.ready, true)
})

test('independent/runtime requirement remains partial without stronger proof', () => {
  const p = profile({ minimum_strength: 'E2', require_independent: true })
  const partial = evaluateProfile({ profile: p, evidence: [ev({ strength: 'E2' })], now })
  assert.equal(partial.results[0].status, 'partial')

  const verified = evaluateProfile({ profile: p, evidence: [ev({ strength: 'E3', independent: true })], now })
  assert.equal(verified.results[0].status, 'verified')
})

test('expired evidence becomes stale and removes readiness', () => {
  const evaluation = evaluateProfile({
    profile: profile(),
    evidence: [ev({ strength: 'E2', valid_until: '2026-08-30T10:00:00Z' })],
    now,
  })
  assert.equal(evaluation.results[0].status, 'stale')
  assert.equal(evaluation.ready, false)
})

test('contradictory evidence blocks even when strong evidence exists', () => {
  const evaluation = evaluateProfile({
    profile: profile(),
    evidence: [
      ev({ evidence_id: 'good', strength: 'E3', independent: true }),
      ev({ evidence_id: 'bad', strength: 'E3', independent: true, contradicts: true, sha256: sha256('bad') }),
    ],
    now,
  })
  assert.equal(evaluation.results[0].status, 'blocked')
  assert.equal(evaluation.ready, false)
})

test('attestation-only controls require explicit authorised E4 attestation', () => {
  const p = profile({ attestation_only: true, minimum_strength: 'E4' })
  const insufficient = evaluateProfile({ profile: p, evidence: [ev({ strength: 'E4', authorised_attestation: false })], now })
  assert.equal(insufficient.results[0].status, 'partial')
  assert.equal(insufficient.ready, false)

  const accepted = evaluateProfile({ profile: p, evidence: [ev({ strength: 'E4', authorised_attestation: true })], now })
  assert.equal(accepted.results[0].status, 'attested')
  assert.equal(accepted.ready, true)
})

test('manifest integrity is reproducible and mutation is detected', () => {
  const p = profile()
  const evidence = [ev({ strength: 'E2' })]
  const evaluation = evaluateProfile({ profile: p, evidence, now })
  const manifest = buildAssuranceManifest({ subject: { id: 'acme-ai' }, profile: p, evidence, evaluation })
  assert.equal(verifyAssuranceManifest(manifest).valid, true)

  const mutated = structuredClone(manifest)
  mutated.subject.id = 'tampered'
  assert.equal(verifyAssuranceManifest(mutated).valid, false)
})
