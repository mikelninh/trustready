import assert from 'node:assert/strict'
import test from 'node:test'
import { readFile } from 'node:fs/promises'

import { PLAN_CATALOG, CAPABILITY_UNITS, buildRemediationPack } from './commercial.mjs'
import { scanRepositorySnapshot } from './scanner.mjs'

const profile = JSON.parse(await readFile(new URL('../profiles/core-ai-procurement-2026.08.json', import.meta.url), 'utf8'))

function snapshot(files = {}) {
  return {
    subject: { id: 'paid-test', name: 'Paid Test' },
    repository_url: 'https://github.com/example/paid-test',
    revision: 'paid-test-rev',
    observed_at: '2026-08-31T12:00:00.000Z',
    files,
  }
}

test('launch plans have deterministic prices and unit limits', () => {
  assert.equal(PLAN_CATALOG.developer.monthly_eur_cents, 4900)
  assert.equal(PLAN_CATALOG.developer.monthly_units, 500)
  assert.equal(PLAN_CATALOG.team.monthly_eur_cents, 24900)
  assert.equal(PLAN_CATALOG.team.monthly_units, 5000)
  assert.equal(CAPABILITY_UNITS.private_scan, 5)
  assert.equal(CAPABILITY_UNITS.remediation_pack, 10)
})

test('remediation pack separates templates, runtime proof and attestations', () => {
  const scan = scanRepositorySnapshot(snapshot(), profile)
  const pack = buildRemediationPack(scan, profile)
  assert.ok(pack.template_files.some((item) => item.control_id === 'TR-AI-001'))
  assert.ok(pack.proof_tasks.some((item) => item.control_id === 'TR-AI-002' && item.lane === 'E3'))
  assert.ok(pack.proof_tasks.some((item) => item.control_id === 'TR-GOV-002' && item.lane === 'E4'))
  assert.match(pack.invariant, /Template generation never changes a score/i)
})

test('generated remediation templates cannot increase readiness by themselves', () => {
  const beforeSnapshot = snapshot()
  const before = scanRepositorySnapshot(beforeSnapshot, profile)
  const pack = buildRemediationPack(before, profile)
  const files = Object.fromEntries(pack.template_files.map((item) => [item.path, item.content]))
  const after = scanRepositorySnapshot(snapshot(files), profile)
  assert.equal(after.evaluation.score, before.evaluation.score)
  for (const item of pack.template_files) {
    const status = after.evaluation.results.find((row) => row.control_id === item.control_id)?.status
    assert.notEqual(status, 'verified', `${item.control_id} template must not self-promote`)
  }
})
