import test from 'node:test'
import assert from 'node:assert/strict'
import { normalizePilotEvent, summarizePilotEvents } from './legal-pilot-metrics.mjs'

const hashA = `sha256:${'a'.repeat(64)}`
const hashB = `sha256:${'b'.repeat(64)}`
let sequence = 0

function event(overrides = {}) {
  sequence += 1
  return {
    event_id: `evt-generated-${String(sequence).padStart(4, '0')}`,
    type: 'proposal_accepted',
    case_ref_hash: hashA,
    occurred_at: '2026-09-03T08:00:00Z',
    review_seconds: 120,
    baseline_seconds: 420,
    ...overrides,
  }
}

test('pilot metrics reject raw matter identifiers and surprise fields', () => {
  assert.throws(() => normalizePilotEvent(event({ case_ref_hash: 'M-2041' })), /sha256 digest/)
  assert.throws(() => normalizePilotEvent({ ...event(), client_name: 'Example GmbH' }), /not allowed/)
})

test('pilot metrics reject any unapproved event type including external execution', () => {
  assert.throws(() => normalizePilotEvent(event({ type: 'external_action_executed' })), /event type denied/)
})

test('proposal outcomes require measured baseline and review duration', () => {
  const missing = event()
  delete missing.baseline_seconds
  assert.throws(() => normalizePilotEvent(missing), /baseline duration required/)
  assert.throws(() => normalizePilotEvent(event({ review_seconds: -1 })), /non-negative/)
})

test('pilot summary measures useful rate, time saved and correctness without raw case ids', () => {
  const rows = [
    event({ event_id: 'evt-accepted-01', type: 'proposal_accepted', case_ref_hash: hashA, review_seconds: 120, baseline_seconds: 420 }),
    event({ event_id: 'evt-edited-0002', type: 'proposal_edited', case_ref_hash: hashB, review_seconds: 240, baseline_seconds: 480 }),
    event({ event_id: 'evt-rejected-03', type: 'proposal_rejected', case_ref_hash: hashB, review_seconds: 180, baseline_seconds: 360 }),
    event({ event_id: 'evt-deadline-04', type: 'deadline_confirmed', case_ref_hash: hashA, review_seconds: undefined, baseline_seconds: undefined, correct: true }),
    event({ event_id: 'evt-matter-0005', type: 'matter_assignment_confirmed', case_ref_hash: hashA, review_seconds: undefined, baseline_seconds: undefined, correct: false }),
    event({ event_id: 'evt-blocked-006', type: 'blocked_action_attempt', case_ref_hash: hashA, review_seconds: undefined, baseline_seconds: undefined, reason_code: 'SHADOW_MODE' }),
  ]
  const summary = summarizePilotEvents(rows)
  assert.equal(summary.unique_cases, 2)
  assert.equal(summary.proposal_outcomes, 3)
  assert.equal(summary.accepted, 1)
  assert.equal(summary.edited, 1)
  assert.equal(summary.rejected, 1)
  assert.equal(summary.useful_rate, 2 / 3)
  assert.equal(summary.total_saved_minutes, 9)
  assert.equal(summary.deadline_accuracy, 1)
  assert.equal(summary.matter_assignment_accuracy, 0)
  assert.equal(summary.blocked_action_attempts, 1)
  assert.equal(summary.autonomous_external_actions_executed, 0)
})

test('duplicate event ids fail closed instead of double-counting pilot value', () => {
  const row = event({ event_id: 'evt-duplicate-01' })
  assert.throws(() => summarizePilotEvents([row, { ...row }]), /duplicate pilot event_id/)
})
