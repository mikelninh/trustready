import test from 'node:test'
import assert from 'node:assert/strict'
import { evaluatePilotReadiness } from '../scripts/legal-pilot-readiness.mjs'

const baseAudit = {
  engineering: { status: 'PASS' },
  verdict: {
    pre_audit_ready: true,
    real_mandate_shadow_ready: false,
    independently_assured: false,
    human_approved_send_ready: false,
  },
}

test('synthetic Bao pilot is ready only while real data and send remain disabled', () => {
  const result = evaluatePilotReadiness({ audit_report: baseAudit, env: { TRUSTREADY_REAL_MANDATE_DATA_ENABLED: 'false', TRUSTREADY_HUMAN_APPROVED_SEND_ENABLED: 'false' } })
  assert.equal(result.synthetic_pilot_ready, true)
  assert.equal(result.real_mandate_pilot_ready, false)
  assert.equal(result.human_approved_send_ready, false)
})

test('environment flag alone can never promote real mandate readiness', () => {
  const result = evaluatePilotReadiness({ audit_report: baseAudit, env: { TRUSTREADY_REAL_MANDATE_DATA_ENABLED: 'true', TRUSTREADY_HUMAN_APPROVED_SEND_ENABLED: 'false' } })
  assert.equal(result.synthetic_pilot_ready, false)
  assert.equal(result.real_mandate_pilot_ready, false)
  assert.ok(result.blockers.includes('REAL_MANDATE_LIVE_EVIDENCE_MISSING'))
  assert.ok(result.blockers.includes('INDEPENDENT_ASSURANCE_MISSING'))
})

test('send cannot be enabled before separate human-approved execution release', () => {
  const audit = {
    engineering: { status: 'PASS' },
    verdict: { pre_audit_ready: true, real_mandate_shadow_ready: true, independently_assured: true, human_approved_send_ready: false },
  }
  const result = evaluatePilotReadiness({ audit_report: audit, env: { TRUSTREADY_REAL_MANDATE_DATA_ENABLED: 'true', TRUSTREADY_HUMAN_APPROVED_SEND_ENABLED: 'true' } })
  assert.equal(result.real_mandate_pilot_ready, false)
  assert.equal(result.human_approved_send_ready, false)
  assert.ok(result.blockers.includes('HUMAN_APPROVED_SEND_NOT_SEPARATELY_RELEASED'))
})

test('real mandate pilot requires live and independent evidence while send remains off', () => {
  const audit = {
    engineering: { status: 'PASS' },
    verdict: { pre_audit_ready: true, real_mandate_shadow_ready: true, independently_assured: true, human_approved_send_ready: false },
  }
  const result = evaluatePilotReadiness({ audit_report: audit, env: { TRUSTREADY_REAL_MANDATE_DATA_ENABLED: 'true', TRUSTREADY_HUMAN_APPROVED_SEND_ENABLED: 'false' } })
  assert.equal(result.real_mandate_pilot_ready, true)
  assert.equal(result.human_approved_send_ready, false)
})