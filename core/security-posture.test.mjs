import test from 'node:test'
import assert from 'node:assert/strict'
import { evaluateSecurityPosture, validateSecurityPosture } from './security-posture.mjs'

function posture(overrides = {}) {
  const controls = [
    'authority_outside_model', 'least_privilege', 'tenant_isolation', 'human_approval', 'provenance', 'protected_data',
    'bounded_execution', 'auditability', 'supply_chain', 'adversarial_evals', 'production_monitoring',
  ].map((id) => ({ id, status: 'implemented', evidence: [{ type: 'test', path: `tests/${id}.test`, claim: `${id} is regression tested.` }] }))
  return {
    version: 'security-posture/v1',
    project: { id: 'demo', repository: 'owner/demo', domain: 'demo' },
    thesis: 'Authority remains outside the model.',
    controls,
    adversarial: { taxonomy: 'OWASP Agentic 2026', cases: 40, passed: 40, criticalEscapes: 0, liveModel: false },
    claims: { productionSecure: false, promptInjectionSolved: false, certified: false },
    residualRisks: ['External review remains required.'],
    ...overrides,
  }
}

test('valid posture with executable evidence is evidence-ready, not certified', () => {
  const result = evaluateSecurityPosture(posture())
  assert.equal(result.state, 'EVIDENCE_READY')
  assert.equal(result.score, 100)
  assert.equal(result.productionSecurityClaimSupported, false)
})

test('critical impact escape blocks posture regardless of other controls', () => {
  const result = evaluateSecurityPosture(posture({ adversarial: { taxonomy: 'OWASP Agentic 2026', cases: 40, passed: 39, criticalEscapes: 1, liveModel: true } }))
  assert.equal(result.state, 'BLOCK')
  assert.ok(result.reasons.includes('critical_impact_escape_present'))
})

test('implemented control without evidence is invalid', () => {
  const candidate = posture()
  candidate.controls[0].evidence = []
  const validation = validateSecurityPosture(candidate)
  assert.equal(validation.ok, false)
  assert.ok(validation.errors.includes('implemented_without_evidence:authority_outside_model'))
})

test('missing baseline security control produces partial state', () => {
  const candidate = posture()
  candidate.controls = candidate.controls.filter((control) => control.id !== 'protected_data')
  const result = evaluateSecurityPosture(candidate)
  assert.equal(result.state, 'PARTIAL')
  assert.ok(result.reasons.some((reason) => reason.includes('protected_data')))
})

test('partial baseline security control cannot be evidence-ready', () => {
  const candidate = posture()
  candidate.controls = candidate.controls.map((control) => control.id === 'adversarial_evals' ? { ...control, status: 'partial' } : control)
  const result = evaluateSecurityPosture(candidate)
  assert.equal(result.state, 'PARTIAL')
  assert.ok(result.reasons.some((reason) => reason.includes('adversarial_evals')))
})

test('zero adversarial cases is partial even when zero of zero passed', () => {
  const result = evaluateSecurityPosture(posture({ adversarial: { taxonomy: 'No dedicated security gauntlet yet', cases: 0, passed: 0, criticalEscapes: 0, liveModel: false } }))
  assert.equal(result.state, 'PARTIAL')
  assert.ok(result.reasons.includes('no_adversarial_cases'))
})

test('not-applicable baseline control does not invent agent requirements', () => {
  const candidate = posture()
  candidate.controls = candidate.controls.map((control) => control.id === 'bounded_execution' ? { ...control, status: 'not_applicable' } : control)
  const result = evaluateSecurityPosture(candidate)
  assert.equal(result.state, 'EVIDENCE_READY')
})

test('self-declared production-security claim is never accepted as verification', () => {
  const result = evaluateSecurityPosture(posture({ claims: { productionSecure: true, promptInjectionSolved: false, certified: false } }))
  assert.equal(result.productionSecurityClaimSupported, false)
  assert.ok(result.reasons.includes('production_security_claim_requires_external_evidence'))
})

test('prompt-injection solved claim is explicitly rejected', () => {
  const result = evaluateSecurityPosture(posture({ claims: { productionSecure: false, promptInjectionSolved: true, certified: false } }))
  assert.ok(result.reasons.includes('prompt_injection_solved_claim_not_accepted'))
})
