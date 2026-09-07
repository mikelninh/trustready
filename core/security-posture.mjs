export const SECURITY_POSTURE_VERSION = 'security-posture/v1'

export const SECURITY_CONTROL_IDS = Object.freeze([
  'authority_outside_model',
  'least_privilege',
  'tenant_isolation',
  'human_approval',
  'provenance',
  'protected_data',
  'bounded_execution',
  'auditability',
  'supply_chain',
  'adversarial_evals',
  'production_monitoring',
])

const STATUSES = new Set(['implemented', 'partial', 'not_proven', 'not_applicable'])
const EVIDENCE_TYPES = new Set(['code', 'test', 'ci', 'doc', 'report', 'deployment'])
const REQUIRED_BASELINE = new Set(['authority_outside_model', 'protected_data', 'bounded_execution', 'auditability', 'adversarial_evals'])
const present = (value) => typeof value === 'string' && value.trim().length > 0

export function validateSecurityPosture(posture) {
  const errors = []
  if (!posture || typeof posture !== 'object') return { ok: false, errors: ['posture_required'] }
  if (posture.version !== SECURITY_POSTURE_VERSION) errors.push('posture_version_invalid')
  if (!present(posture.project?.id)) errors.push('project_id_required')
  if (!/^[^/]+\/[^/]+$/.test(posture.project?.repository ?? '')) errors.push('project_repository_invalid')
  if (!present(posture.project?.domain)) errors.push('project_domain_required')
  if (!present(posture.thesis)) errors.push('security_thesis_required')
  if (!Array.isArray(posture.controls) || posture.controls.length === 0) errors.push('controls_required')

  const ids = new Set()
  for (const control of posture.controls ?? []) {
    if (!SECURITY_CONTROL_IDS.includes(control?.id)) errors.push(`control_id_invalid:${control?.id ?? 'missing'}`)
    if (ids.has(control?.id)) errors.push(`control_duplicate:${control?.id}`)
    if (control?.id) ids.add(control.id)
    if (!STATUSES.has(control?.status)) errors.push(`control_status_invalid:${control?.id ?? 'missing'}`)
    if (!Array.isArray(control?.evidence)) errors.push(`control_evidence_required:${control?.id ?? 'missing'}`)
    for (const evidence of control?.evidence ?? []) {
      if (!EVIDENCE_TYPES.has(evidence?.type)) errors.push(`evidence_type_invalid:${control?.id}`)
      if (!present(evidence?.path)) errors.push(`evidence_path_required:${control?.id}`)
      if (!present(evidence?.claim)) errors.push(`evidence_claim_required:${control?.id}`)
    }
    if (control?.status === 'implemented' && (control?.evidence?.length ?? 0) === 0) errors.push(`implemented_without_evidence:${control?.id}`)
  }

  const adversarial = posture.adversarial ?? {}
  if (!present(adversarial.taxonomy)) errors.push('adversarial_taxonomy_required')
  if (!Number.isInteger(adversarial.cases) || adversarial.cases < 0) errors.push('adversarial_cases_invalid')
  if (!Number.isInteger(adversarial.passed) || adversarial.passed < 0 || adversarial.passed > (adversarial.cases ?? -1)) errors.push('adversarial_passed_invalid')
  if (!Number.isInteger(adversarial.criticalEscapes) || adversarial.criticalEscapes < 0) errors.push('critical_escapes_invalid')
  if (typeof adversarial.liveModel !== 'boolean') errors.push('live_model_flag_required')

  for (const claim of ['productionSecure', 'promptInjectionSolved', 'certified']) {
    if (typeof posture.claims?.[claim] !== 'boolean') errors.push(`claim_flag_required:${claim}`)
  }
  if (!Array.isArray(posture.residualRisks)) errors.push('residual_risks_required')

  return { ok: errors.length === 0, errors: [...new Set(errors)] }
}

export function evaluateSecurityPosture(posture) {
  const validation = validateSecurityPosture(posture)
  if (!validation.ok) return { state: 'INVALID', score: 0, validation, reasons: validation.errors }

  const applicable = posture.controls.filter((control) => control.status !== 'not_applicable')
  const points = applicable.reduce((total, control) => total + ({ implemented: 1, partial: 0.5, not_proven: 0 }[control.status] ?? 0), 0)
  const score = applicable.length === 0 ? 0 : Math.round((points / applicable.length) * 100)
  const byId = new Map(posture.controls.map((control) => [control.id, control]))
  const baselineGaps = [...REQUIRED_BASELINE].filter((id) => {
    const control = byId.get(id)
    return !control || !['implemented', 'not_applicable'].includes(control.status)
  })
  const reasons = []

  if (posture.adversarial.criticalEscapes > 0) reasons.push('critical_impact_escape_present')
  if (posture.adversarial.cases === 0) reasons.push('no_adversarial_cases')
  if (posture.adversarial.passed !== posture.adversarial.cases) reasons.push('adversarial_regressions_present')
  if (baselineGaps.length) reasons.push(`baseline_controls_not_proven:${baselineGaps.join(',')}`)
  if (posture.claims.productionSecure) reasons.push('production_security_claim_requires_external_evidence')
  if (posture.claims.promptInjectionSolved) reasons.push('prompt_injection_solved_claim_not_accepted')
  if (posture.claims.certified) reasons.push('certification_claim_requires_external_verification')

  let state = 'EVIDENCE_READY'
  if (posture.adversarial.criticalEscapes > 0) state = 'BLOCK'
  else if (posture.adversarial.cases === 0 || posture.adversarial.passed !== posture.adversarial.cases || baselineGaps.length > 0) state = 'PARTIAL'

  return {
    state,
    score,
    validation,
    reasons,
    implemented: posture.controls.filter((control) => control.status === 'implemented').length,
    partial: posture.controls.filter((control) => control.status === 'partial').length,
    notProven: posture.controls.filter((control) => control.status === 'not_proven').length,
    notApplicable: posture.controls.filter((control) => control.status === 'not_applicable').length,
    productionSecurityClaimSupported: false,
    truthBoundary: 'This evaluates repository-published engineering evidence. It is not a penetration test, certification, deployment review or proof that prompt injection is solved.',
  }
}

export function portfolioSummary(postures) {
  return postures.map((posture) => ({ posture, evaluation: evaluateSecurityPosture(posture) }))
}
