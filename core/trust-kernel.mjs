import crypto from 'node:crypto'

export const EVIDENCE_STRENGTH = Object.freeze({
  E0: 0,
  E1: 1,
  E2: 2,
  E3: 3,
  E4: 4,
  E5: 5,
})

export const CONTROL_STATES = new Set([
  'not_observed',
  'candidate',
  'partial',
  'verified',
  'attested',
  'stale',
  'regressed',
  'not_applicable',
  'blocked',
])

export function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`
  }
  return JSON.stringify(value)
}

export function sha256(value) {
  return crypto.createHash('sha256').update(typeof value === 'string' ? value : canonicalize(value)).digest('hex')
}

export function validateEvidence(evidence) {
  if (!evidence || typeof evidence !== 'object') throw new TypeError('Evidence must be an object')
  if (!evidence.evidence_id) throw new TypeError('evidence_id is required')
  if (!(evidence.strength in EVIDENCE_STRENGTH)) throw new TypeError(`Unknown evidence strength: ${evidence.strength}`)
  if (!evidence.type) throw new TypeError('evidence.type is required')
  if (!evidence.observed_at) throw new TypeError('evidence.observed_at is required')
  if (!evidence.sha256) throw new TypeError('evidence.sha256 is required')
  return evidence
}

function isExpired(evidence, now) {
  if (!evidence.valid_until) return false
  return new Date(evidence.valid_until).getTime() < now.getTime()
}

function maxStrength(items) {
  return items.reduce((max, evidence) => Math.max(max, EVIDENCE_STRENGTH[evidence.strength]), -1)
}

function independentlyObserved(items) {
  return items.some((evidence) => EVIDENCE_STRENGTH[evidence.strength] >= EVIDENCE_STRENGTH.E3 || evidence.independent === true)
}

export function evaluateControl({ control, evidence = [], now = new Date() }) {
  if (!control?.id) throw new TypeError('control.id is required')
  const checked = evidence.map(validateEvidence)
  const relevant = checked.filter((item) => item.control_ids?.includes(control.id))

  const contradictions = relevant.filter((item) => item.contradicts === true)
  if (contradictions.length > 0) {
    return {
      control_id: control.id,
      status: 'blocked',
      evidence_ids: relevant.map((item) => item.evidence_id),
      reason: 'Contradictory evidence blocks readiness until resolved.',
      blocking: true,
    }
  }

  if (control.applicability === false) {
    return {
      control_id: control.id,
      status: 'not_applicable',
      evidence_ids: relevant.map((item) => item.evidence_id),
      reason: control.applicability_reason || 'Marked not applicable by profile.',
      blocking: false,
    }
  }

  if (relevant.length === 0) {
    return {
      control_id: control.id,
      status: 'not_observed',
      evidence_ids: [],
      reason: 'No accepted evidence observed.',
      blocking: Boolean(control.blocking),
    }
  }

  const fresh = relevant.filter((item) => !isExpired(item, now))
  if (fresh.length === 0) {
    return {
      control_id: control.id,
      status: 'stale',
      evidence_ids: relevant.map((item) => item.evidence_id),
      reason: 'All evidence is outside the configured validity window.',
      blocking: Boolean(control.blocking),
    }
  }

  const nonCandidate = fresh.filter((item) => item.strength !== 'E0' && item.candidate !== true)
  if (nonCandidate.length === 0) {
    return {
      control_id: control.id,
      status: 'candidate',
      evidence_ids: fresh.map((item) => item.evidence_id),
      reason: 'Candidate evidence was discovered but cannot earn control credit.',
      blocking: Boolean(control.blocking),
    }
  }

  const requiredStrength = EVIDENCE_STRENGTH[control.minimum_strength || 'E1']
  const strongest = maxStrength(nonCandidate)
  const requiresIndependent = Boolean(control.require_independent)
  const independentSatisfied = !requiresIndependent || independentlyObserved(nonCandidate)

  if (control.attestation_only) {
    const attestation = nonCandidate.find((item) => item.strength === 'E4' && item.authorised_attestation === true)
    if (attestation) {
      return {
        control_id: control.id,
        status: 'attested',
        evidence_ids: nonCandidate.map((item) => item.evidence_id),
        reason: 'Accepted authorised attestation satisfies this attestation-only control.',
        blocking: false,
      }
    }
  }

  if (strongest >= requiredStrength && independentSatisfied) {
    return {
      control_id: control.id,
      status: 'verified',
      evidence_ids: nonCandidate.map((item) => item.evidence_id),
      reason: 'Accepted evidence satisfies the deterministic profile rule.',
      blocking: false,
    }
  }

  return {
    control_id: control.id,
    status: 'partial',
    evidence_ids: nonCandidate.map((item) => item.evidence_id),
    reason: requiresIndependent && !independentSatisfied
      ? 'Evidence exists, but the profile requires stronger independent/runtime proof.'
      : `Evidence exists, but minimum strength ${control.minimum_strength || 'E1'} is not met.`,
    blocking: Boolean(control.blocking),
  }
}

export function evaluateProfile({ profile, evidence, now = new Date() }) {
  if (!profile?.id || !profile?.version || !Array.isArray(profile.controls)) throw new TypeError('profile must include id, version and controls')
  const results = profile.controls.map((control) => evaluateControl({ control, evidence, now }))
  const applicable = results.filter((result) => result.status !== 'not_applicable')
  const satisfied = applicable.filter((result) => ['verified', 'attested'].includes(result.status))
  const blockers = results.filter((result) => result.status === 'blocked' || (result.blocking && !['verified', 'attested', 'not_applicable'].includes(result.status)))

  const relevantEvidenceIds = new Set(results.flatMap((result) => result.evidence_ids))
  const usedEvidence = evidence.filter((item) => relevantEvidenceIds.has(item.evidence_id))
  const independentIds = new Set(usedEvidence.filter((item) => item.independent === true || EVIDENCE_STRENGTH[item.strength] >= EVIDENCE_STRENGTH.E3).map((item) => item.evidence_id))
  const attestationIds = new Set(usedEvidence.filter((item) => item.strength === 'E4').map((item) => item.evidence_id))
  const freshIds = new Set(usedEvidence.filter((item) => !isExpired(item, now)).map((item) => item.evidence_id))

  const pct = (num, den) => den === 0 ? 0 : Math.round((num / den) * 10000) / 100

  return {
    profile_id: profile.id,
    profile_version: profile.version,
    generated_at: now.toISOString(),
    score: pct(satisfied.length, applicable.length),
    coverage_pct: pct(applicable.filter((result) => result.status !== 'not_observed').length, applicable.length),
    verified_pct: pct(applicable.filter((result) => result.status === 'verified').length, applicable.length),
    independent_evidence_pct: pct(independentIds.size, usedEvidence.length),
    attested_evidence_pct: pct(attestationIds.size, usedEvidence.length),
    fresh_evidence_pct: pct(freshIds.size, usedEvidence.length),
    blocking_findings: blockers.map((result) => result.control_id),
    ready: blockers.length === 0 && satisfied.length === applicable.length,
    results,
  }
}

export function buildAssuranceManifest({ subject, profile, evidence, evaluation, ruleset_version = 'trust-kernel-v1' }) {
  const body = {
    schema: 'trustready-assurance-manifest-v1',
    subject,
    profile: { id: profile.id, version: profile.version },
    ruleset_version,
    evidence: evidence.map((item) => ({
      evidence_id: item.evidence_id,
      sha256: item.sha256,
      type: item.type,
      strength: item.strength,
      observed_at: item.observed_at,
      valid_until: item.valid_until || null,
      source: item.source || null,
      independent: Boolean(item.independent),
    })).sort((a, b) => a.evidence_id.localeCompare(b.evidence_id)),
    evaluation,
  }
  return { ...body, manifest_sha256: sha256(body) }
}

export function verifyAssuranceManifest(manifest) {
  if (manifest?.schema !== 'trustready-assurance-manifest-v1') return { valid: false, reason: 'Unsupported manifest schema' }
  const { manifest_sha256, ...body } = manifest
  const calculated = sha256(body)
  return {
    valid: manifest_sha256 === calculated,
    expected: manifest_sha256,
    calculated,
    reason: manifest_sha256 === calculated ? 'Manifest integrity verified.' : 'Manifest hash mismatch.',
  }
}
