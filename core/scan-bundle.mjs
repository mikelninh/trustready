import { evaluateProfile } from './trust-kernel.mjs'
import {
  dedupeEvidence,
  discoverCandidateEvidence,
  explainProfileGaps,
  promoteRepositoryEvidence,
} from './scanner.mjs'

export function validateGenericProvenance(item) {
  const required = [
    'subject_id',
    'source_revision',
    'content_sha256',
    'collector_version',
    'promotion_rule_id',
    'promotion_ruleset_version',
  ]
  const missing = required.filter((key) => !item?.provenance?.[key])
  const hasLocator = Boolean(item?.provenance?.source_path || item?.provenance?.source_url || item?.source)
  if (!hasLocator) missing.push('source_path_or_url')
  const hashMatches = Boolean(item?.provenance?.content_sha256) && item.provenance.content_sha256 === item.sha256
  return { valid: missing.length === 0 && hashMatches, missing, hashMatches }
}

export function scanEvidenceBundle({ snapshot, externalEvidence = [], profile, now = new Date(snapshot?.observed_at || Date.now()) }) {
  if (!snapshot?.subject?.id) throw new TypeError('snapshot.subject.id is required')
  if (!profile?.controls) throw new TypeError('profile.controls is required')

  const candidates = discoverCandidateEvidence(snapshot, profile)
  const repositoryEvidence = promoteRepositoryEvidence(snapshot)
  const evidence = dedupeEvidence([...candidates, ...repositoryEvidence, ...externalEvidence])
  const evaluation = evaluateProfile({ profile, evidence, now })
  const accepted = evidence.filter((item) => item.strength !== 'E0' && item.candidate !== true)
  const provenanceChecks = accepted.map((item) => ({ evidence_id: item.evidence_id, ...validateGenericProvenance(item) }))

  return {
    schema: 'trustready-evidence-bundle-scan-v1',
    subject: snapshot.subject,
    observed_at: now.toISOString(),
    profile: { id: profile.id, version: profile.version },
    evidence,
    evaluation,
    gaps: explainProfileGaps(profile, evaluation, evidence),
    provenance_complete: provenanceChecks.every((item) => item.valid),
    provenance_checks: provenanceChecks,
    evidence_summary: {
      candidates: evidence.filter((item) => item.candidate === true || item.strength === 'E0').length,
      repository_accepted: repositoryEvidence.length,
      external_runtime_accepted: externalEvidence.filter((item) => item.type === 'runtime_http_observation').length,
      total_accepted: accepted.length,
    },
    boundary: 'Evidence types remain distinguishable. Source/config evidence is not treated as deployment proof; external observations prove only what was observable at the recorded time and URL.',
  }
}
