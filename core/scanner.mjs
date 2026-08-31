import { evaluateProfile, sha256 } from './trust-kernel.mjs'

export const SCANNER_RULESET_VERSION = 'scanner-rules-2026.08.1'
export const COLLECTOR_VERSION = 'repository-snapshot-v1'

const DAY_MS = 24 * 60 * 60 * 1000

function normalizePath(value) {
  return String(value || '').replace(/^\.\//, '')
}

function text(value) {
  return String(value || '').toLowerCase()
}

function hasAll(value, terms) {
  const haystack = text(value)
  return terms.every((term) => haystack.includes(term.toLowerCase()))
}

function hasAny(value, terms) {
  const haystack = text(value)
  return terms.some((term) => haystack.includes(term.toLowerCase()))
}

function fileEntries(snapshot) {
  return Object.entries(snapshot.files || {}).map(([path, content]) => [normalizePath(path), String(content ?? '')])
}

function findFile(snapshot, predicate) {
  return fileEntries(snapshot).find(([path, content]) => predicate(path, content)) || null
}

function findFiles(snapshot, predicate) {
  return fileEntries(snapshot).filter(([path, content]) => predicate(path, content))
}

function sourceUrl(snapshot, filePath) {
  if (snapshot.repository_url && snapshot.revision) {
    return `${snapshot.repository_url.replace(/\/$/, '')}/blob/${snapshot.revision}/${filePath}`
  }
  return snapshot.repository_url || snapshot.subject?.url || null
}

function observedAt(snapshot) {
  return snapshot.observed_at || new Date().toISOString()
}

function validUntil(snapshot, days = 90) {
  const observed = new Date(observedAt(snapshot))
  return new Date(observed.getTime() + days * DAY_MS).toISOString()
}

function evidenceId({ snapshot, controlId, filePath, ruleId, content }) {
  return `ev-${sha256({
    subject: snapshot.subject?.id || snapshot.repository_url || 'unknown',
    revision: snapshot.revision || 'unknown',
    controlId,
    filePath,
    ruleId,
    contentHash: sha256(content),
  }).slice(0, 24)}`
}

function makeEvidence(snapshot, {
  controlId,
  filePath,
  content,
  strength,
  ruleId,
  type = 'repository_artifact',
  candidate = false,
  independent = false,
  note,
  validityDays = 90,
}) {
  const path = normalizePath(filePath)
  const item = {
    evidence_id: evidenceId({ snapshot, controlId, filePath: path, ruleId, content }),
    type,
    strength,
    observed_at: observedAt(snapshot),
    valid_until: validUntil(snapshot, validityDays),
    sha256: sha256(content),
    control_ids: [controlId],
    source: sourceUrl(snapshot, path),
    independent,
    candidate,
    note,
    provenance: {
      subject_id: snapshot.subject?.id || null,
      repository_url: snapshot.repository_url || null,
      source_path: path,
      source_revision: snapshot.revision || null,
      content_sha256: sha256(content),
      collector_version: COLLECTOR_VERSION,
      promotion_rule_id: ruleId,
      promotion_ruleset_version: SCANNER_RULESET_VERSION,
    },
  }
  return item
}

const CANDIDATE_TERMS = Object.freeze({
  'TR-GOV-001': ['purpose', 'intended', 'users', 'use case'],
  'TR-GOV-002': ['ai act', 'provider', 'deployer', 'risk classification'],
  'TR-GOV-003': ['owner', 'accountable', 'responsible'],
  'TR-AI-001': ['model', 'provider', 'openai', 'anthropic', 'gemini', 'llm'],
  'TR-AI-002': ['human approval', 'human review', 'human oversight', 'authority'],
  'TR-AI-003': ['ai disclosure', 'interacting with ai', 'ai-generated'],
  'TR-AI-004': ['limitations', 'not proven', 'non-goal', 'prohibited'],
  'TR-DATA-001': ['data flow', 'storage', 'database', 'input', 'output'],
  'TR-DATA-002': ['subprocessor', 'processor', 'vendor'],
  'TR-DATA-003': ['retention', 'deletion', 'delete'],
  'TR-SEC-001': ['authentication', 'authorization', 'tenant', 'rbac'],
  'TR-SEC-002': ['security', 'vulnerability', 'report'],
  'TR-SEC-003': ['incident response', 'security incident', 'containment'],
  'TR-OPS-001': ['audit', 'trace', 'replay'],
  'TR-OPS-002': ['eval', 'test', 'failure mode', 'regression'],
  'TR-OPS-003': ['monitoring', 'alert', 'regression detection'],
  'TR-OPS-004': ['backup', 'restore', 'rollback'],
  'TR-SUPPLY-001': ['lockfile', 'dependency', 'supply chain', 'provenance'],
  'TR-BUY-001': ['trust center', 'assurance', 'buyer', 'unknown'],
  'TR-BUY-002': ['valid_until', 'observed_at', 'freshness', 'expiry'],
})

export function discoverCandidateEvidence(snapshot, profile) {
  const entries = fileEntries(snapshot)
  const candidates = []

  for (const control of profile.controls) {
    const terms = CANDIDATE_TERMS[control.id] || []
    if (terms.length === 0) continue
    for (const [path, content] of entries) {
      if (!hasAny(content, terms)) continue
      candidates.push(makeEvidence(snapshot, {
        controlId: control.id,
        filePath: path,
        content,
        strength: 'E0',
        ruleId: `candidate:${control.id}`,
        candidate: true,
        note: 'Heuristic discovery only. Candidate evidence cannot earn verified credit.',
        validityDays: 30,
      }))
    }
  }

  return dedupeEvidence(candidates)
}

function isDedicated(path, names) {
  const lower = path.toLowerCase()
  return names.some((name) => lower === name.toLowerCase() || lower.endsWith(`/${name.toLowerCase()}`))
}

const PROMOTION_RULES = [
  {
    id: 'repo.product-purpose.v1',
    controlId: 'TR-GOV-001',
    strength: 'E1',
    match(snapshot) {
      return findFile(snapshot, (path, content) =>
        isDedicated(path, ['README.md', 'PRODUCT.md', 'SYSTEM_PURPOSE.md']) &&
        content.length >= 120 &&
        hasAny(content, ['purpose', 'what it does', 'intended', 'for ', 'users', 'workflow']))
    },
    note: 'Substantive product-purpose artifact observed in repository.',
  },
  {
    id: 'repo.model-inventory.v1',
    controlId: 'TR-AI-001',
    strength: 'E2',
    match(snapshot) {
      return findFile(snapshot, (path, content) =>
        isDedicated(path, ['MODEL_VENDOR_INVENTORY.md', 'MODEL_INVENTORY.md', 'AI_INVENTORY.json']) &&
        hasAny(content, ['model', 'provider']) &&
        hasAny(content, ['version', 'purpose', 'data', 'vendor']))
    },
    note: 'Dedicated model/provider inventory satisfies repository-level technical evidence rule.',
  },
  {
    id: 'repo.limitations.v1',
    controlId: 'TR-AI-004',
    strength: 'E1',
    match(snapshot) {
      return findFile(snapshot, (path, content) =>
        isDedicated(path, ['README.md', 'LIMITATIONS.md', 'ASSURANCE.md']) &&
        hasAny(content, ['limitations', 'not proven', 'does not', 'non-goal', 'prohibited']))
    },
    note: 'Explicit limitations/non-goal language observed.',
  },
  {
    id: 'repo.data-flow.v1',
    controlId: 'TR-DATA-001',
    strength: 'E2',
    match(snapshot) {
      return findFile(snapshot, (path, content) =>
        isDedicated(path, ['DATA_FLOW.md', 'DATAFLOW.md', 'ARCHITECTURE.md']) &&
        hasAny(content, ['input', 'ingest']) &&
        hasAny(content, ['storage', 'database', 'persist']) &&
        hasAny(content, ['output', 'delete', 'retention', 'processor']))
    },
    note: 'Dedicated end-to-end data-flow artifact observed.',
  },
  {
    id: 'repo.subprocessors.v1',
    controlId: 'TR-DATA-002',
    strength: 'E2',
    match(snapshot) {
      return findFile(snapshot, (path, content) =>
        isDedicated(path, ['SUBPROCESSORS.md', 'PROCESSORS.md', 'VENDORS.md']) &&
        hasAny(content, ['processor', 'subprocessor', 'vendor']) &&
        hasAny(content, ['purpose', 'service', 'data']))
    },
    note: 'Dedicated processor/subprocessor inventory observed.',
  },
  {
    id: 'repo.security-intake.v1',
    controlId: 'TR-SEC-002',
    strength: 'E2',
    match(snapshot) {
      return findFile(snapshot, (path, content) =>
        isDedicated(path, ['SECURITY.md']) &&
        hasAny(content, ['report', 'contact', 'email', 'security@']) &&
        hasAny(content, ['vulnerability', 'security issue', 'security']))
    },
    note: 'Dedicated security/vulnerability intake process observed.',
  },
  {
    id: 'repo.evaluation-evidence.v1',
    controlId: 'TR-OPS-002',
    strength: 'E2',
    match(snapshot) {
      const workflow = findFile(snapshot, (path, content) =>
        path.startsWith('.github/workflows/') &&
        hasAny(content, ['node --test', 'pytest', 'eval', 'test']))
      const tests = findFiles(snapshot, (path) =>
        /(^|\/)(test|tests|evals?|benchmarks?)(\/|\.)/i.test(path) || /\.(test|spec)\.(mjs|js|ts|py)$/i.test(path))
      if (!workflow || tests.length === 0) return null
      return [workflow[0], `${workflow[1]}\nTEST_FILES\n${tests.map(([path]) => path).sort().join('\n')}`]
    },
    note: 'CI invokes tests/evaluations and repository contains concrete test/eval artifacts.',
  },
  {
    id: 'repo.supply-chain-lock.v1',
    controlId: 'TR-SUPPLY-001',
    strength: 'E2',
    match(snapshot) {
      return findFile(snapshot, (path, content) =>
        /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock|uv\.lock|requirements\.lock)$/i.test(path) && content.length > 40)
    },
    note: 'Dependency lock/inventory artifact provides repository-level supply-chain provenance.',
  },
  {
    id: 'repo.buyer-assurance-pack.v1',
    controlId: 'TR-BUY-001',
    strength: 'E2',
    match(snapshot) {
      return findFile(snapshot, (path, content) =>
        isDedicated(path, ['TRUST_CENTER.md', 'ASSURANCE.md', 'BUYER_PACK.md']) &&
        hasAny(content, ['evidence', 'proof', 'source']) &&
        hasAny(content, ['unknown', 'limitation', 'not proven', 'gap']))
    },
    note: 'Buyer-facing assurance artifact cites evidence while preserving unknowns/limitations.',
  },
  {
    id: 'repo.evidence-freshness.v1',
    controlId: 'TR-BUY-002',
    strength: 'E2',
    match(snapshot) {
      return findFile(snapshot, (path, content) =>
        isDedicated(path, ['ASSURANCE_MANIFEST.json', 'EVIDENCE_MANIFEST.json', 'TRUST_MANIFEST.json']) &&
        hasAll(content, ['observed_at', 'valid_until']) &&
        hasAny(content, ['sha256', 'hash']))
    },
    note: 'Machine-readable evidence manifest includes freshness/expiry metadata and hashes.',
  },
]

function normalizeMatch(match) {
  if (!match) return null
  if (Array.isArray(match) && match.length === 2 && typeof match[0] === 'string') return match
  return null
}

export function promoteRepositoryEvidence(snapshot) {
  const promoted = []
  for (const rule of PROMOTION_RULES) {
    const match = normalizeMatch(rule.match(snapshot))
    if (!match) continue
    const [path, content] = match
    promoted.push(makeEvidence(snapshot, {
      controlId: rule.controlId,
      filePath: path,
      content,
      strength: rule.strength,
      ruleId: rule.id,
      note: rule.note,
      candidate: false,
      independent: false,
    }))
  }
  return dedupeEvidence(promoted)
}

export function dedupeEvidence(items) {
  const seen = new Set()
  const result = []
  for (const item of items) {
    const key = `${item.evidence_id}:${item.strength}:${item.candidate}`
    if (seen.has(key)) continue
    seen.add(key)
    result.push(item)
  }
  return result
}

export function validateEvidenceProvenance(item) {
  const required = [
    'subject_id',
    'source_path',
    'source_revision',
    'content_sha256',
    'collector_version',
    'promotion_rule_id',
    'promotion_ruleset_version',
  ]
  const missing = required.filter((key) => !item?.provenance?.[key])
  const hashMatches = Boolean(item?.provenance?.content_sha256) && item.provenance.content_sha256 === item.sha256
  return { valid: missing.length === 0 && hashMatches, missing, hashMatches }
}

export function explainProfileGaps(profile, evaluation, evidence) {
  const byId = new Map(evidence.map((item) => [item.evidence_id, item]))
  const controls = new Map(profile.controls.map((item) => [item.id, item]))
  return evaluation.results.map((result) => {
    const control = controls.get(result.control_id)
    const items = result.evidence_ids.map((id) => byId.get(id)).filter(Boolean)
    return {
      control_id: result.control_id,
      title: control?.title || result.control_id,
      status: result.status,
      blocking: result.blocking,
      rule_profile: `${profile.id}@${profile.version}`,
      minimum_strength: control?.minimum_strength || 'E1',
      require_independent: Boolean(control?.require_independent),
      attestation_only: Boolean(control?.attestation_only),
      reason: result.reason,
      evidence: items.map((item) => ({
        evidence_id: item.evidence_id,
        strength: item.strength,
        candidate: Boolean(item.candidate),
        source: item.source,
        observed_at: item.observed_at,
        valid_until: item.valid_until,
        sha256: item.sha256,
        promotion_rule_id: item.provenance?.promotion_rule_id || null,
        ruleset_version: item.provenance?.promotion_ruleset_version || null,
      })),
      next_proof: nextProof(control, result),
      remediation_lane: remediationLane(control, result),
    }
  })
}

function nextProof(control, result) {
  if (['verified', 'attested', 'not_applicable'].includes(result.status)) return null
  if (result.status === 'blocked') return 'Resolve the contradictory evidence, preserve both records, and re-run the deterministic rule.'
  if (control?.attestation_only) return 'Obtain an authenticated, named, authorised attestation for this organisational/legal conclusion.'
  if (control?.require_independent || control?.minimum_strength === 'E3') return 'Provide runtime/deployment observation or independent technical evidence tied to the exact environment.'
  if (control?.minimum_strength === 'E2') return 'Provide code/config/CI or another dedicated machine-verifiable technical artifact that satisfies the promotion rule.'
  return 'Provide a dedicated current policy/document artifact with explicit scope and owner.'
}

function remediationLane(control, result) {
  if (['verified', 'attested', 'not_applicable'].includes(result.status)) return 'none'
  if (result.status === 'blocked') return 'human_security_review'
  if (control?.attestation_only) return 'human_legal_or_accountable_owner'
  if (control?.require_independent || control?.minimum_strength === 'E3') return 'technical_runtime_proof'
  return 'automatable_or_documentable'
}

export function scanRepositorySnapshot(snapshot, profile, { now = new Date(observedAt(snapshot)) } = {}) {
  if (!snapshot?.subject?.id) throw new TypeError('snapshot.subject.id is required')
  if (!snapshot?.revision) throw new TypeError('snapshot.revision is required')
  if (!snapshot?.files || typeof snapshot.files !== 'object') throw new TypeError('snapshot.files is required')

  const candidates = discoverCandidateEvidence(snapshot, profile)
  const promoted = promoteRepositoryEvidence(snapshot)
  const evidence = dedupeEvidence([...candidates, ...promoted])
  const evaluation = evaluateProfile({ profile, evidence, now })
  const provenance = promoted.map((item) => ({ evidence_id: item.evidence_id, ...validateEvidenceProvenance(item) }))

  return {
    schema: 'trustready-scan-v1',
    subject: snapshot.subject,
    repository_url: snapshot.repository_url || null,
    source_revision: snapshot.revision,
    observed_at: observedAt(snapshot),
    collector_version: COLLECTOR_VERSION,
    scanner_ruleset_version: SCANNER_RULESET_VERSION,
    profile: { id: profile.id, version: profile.version },
    evidence,
    evaluation,
    gaps: explainProfileGaps(profile, evaluation, evidence),
    provenance_complete: provenance.every((item) => item.valid),
    provenance_checks: provenance,
    boundary: 'Repository scans can verify only controls whose configured evidence strength can be established from repository artifacts. Runtime, organisational, legal and independent-audit controls remain unresolved until stronger evidence is provided.',
  }
}
