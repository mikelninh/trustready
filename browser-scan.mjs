export const BROWSER_SCANNER_RULESET_VERSION = 'browser-scanner-2026.08.1'
export const BROWSER_COLLECTOR_VERSION = 'github-public-browser-v1'

const MAX_FILE_BYTES = 128_000
const MAX_FILES = 120
const DAY_MS = 24 * 60 * 60 * 1000

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

function parseRepoUrl(input) {
  const url = new URL(input)
  if (!['github.com', 'www.github.com'].includes(url.hostname)) throw new Error('Only public github.com repository URLs are supported in browser mode.')
  const parts = url.pathname.split('/').filter(Boolean)
  if (parts.length < 2) throw new Error('GitHub URL must include owner/repository.')
  return { owner: parts[0], repo: parts[1].replace(/\.git$/, ''), canonical: `https://github.com/${parts[0]}/${parts[1].replace(/\.git$/, '')}` }
}

function relevantPath(path) {
  const lower = path.toLowerCase()
  if (/^(readme|security|privacy|trust|assurance|limitations|architecture|data[_-]?flow|subprocessors?|processors?|vendors?|model[_-]?(vendor[_-]?)?inventory|ai[_-]?act|human[_-]?oversight|retention|incident|runbook|owners?)\.(md|txt|json|ya?ml)$/i.test(path)) return true
  if (lower.startsWith('docs/') && /(security|privacy|trust|assurance|limitation|architecture|data|processor|vendor|model|ai|oversight|retention|incident|runbook|owner)/.test(lower)) return true
  if (lower.startsWith('.github/workflows/') && /\.ya?ml$/.test(lower)) return true
  if (/(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock|uv\.lock|requirements\.lock)$/.test(lower)) return true
  if (/(^|\/)(test|tests|eval|evals|benchmark|benchmarks)(\/|\.)/.test(lower)) return /\.(mjs|js|ts|py|json|md|ya?ml)$/.test(lower)
  if (/\.(test|spec)\.(mjs|js|ts|py)$/.test(lower)) return true
  if (/(^|\/)(assurance|evidence|trust)[_-]?manifest\.json$/.test(lower)) return true
  return false
}

async function fetchJson(url) {
  const response = await fetch(url, { headers: { accept: 'application/vnd.github+json' } })
  if (!response.ok) throw new Error(`GitHub API request failed (${response.status}). You may have hit GitHub's anonymous API rate limit.`)
  return response.json()
}

async function fetchText(url) {
  const response = await fetch(url, { headers: { accept: 'text/plain' } })
  if (!response.ok) throw new Error(`GitHub raw file request failed (${response.status}).`)
  return response.text()
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(String(value))
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

async function collectFiles(items, parsed, revision, concurrency = 8) {
  const files = {}
  const errors = []
  let cursor = 0
  async function worker() {
    while (cursor < items.length) {
      const item = items[cursor++]
      const raw = `https://raw.githubusercontent.com/${parsed.owner}/${parsed.repo}/${revision}/${item.path}`
      try { files[item.path] = await fetchText(raw) }
      catch (error) { errors.push({ path: item.path, error: error.message }) }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, Math.max(1, items.length)) }, worker))
  return { files, errors }
}

export async function collectPublicGitHubInBrowser(input) {
  const parsed = parseRepoUrl(input)
  const repo = await fetchJson(`https://api.github.com/repos/${parsed.owner}/${parsed.repo}`)
  const branch = repo.default_branch || 'main'
  const commit = await fetchJson(`https://api.github.com/repos/${parsed.owner}/${parsed.repo}/commits/${encodeURIComponent(branch)}`)
  const revision = commit.sha
  const tree = await fetchJson(`https://api.github.com/repos/${parsed.owner}/${parsed.repo}/git/trees/${revision}?recursive=1`)
  if (tree.truncated) throw new Error('GitHub returned a truncated repository tree. TrustReady refuses to score an incomplete snapshot.')
  const selected = (tree.tree || [])
    .filter((item) => item.type === 'blob' && Number(item.size || 0) <= MAX_FILE_BYTES && relevantPath(item.path))
    .sort((a,b) => a.path.localeCompare(b.path))
    .slice(0, MAX_FILES)
  const { files, errors } = await collectFiles(selected, parsed, revision)
  if (errors.length) throw new Error(`Evidence collection was incomplete (${errors.length} file${errors.length === 1 ? '' : 's'} failed). TrustReady refuses to convert missing fetches into a score.`)
  return {
    subject: { id: `${parsed.owner}/${parsed.repo}`.toLowerCase(), name: repo.name || parsed.repo, url: repo.html_url || parsed.canonical, description: repo.description || null },
    repository_url: parsed.canonical,
    revision,
    observed_at: new Date().toISOString(),
    files,
    files_selected: selected.length,
  }
}

function entries(snapshot) { return Object.entries(snapshot.files || {}).map(([path, content]) => [path, String(content || '')]) }
function lower(value) { return String(value || '').toLowerCase() }
function hasAny(value, terms) { const h = lower(value); return terms.some((t) => h.includes(t.toLowerCase())) }
function hasAll(value, terms) { const h = lower(value); return terms.every((t) => h.includes(t.toLowerCase())) }
function isDedicated(path, names) { const p = lower(path); return names.some((n) => p === lower(n) || p.endsWith(`/${lower(n)}`)) }
function findFile(snapshot, fn) { return entries(snapshot).find(([p,c]) => fn(p,c)) || null }
function findFiles(snapshot, fn) { return entries(snapshot).filter(([p,c]) => fn(p,c)) }

const PROMOTION_RULES = [
  { id:'repo.product-purpose.v1', controlId:'TR-GOV-001', strength:'E1', match:s=>findFile(s,(p,c)=>isDedicated(p,['README.md','PRODUCT.md','SYSTEM_PURPOSE.md'])&&c.length>=120&&hasAny(c,['purpose','what it does','intended','for ','users','workflow'])) },
  { id:'repo.model-inventory.v1', controlId:'TR-AI-001', strength:'E2', match:s=>findFile(s,(p,c)=>isDedicated(p,['MODEL_VENDOR_INVENTORY.md','MODEL_INVENTORY.md','AI_INVENTORY.json'])&&hasAny(c,['model','provider'])&&hasAny(c,['version','purpose','data','vendor'])) },
  { id:'repo.limitations.v1', controlId:'TR-AI-004', strength:'E1', match:s=>findFile(s,(p,c)=>isDedicated(p,['README.md','LIMITATIONS.md','ASSURANCE.md'])&&hasAny(c,['limitations','not proven','does not','non-goal','prohibited'])) },
  { id:'repo.data-flow.v1', controlId:'TR-DATA-001', strength:'E2', match:s=>findFile(s,(p,c)=>isDedicated(p,['DATA_FLOW.md','DATAFLOW.md','ARCHITECTURE.md'])&&hasAny(c,['input','ingest'])&&hasAny(c,['storage','database','persist'])&&hasAny(c,['output','delete','retention','processor'])) },
  { id:'repo.subprocessors.v1', controlId:'TR-DATA-002', strength:'E2', match:s=>findFile(s,(p,c)=>isDedicated(p,['SUBPROCESSORS.md','PROCESSORS.md','VENDORS.md'])&&hasAny(c,['processor','subprocessor','vendor'])&&hasAny(c,['purpose','service','data'])) },
  { id:'repo.security-intake.v1', controlId:'TR-SEC-002', strength:'E2', match:s=>findFile(s,(p,c)=>isDedicated(p,['SECURITY.md'])&&hasAny(c,['report','contact','email','security@'])&&hasAny(c,['vulnerability','security issue','security'])) },
  { id:'repo.evaluation-evidence.v1', controlId:'TR-OPS-002', strength:'E2', match:s=>{ const w=findFile(s,(p,c)=>p.startsWith('.github/workflows/')&&hasAny(c,['node --test','pytest','eval','test'])); const tests=findFiles(s,p=>/(^|\/)(test|tests|evals?|benchmarks?)(\/|\.)/i.test(p)||/\.(test|spec)\.(mjs|js|ts|py)$/i.test(p)); return w&&tests.length?[w[0],`${w[1]}\nTEST_FILES\n${tests.map(([p])=>p).sort().join('\n')}`]:null } },
  { id:'repo.supply-chain-lock.v1', controlId:'TR-SUPPLY-001', strength:'E2', match:s=>findFile(s,(p,c)=>(/(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock|uv\.lock|requirements\.lock)$/i.test(p)&&c.length>40)) },
  { id:'repo.buyer-assurance-pack.v1', controlId:'TR-BUY-001', strength:'E2', match:s=>findFile(s,(p,c)=>isDedicated(p,['TRUST_CENTER.md','ASSURANCE.md','BUYER_PACK.md'])&&hasAny(c,['evidence','proof','source'])&&hasAny(c,['unknown','limitation','not proven','gap'])) },
  { id:'repo.evidence-freshness.v1', controlId:'TR-BUY-002', strength:'E2', match:s=>findFile(s,(p,c)=>isDedicated(p,['ASSURANCE_MANIFEST.json','EVIDENCE_MANIFEST.json','TRUST_MANIFEST.json'])&&hasAll(c,['observed_at','valid_until'])&&hasAny(c,['sha256','hash'])) },
]

function firstCandidate(snapshot, controlId) {
  const terms = CANDIDATE_TERMS[controlId] || []
  return entries(snapshot).find(([,content]) => hasAny(content, terms)) || null
}

function nextProof(control, status) {
  if (['verified','attested','not_applicable'].includes(status)) return null
  if (control.attestation_only) return 'Obtain an authenticated, named, authorised attestation for this organisational/legal conclusion.'
  if (control.require_independent || control.minimum_strength === 'E3') return 'Provide runtime/deployment observation or independent technical evidence tied to the exact environment.'
  if (control.minimum_strength === 'E2') return 'Provide code/config/CI or another dedicated machine-verifiable technical artifact that satisfies the promotion rule.'
  return 'Provide a dedicated current policy/document artifact with explicit scope and owner.'
}

function remediationLane(control, status) {
  if (['verified','attested','not_applicable'].includes(status)) return 'none'
  if (control.attestation_only) return 'human_legal_or_accountable_owner'
  if (control.require_independent || control.minimum_strength === 'E3') return 'technical_runtime_proof'
  return 'automatable_or_documentable'
}

export async function scanSnapshotInBrowser(snapshot, profile) {
  const promoted = new Map()
  for (const rule of PROMOTION_RULES) {
    const match = rule.match(snapshot)
    if (!match) continue
    const [path, content] = match
    promoted.set(rule.controlId, {
      strength: rule.strength,
      source: `${snapshot.repository_url}/blob/${snapshot.revision}/${path}`,
      observed_at: snapshot.observed_at,
      valid_until: new Date(new Date(snapshot.observed_at).getTime() + 90 * DAY_MS).toISOString(),
      sha256: await sha256(content),
      promotion_rule_id: rule.id,
      ruleset_version: BROWSER_SCANNER_RULESET_VERSION,
    })
  }

  const controls = profile.controls.map((control) => {
    const proof = promoted.get(control.id)
    const candidate = firstCandidate(snapshot, control.id)
    let status = 'not_observed'
    let reason = 'No accepted evidence observed.'
    const evidence = []
    if (proof && !control.attestation_only && !control.require_independent && control.minimum_strength !== 'E3') {
      status = 'verified'
      reason = 'Accepted repository evidence satisfies the deterministic public-source rule.'
      evidence.push(proof)
    } else if (candidate) {
      status = 'candidate'
      reason = control.attestation_only
        ? 'Candidate evidence exists, but this conclusion requires an authorised E4 attestation.'
        : (control.require_independent || control.minimum_strength === 'E3')
          ? 'Candidate evidence exists, but repository source cannot prove deployed runtime behaviour.'
          : 'Candidate evidence was discovered but does not satisfy the deterministic promotion rule.'
      evidence.push({ strength:'E0', source:`${snapshot.repository_url}/blob/${snapshot.revision}/${candidate[0]}`, observed_at:snapshot.observed_at, valid_until:new Date(new Date(snapshot.observed_at).getTime()+30*DAY_MS).toISOString(), candidate:true })
    }
    const satisfied = status === 'verified'
    const lane = control.attestation_only ? 'E4' : ((control.require_independent || control.minimum_strength === 'E3') ? 'E3' : 'E1/E2')
    return {
      ...control,
      status,
      reason,
      points: satisfied ? 5 : 0,
      potential_points: satisfied ? 0 : 5,
      lane,
      next_proof: nextProof(control, status),
      remediation_lane: remediationLane(control, status),
      evidence,
    }
  })

  const verified = controls.filter((c) => c.status === 'verified').length
  const covered = controls.filter((c) => c.status !== 'not_observed').length
  const score = Math.round((verified / controls.length) * 10000) / 100
  let cursor = score
  const phaseDefs = [
    ['E1/E2','Build missing evidence','Dedicated documents, inventories, CI/eval proof and buyer evidence that can be checked deterministically.'],
    ['E4','Authorised human attestation','Organisational/legal claims that TrustReady must never self-attest.'],
    ['E3','Prove deployed behaviour','Environment-bound runtime tests and independent observations. Repository text cannot satisfy these.'],
  ]
  const path_to_100 = phaseDefs.map(([lane,title,description]) => {
    const unresolved = controls.filter((c) => c.lane === lane && c.status !== 'verified')
    const gain = unresolved.length * 5
    const from = cursor
    const to = Math.min(100, cursor + gain)
    cursor = to
    return { id:lane, lane, title, description, controls:unresolved, gain, from, to }
  })

  return {
    schema:'trustready-public-browser-scan-v1',
    subject:snapshot.subject,
    profile:{ id:profile.id, version:profile.version, title:profile.title },
    score,
    coverage_pct:Math.round((covered / controls.length) * 10000) / 100,
    ready:score === 100,
    source_revision:snapshot.revision,
    observed_at:snapshot.observed_at,
    provenance_complete:controls.filter(c=>c.status==='verified').every(c=>c.evidence.every(e=>e.sha256&&e.source&&e.promotion_rule_id&&e.ruleset_version)),
    blocking_findings:controls.filter(c=>c.blocking&&c.status!=='verified').map(c=>c.id),
    controls,
    path_to_100,
    boundary:'Public-repository evidence scan only. Runtime, organisational, legal and independent-audit controls remain unresolved until stronger evidence is supplied. This is not certification, a legal opinion, or a security guarantee.',
    collection_boundary:'Browser mode reads only public GitHub repository evidence. Source files are fetched directly from GitHub into your browser; they are not uploaded to TrustReady.',
  }
}

export async function scanPublicGitHubInBrowser(repoUrl, profileUrl = './profiles/core-ai-procurement-2026.08.json') {
  const profileResponse = await fetch(profileUrl)
  if (!profileResponse.ok) throw new Error('Could not load the versioned TrustReady profile.')
  const profile = await profileResponse.json()
  const snapshot = await collectPublicGitHubInBrowser(repoUrl)
  return scanSnapshotInBrowser(snapshot, profile)
}
