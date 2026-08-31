import { sha256 } from './trust-kernel.mjs'

export const GITHUB_PUBLIC_COLLECTOR_VERSION = 'github-public-v1'

const MAX_FILE_BYTES = 128_000
const MAX_FILES = 120

export function parseGitHubRepositoryUrl(input) {
  let url
  try {
    url = new URL(input)
  } catch {
    throw new TypeError('A valid GitHub repository URL is required')
  }
  if (!['github.com', 'www.github.com'].includes(url.hostname)) throw new TypeError('Only github.com repository URLs are supported')
  const parts = url.pathname.split('/').filter(Boolean)
  if (parts.length < 2) throw new TypeError('GitHub URL must include owner/repository')
  const owner = parts[0]
  const repo = parts[1].replace(/\.git$/, '')
  return { owner, repo, canonicalUrl: `https://github.com/${owner}/${repo}` }
}

async function fetchJson(url, fetchImpl) {
  const response = await fetchImpl(url, { headers: { accept: 'application/vnd.github+json', 'user-agent': 'trustready-scanner' } })
  if (!response.ok) throw new Error(`GitHub API request failed (${response.status}): ${url}`)
  return response.json()
}

async function fetchText(url, fetchImpl) {
  const response = await fetchImpl(url, { headers: { accept: 'text/plain', 'user-agent': 'trustready-scanner' } })
  if (!response.ok) throw new Error(`GitHub raw request failed (${response.status}): ${url}`)
  return response.text()
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

function selectBlobs(tree) {
  return tree
    .filter((item) => item.type === 'blob' && item.size <= MAX_FILE_BYTES && relevantPath(item.path))
    .sort((a, b) => a.path.localeCompare(b.path))
    .slice(0, MAX_FILES)
}

export async function collectPublicGitHubSnapshot(inputUrl, { fetchImpl = globalThis.fetch, observedAt = new Date() } = {}) {
  if (typeof fetchImpl !== 'function') throw new TypeError('fetch implementation is required')
  const parsed = parseGitHubRepositoryUrl(inputUrl)
  const repo = await fetchJson(`https://api.github.com/repos/${parsed.owner}/${parsed.repo}`, fetchImpl)
  const defaultBranch = repo.default_branch || 'main'
  const commit = await fetchJson(`https://api.github.com/repos/${parsed.owner}/${parsed.repo}/commits/${encodeURIComponent(defaultBranch)}`, fetchImpl)
  const revision = commit.sha
  if (!revision) throw new Error('GitHub commit response did not include sha')
  const tree = await fetchJson(`https://api.github.com/repos/${parsed.owner}/${parsed.repo}/git/trees/${revision}?recursive=1`, fetchImpl)
  if (tree.truncated) throw new Error('GitHub tree was truncated; scanner refuses to treat an incomplete repository tree as complete evidence')
  const selected = selectBlobs(tree.tree || [])
  const files = {}
  const collectionErrors = []

  for (const item of selected) {
    const raw = `https://raw.githubusercontent.com/${parsed.owner}/${parsed.repo}/${revision}/${item.path}`
    try {
      files[item.path] = await fetchText(raw, fetchImpl)
    } catch (error) {
      collectionErrors.push({ path: item.path, error: error.message })
    }
  }

  return {
    subject: {
      id: `${parsed.owner}/${parsed.repo}`.toLowerCase(),
      name: repo.name || parsed.repo,
      url: repo.html_url || parsed.canonicalUrl,
      description: repo.description || null,
    },
    repository_url: parsed.canonicalUrl,
    revision,
    observed_at: observedAt.toISOString(),
    files,
    collection: {
      collector_version: GITHUB_PUBLIC_COLLECTOR_VERSION,
      default_branch: defaultBranch,
      repository_tree_sha256: sha256((tree.tree || []).map((item) => [item.path, item.sha, item.size, item.type])),
      files_selected: selected.length,
      files_collected: Object.keys(files).length,
      collection_errors: collectionErrors,
      incomplete: collectionErrors.length > 0,
      boundary: 'Only repository evidence is collected. Absence from GitHub is not proof that an organisational, deployment or private control does not exist elsewhere.',
    },
  }
}
