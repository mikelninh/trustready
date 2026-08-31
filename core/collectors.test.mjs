import assert from 'node:assert/strict'
import test from 'node:test'
import { readFile } from 'node:fs/promises'

import { collectPublicGitHubSnapshot, parseGitHubRepositoryUrl } from '../collectors/github-public.mjs'
import { collectPublicUrlEvidence } from '../collectors/url-public.mjs'
import { scanEvidenceBundle } from './scan-bundle.mjs'

const profile = JSON.parse(await readFile(new URL('../profiles/core-ai-procurement-2026.08.json', import.meta.url), 'utf8'))

function response(status, body, { json = false, url = 'https://example.test/' } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    url,
    async json() { return json ? body : JSON.parse(body) },
    async text() { return json ? JSON.stringify(body) : body },
  }
}

test('public GitHub collector pins evidence to immutable commit revision', async () => {
  assert.deepEqual(parseGitHubRepositoryUrl('https://github.com/acme/agent.git'), {
    owner: 'acme',
    repo: 'agent',
    canonicalUrl: 'https://github.com/acme/agent',
  })

  const fetchImpl = async (url) => {
    if (url === 'https://api.github.com/repos/acme/agent') {
      return response(200, { name: 'agent', description: 'AI support agent', default_branch: 'main', html_url: 'https://github.com/acme/agent' }, { json: true })
    }
    if (url === 'https://api.github.com/repos/acme/agent/commits/main') {
      return response(200, { sha: 'deadbeef1234567890' }, { json: true })
    }
    if (url === 'https://api.github.com/repos/acme/agent/git/trees/deadbeef1234567890?recursive=1') {
      return response(200, { truncated: false, tree: [
        { type: 'blob', path: 'README.md', size: 200, sha: 'r1' },
        { type: 'blob', path: 'MODEL_VENDOR_INVENTORY.md', size: 200, sha: 'm1' },
        { type: 'blob', path: 'large.bin', size: 999999, sha: 'x1' },
      ] }, { json: true })
    }
    if (url === 'https://raw.githubusercontent.com/acme/agent/deadbeef1234567890/README.md') {
      return response(200, '# Agent\n\nPurpose: draft support replies for trained users. The intended workflow keeps final authority with operators and documents important limitations.')
    }
    if (url === 'https://raw.githubusercontent.com/acme/agent/deadbeef1234567890/MODEL_VENDOR_INVENTORY.md') {
      return response(200, '# Models\nProvider: ExampleAI\nModel: v3\nVersion: 3\nPurpose: drafting\nData: minimised text')
    }
    throw new Error(`Unexpected URL ${url}`)
  }

  const snapshot = await collectPublicGitHubSnapshot('https://github.com/acme/agent', {
    fetchImpl,
    observedAt: new Date('2026-08-31T12:00:00Z'),
  })
  assert.equal(snapshot.revision, 'deadbeef1234567890')
  assert.equal(snapshot.collection.incomplete, false)
  assert.equal(snapshot.collection.files_collected, 2)
  assert.ok(snapshot.files['MODEL_VENDOR_INVENTORY.md'])
})

test('GitHub collector fails closed on truncated repository tree', async () => {
  const fetchImpl = async (url) => {
    if (url.endsWith('/repos/acme/huge')) return response(200, { name: 'huge', default_branch: 'main' }, { json: true })
    if (url.endsWith('/commits/main')) return response(200, { sha: 'abc' }, { json: true })
    if (url.includes('/git/trees/abc')) return response(200, { truncated: true, tree: [] }, { json: true })
    throw new Error(`Unexpected URL ${url}`)
  }
  await assert.rejects(() => collectPublicGitHubSnapshot('https://github.com/acme/huge', { fetchImpl }), /tree was truncated/i)
})

test('deployed URL collector promotes only explicit visible AI disclosure', async () => {
  const positive = await collectPublicUrlEvidence('https://app.example.test/', {
    subjectId: 'acme/app',
    observedAt: new Date('2026-08-31T12:00:00Z'),
    fetchImpl: async () => response(200, '<html><body><p>You are interacting with an AI system.</p></body></html>', { url: 'https://app.example.test/' }),
  })
  assert.equal(positive.evidence.length, 1)
  assert.equal(positive.evidence[0].strength, 'E3')
  assert.equal(positive.evidence[0].independent, true)
  assert.deepEqual(positive.evidence[0].control_ids, ['TR-AI-003'])

  const vague = await collectPublicUrlEvidence('https://app.example.test/', {
    subjectId: 'acme/app',
    observedAt: new Date('2026-08-31T12:00:00Z'),
    fetchImpl: async () => response(200, '<html><body><p>AI-powered productivity for everyone.</p></body></html>', { url: 'https://app.example.test/' }),
  })
  assert.equal(vague.evidence.length, 0)
})

test('evidence bundle keeps repository claims separate from externally observed runtime proof', async () => {
  const snapshot = {
    subject: { id: 'acme/app', name: 'App' },
    repository_url: 'https://github.com/acme/app',
    revision: 'deadbeef',
    observed_at: '2026-08-31T12:00:00Z',
    files: {
      'README.md': '# App\n\nPurpose: an AI support assistant for trained users. Human approval is required and an AI disclosure appears in the product.',
    },
  }
  const runtime = await collectPublicUrlEvidence('https://app.example.test/', {
    subjectId: 'acme/app',
    observedAt: new Date('2026-08-31T12:00:00Z'),
    fetchImpl: async () => response(200, '<html><body>You are interacting with an AI system.</body></html>', { url: 'https://app.example.test/' }),
  })
  const scan = scanEvidenceBundle({ snapshot, externalEvidence: runtime.evidence, profile })
  assert.equal(scan.provenance_complete, true)
  assert.equal(scan.evaluation.results.find((item) => item.control_id === 'TR-AI-003').status, 'verified')
  assert.notEqual(scan.evaluation.results.find((item) => item.control_id === 'TR-AI-002').status, 'verified')
  assert.equal(scan.evidence_summary.external_runtime_accepted, 1)
})
