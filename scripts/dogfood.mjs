#!/usr/bin/env node

import { mkdir, writeFile, readFile } from 'node:fs/promises'
import path from 'node:path'

import { collectPublicGitHubSnapshot } from '../collectors/github-public.mjs'
import { scanRepositorySnapshot } from '../core/scanner.mjs'

const profile = JSON.parse(await readFile(new URL('../profiles/core-ai-procurement-2026.08.json', import.meta.url), 'utf8'))

const TARGETS = [
  { id: 'digital-worker-factory', name: 'Digital Worker Factory', repo: 'https://github.com/mikelninh/digital-worker-factory' },
  { id: 'pruefpilot', name: 'PrüfPilot', repo: 'https://github.com/mikelninh/pruefpilot' },
  { id: 'gitlaw', name: 'GitLaw', repo: 'https://github.com/mikelninh/gitlaw' },
  { id: 'trustready', name: 'TrustReady', repo: 'https://github.com/mikelninh/trustready' },
]

function deriveHausPilot(factorySnapshot) {
  const files = Object.fromEntries(Object.entries(factorySnapshot.files).filter(([file]) => file.toLowerCase().includes('hauspilot')))
  return {
    ...factorySnapshot,
    subject: {
      id: 'hauspilot',
      name: 'HausPilot',
      url: 'https://github.com/mikelninh/digital-worker-factory/tree/main/packs/hauspilot',
    },
    files,
    collection: {
      ...factorySnapshot.collection,
      derived_subject: true,
      derived_from: factorySnapshot.subject.id,
      boundary: 'HausPilot is currently a product/module inside Digital Worker Factory. This derived public scan intentionally excludes Factory-wide evidence unless it was collected from a HausPilot path.',
    },
  }
}

function summarize(scan) {
  const counts = Object.fromEntries(['verified', 'attested', 'partial', 'candidate', 'not_observed', 'stale', 'blocked', 'not_applicable'].map((status) => [status, 0]))
  for (const result of scan.evaluation.results) counts[result.status] = (counts[result.status] || 0) + 1
  const unresolved = scan.gaps
    .filter((item) => !['verified', 'attested', 'not_applicable'].includes(item.status))
    .sort((a, b) => Number(b.blocking) - Number(a.blocking))
  return {
    subject: scan.subject,
    source_revision: scan.source_revision,
    public_repository_score: scan.evaluation.score,
    ready: scan.evaluation.ready,
    counts,
    provenance_complete: scan.provenance_complete,
    blocking_findings: scan.evaluation.blocking_findings,
    top_gaps: unresolved.slice(0, 8).map((item) => ({
      control_id: item.control_id,
      title: item.title,
      status: item.status,
      blocking: item.blocking,
      next_proof: item.next_proof,
      remediation_lane: item.remediation_lane,
    })),
    boundary: 'This is a public-repository evidence scan, not a claim of legal compliance, certification, production security or complete product readiness.',
  }
}

const outputDir = process.argv[2] || null
const scans = []
let factorySnapshot = null

for (const target of TARGETS) {
  const snapshot = await collectPublicGitHubSnapshot(target.repo)
  snapshot.subject.id = target.id
  snapshot.subject.name = target.name
  if (target.id === 'digital-worker-factory') factorySnapshot = snapshot
  scans.push(scanRepositorySnapshot(snapshot, profile))
}

if (factorySnapshot) scans.splice(1, 0, scanRepositorySnapshot(deriveHausPilot(factorySnapshot), profile))

const report = {
  schema: 'trustready-dogfood-report-v1',
  generated_at: new Date().toISOString(),
  profile: { id: profile.id, version: profile.version },
  products: scans.map(summarize),
  truth_boundary: 'Scores represent only controls satisfied by accepted public repository evidence under the selected profile. Runtime/organisational/legal controls remain unresolved until stronger evidence is supplied.',
}

if (outputDir) {
  await mkdir(outputDir, { recursive: true })
  await writeFile(path.join(outputDir, 'dogfood-report.json'), JSON.stringify(report, null, 2) + '\n', 'utf8')
  for (const scan of scans) {
    await writeFile(path.join(outputDir, `${scan.subject.id}-scan.json`), JSON.stringify(scan, null, 2) + '\n', 'utf8')
  }
}

console.log(JSON.stringify(report, null, 2))
