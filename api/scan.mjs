import fs from 'node:fs'
import { collectPublicGitHubSnapshot } from '../collectors/github-public.mjs'
import { scanRepositorySnapshot } from '../core/scanner.mjs'

const profile = JSON.parse(fs.readFileSync(new URL('../profiles/core-ai-procurement-2026.08.json', import.meta.url), 'utf8'))
const POINTS_PER_CONTROL = 100 / profile.controls.length

function buildRoadmap(scan) {
  const resultById = new Map(scan.evaluation.results.map((item) => [item.control_id, item]))
  const gapById = new Map(scan.gaps.map((item) => [item.control_id, item]))
  const phases = [
    { id: 'build-evidence', title: 'Build missing evidence', lane: 'E1/E2', description: 'Dedicated documents, inventories, CI/eval proof and buyer evidence that can be checked deterministically.', controls: [] },
    { id: 'human-attestation', title: 'Authorised human attestation', lane: 'E4', description: 'Organisational/legal claims that TrustReady must never self-attest.', controls: [] },
    { id: 'runtime-proof', title: 'Prove deployed behaviour', lane: 'E3', description: 'Environment-bound runtime tests and independent observations. Repository text cannot satisfy these.', controls: [] },
  ]

  const controls = profile.controls.map((control) => {
    const result = resultById.get(control.id)
    const gap = gapById.get(control.id)
    const satisfied = ['verified', 'attested', 'not_applicable'].includes(result.status)
    const lane = control.attestation_only ? 'E4' : (control.require_independent || control.minimum_strength === 'E3' ? 'E3' : 'E1/E2')
    const row = {
      ...control,
      status: result.status,
      reason: result.reason,
      points: satisfied ? POINTS_PER_CONTROL : 0,
      potential_points: satisfied ? 0 : POINTS_PER_CONTROL,
      lane,
      next_proof: gap?.next_proof || null,
      remediation_lane: gap?.remediation_lane || 'none',
      evidence: gap?.evidence || [],
    }
    if (!satisfied) {
      const phase = lane === 'E4' ? phases[1] : lane === 'E3' ? phases[2] : phases[0]
      phase.controls.push(row)
    }
    return row
  })

  let cursor = scan.evaluation.score
  const path = phases.map((phase) => {
    const gain = phase.controls.length * POINTS_PER_CONTROL
    const from = cursor
    const to = Math.min(100, cursor + gain)
    cursor = to
    return { ...phase, from, to, gain }
  })

  return { controls, path }
}

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET')
    return res.status(405).json({ error: 'Use GET /api/scan?repo=https://github.com/owner/repo' })
  }

  const repo = Array.isArray(req.query?.repo) ? req.query.repo[0] : req.query?.repo
  if (!repo) return res.status(400).json({ error: 'repo query parameter is required' })

  try {
    const snapshot = await collectPublicGitHubSnapshot(repo)
    if (snapshot.collection?.incomplete) {
      return res.status(422).json({
        error: 'Evidence collection was incomplete. TrustReady refuses to score an incomplete repository snapshot as complete evidence.',
        collection: snapshot.collection,
      })
    }
    const scan = scanRepositorySnapshot(snapshot, profile)
    const roadmap = buildRoadmap(scan)

    res.setHeader('Cache-Control', 'public, s-maxage=300, stale-while-revalidate=600')
    return res.status(200).json({
      schema: 'trustready-public-scan-api-v1',
      subject: scan.subject,
      profile: { id: profile.id, version: profile.version, title: profile.title },
      score: scan.evaluation.score,
      coverage_pct: scan.evaluation.coverage_pct,
      ready: scan.evaluation.ready,
      source_revision: scan.source_revision,
      observed_at: scan.observed_at,
      provenance_complete: scan.provenance_complete,
      blocking_findings: scan.evaluation.blocking_findings,
      controls: roadmap.controls,
      path_to_100: roadmap.path,
      boundary: scan.boundary,
      collection_boundary: snapshot.collection?.boundary || null,
    })
  } catch (error) {
    return res.status(400).json({ error: error.message || 'Scan failed' })
  }
}
