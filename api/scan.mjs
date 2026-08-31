import fs from 'node:fs'
import { collectPublicGitHubSnapshot } from '../collectors/github-public.mjs'
import { scanRepositorySnapshot } from '../core/scanner.mjs'
import { publicScanShape } from '../core/commercial.mjs'

const profile = JSON.parse(fs.readFileSync(new URL('../profiles/core-ai-procurement-2026.08.json', import.meta.url), 'utf8'))

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

    res.setHeader('Cache-Control', 'public, s-maxage=300, stale-while-revalidate=600')
    return res.status(200).json({
      ...publicScanShape(scan, profile),
      collection_boundary: snapshot.collection?.boundary || null,
    })
  } catch (error) {
    return res.status(400).json({ error: error.message || 'Scan failed' })
  }
}
