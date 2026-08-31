import fs from 'node:fs'
import { bearerToken, verifyEntitlementToken } from '../../core/billing.mjs'
import { retrieveSubscription } from '../../core/stripe.mjs'
import { collectPublicGitHubSnapshot } from '../../collectors/github-public.mjs'
import { scanRepositorySnapshot } from '../../core/scanner.mjs'

const profile = JSON.parse(fs.readFileSync(new URL('../../profiles/core-ai-procurement-2026.08.json', import.meta.url), 'utf8'))

export default async function handler(req, res) {
  if (req.method !== 'GET') { res.setHeader('Allow', 'GET'); return res.status(405).json({ error: 'Use GET' }) }
  const checked = verifyEntitlementToken(bearerToken(req), process.env.TRUSTREADY_TOKEN_SECRET)
  if (!checked.valid) return res.status(401).json({ error: checked.reason })
  try {
    const subscription = await retrieveSubscription(checked.payload.subscription_id)
    if (!['active','trialing'].includes(subscription.status)) return res.status(402).json({ error: `Subscription ${subscription.status}` })
    const repo = Array.isArray(req.query?.repo) ? req.query.repo[0] : req.query?.repo
    if (!repo) return res.status(400).json({ error: 'repo query parameter is required' })
    const snapshot = await collectPublicGitHubSnapshot(repo)
    if (snapshot.collection?.incomplete) return res.status(422).json({ error: 'Evidence collection incomplete', collection: snapshot.collection })
    const scan = scanRepositorySnapshot(snapshot, profile)
    console.log(JSON.stringify({ event: 'trustready.api_unit', customer_id: checked.payload.sub, plan: checked.payload.plan, units: 1, operation: 'scan', at: new Date().toISOString() }))
    res.setHeader('Cache-Control', 'no-store')
    res.setHeader('X-TrustReady-Unit-Cost', '1')
    res.setHeader('X-TrustReady-Plan', checked.payload.plan)
    return res.status(200).json({ ...scan, commercial: { plan: checked.payload.plan, unit_cost: 1, included_monthly_units: checked.plan.api_units } })
  } catch (error) {
    return res.status(400).json({ error: error.message || 'Paid scan failed' })
  }
}
