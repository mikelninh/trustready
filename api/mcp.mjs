import { bearerToken, verifyEntitlementToken } from '../core/billing.mjs'
import { retrieveSubscription } from '../core/stripe.mjs'
import { trustReadyMcpHandler } from '../mcp/server.mjs'

export default async function handler(req, res) {
  const checked = verifyEntitlementToken(bearerToken(req), process.env.TRUSTREADY_TOKEN_SECRET)
  if (!checked.valid) return res.status(401).json({ error: checked.reason })
  try {
    const subscription = await retrieveSubscription(checked.payload.subscription_id)
    if (!['active', 'trialing'].includes(subscription.status)) return res.status(402).json({ error: `Subscription ${subscription.status}` })
    console.log(JSON.stringify({ event: 'trustready.api_unit', customer_id: checked.payload.sub, plan: checked.payload.plan, units: 1, operation: 'mcp', at: new Date().toISOString() }))
    return trustReadyMcpHandler(req, res)
  } catch (error) {
    return res.status(400).json({ error: error.message || 'MCP request failed' })
  }
}
