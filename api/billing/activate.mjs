import { createEntitlementToken, PLANS } from '../../core/billing.mjs'
import { retrieveCheckoutSession } from '../../core/stripe.mjs'

function subscriptionStatus(session) {
  const sub = typeof session.subscription === 'object' ? session.subscription : null
  return sub?.status || null
}

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET')
    return res.status(405).json({ error: 'Use GET /api/billing/activate?session_id=...' })
  }
  const sessionId = Array.isArray(req.query?.session_id) ? req.query.session_id[0] : req.query?.session_id
  if (!sessionId) return res.status(400).json({ error: 'session_id is required' })
  if (!process.env.TRUSTREADY_TOKEN_SECRET) return res.status(503).json({ error: 'Entitlement signing is not configured' })

  try {
    const session = await retrieveCheckoutSession(sessionId)
    const plan = session.metadata?.trustready_plan || session.subscription?.metadata?.trustready_plan
    if (!PLANS[plan]) return res.status(403).json({ error: 'Checkout session is not a TrustReady paid plan' })
    const status = subscriptionStatus(session)
    if (!['active', 'trialing'].includes(status)) return res.status(402).json({ error: `Subscription is not active (${status || 'unknown'})` })
    const customerId = typeof session.customer === 'object' ? session.customer.id : session.customer
    const subscriptionId = typeof session.subscription === 'object' ? session.subscription.id : session.subscription
    const email = session.customer_details?.email || session.customer?.email || null
    const expires = new Date(Date.now() + 24 * 60 * 60 * 1000)
    const token = createEntitlementToken({ customer_id: customerId, subscription_id: subscriptionId, plan, email, expires_at: expires }, process.env.TRUSTREADY_TOKEN_SECRET)
    res.setHeader('Cache-Control', 'no-store')
    return res.status(200).json({ plan, api_units: PLANS[plan].api_units, token, token_expires_at: expires.toISOString(), customer_id: customerId, subscription_id: subscriptionId })
  } catch (error) {
    return res.status(400).json({ error: error.message || 'Activation failed' })
  }
}
