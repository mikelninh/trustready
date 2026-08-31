import { configuredPrice, PLANS } from '../../core/billing.mjs'
import { createCheckoutSession } from '../../core/stripe.mjs'

function originFor(req) {
  const configured = process.env.TRUSTREADY_APP_ORIGIN
  if (configured) return configured.replace(/\/$/, '')
  const proto = req.headers?.['x-forwarded-proto'] || 'https'
  const host = req.headers?.host
  if (!host) throw new Error('Cannot determine app origin')
  return `${proto}://${host}`
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST')
    return res.status(405).json({ error: 'Use POST /api/billing/checkout' })
  }
  const { plan, email } = req.body || {}
  if (!PLANS[plan]) return res.status(400).json({ error: 'plan must be developer or team' })
  const price = configuredPrice(plan)
  if (!price) return res.status(503).json({ error: `Billing is not configured for ${plan}. Missing ${PLANS[plan].env_price}.` })
  try {
    const session = await createCheckoutSession({ price_id: price, plan, origin: originFor(req), customer_email: email })
    return res.status(200).json({ checkout_url: session.url, session_id: session.id })
  } catch (error) {
    return res.status(400).json({ error: error.message || 'Checkout creation failed' })
  }
}
