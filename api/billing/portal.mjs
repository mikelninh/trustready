import { bearerToken, verifyEntitlementToken } from '../../core/billing.mjs'
import { createBillingPortalSession } from '../../core/stripe.mjs'

function originFor(req) {
  if (process.env.TRUSTREADY_APP_ORIGIN) return process.env.TRUSTREADY_APP_ORIGIN.replace(/\/$/, '')
  const proto = req.headers?.['x-forwarded-proto'] || 'https'
  return `${proto}://${req.headers.host}`
}

export default async function handler(req, res) {
  if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return res.status(405).json({ error: 'Use POST' }) }
  const checked = verifyEntitlementToken(bearerToken(req), process.env.TRUSTREADY_TOKEN_SECRET)
  if (!checked.valid) return res.status(401).json({ error: checked.reason })
  try {
    const session = await createBillingPortalSession(checked.payload.sub, `${originFor(req)}/success.html`)
    return res.status(200).json({ url: session.url })
  } catch (error) {
    return res.status(400).json({ error: error.message || 'Portal creation failed' })
  }
}
