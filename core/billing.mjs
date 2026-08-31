import crypto from 'node:crypto'

export const PLANS = Object.freeze({
  developer: { id: 'developer', monthly_eur: 49, api_units: 500, env_price: 'STRIPE_PRICE_DEVELOPER' },
  team: { id: 'team', monthly_eur: 249, api_units: 5000, env_price: 'STRIPE_PRICE_TEAM' },
})

function b64url(value) {
  return Buffer.from(value).toString('base64url')
}

function fromB64url(value) {
  return Buffer.from(value, 'base64url').toString('utf8')
}

function sign(input, secret) {
  return crypto.createHmac('sha256', secret).update(input).digest('base64url')
}

export function createEntitlementToken({ customer_id, subscription_id, plan, email = null, expires_at }, secret) {
  if (!secret) throw new Error('TRUSTREADY_TOKEN_SECRET is required')
  if (!PLANS[plan]) throw new Error(`Unknown plan: ${plan}`)
  const payload = {
    v: 1,
    sub: customer_id,
    subscription_id,
    plan,
    email,
    exp: Math.floor(new Date(expires_at).getTime() / 1000),
  }
  const encoded = b64url(JSON.stringify(payload))
  return `tr_live_${encoded}.${sign(encoded, secret)}`
}

export function verifyEntitlementToken(token, secret, now = new Date()) {
  if (!secret || !token?.startsWith('tr_live_')) return { valid: false, reason: 'Invalid token format' }
  const raw = token.slice('tr_live_'.length)
  const [encoded, signature] = raw.split('.')
  if (!encoded || !signature) return { valid: false, reason: 'Invalid token format' }
  const expected = sign(encoded, secret)
  const a = Buffer.from(signature)
  const b = Buffer.from(expected)
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { valid: false, reason: 'Invalid token signature' }
  let payload
  try { payload = JSON.parse(fromB64url(encoded)) } catch { return { valid: false, reason: 'Invalid token payload' } }
  if (!PLANS[payload.plan]) return { valid: false, reason: 'Unknown plan' }
  if (!payload.exp || payload.exp <= Math.floor(now.getTime() / 1000)) return { valid: false, reason: 'Token expired' }
  return { valid: true, payload, plan: PLANS[payload.plan] }
}

export function bearerToken(req) {
  const value = req.headers?.authorization || ''
  const match = /^Bearer\s+(.+)$/i.exec(value)
  return match?.[1] || null
}

export function configuredPrice(plan, env = process.env) {
  const config = PLANS[plan]
  if (!config) return null
  return env[config.env_price] || null
}
