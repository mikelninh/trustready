const API = 'https://api.stripe.com/v1'

function secret(env = process.env) {
  if (!env.STRIPE_SECRET_KEY) throw new Error('STRIPE_SECRET_KEY is not configured')
  return env.STRIPE_SECRET_KEY
}

function formEncode(value, prefix, out = new URLSearchParams()) {
  if (value === undefined || value === null) return out
  if (Array.isArray(value)) {
    value.forEach((item, i) => formEncode(item, `${prefix}[${i}]`, out))
  } else if (typeof value === 'object') {
    Object.entries(value).forEach(([key, item]) => formEncode(item, prefix ? `${prefix}[${key}]` : key, out))
  } else {
    out.append(prefix, String(value))
  }
  return out
}

export async function stripeRequest(path, { method = 'GET', body, env = process.env } = {}) {
  const options = {
    method,
    headers: {
      Authorization: `Bearer ${secret(env)}`,
      'Stripe-Version': '2026-06-24',
    },
  }
  if (body) {
    options.headers['Content-Type'] = 'application/x-www-form-urlencoded'
    options.body = formEncode(body, '').toString()
  }
  const response = await fetch(`${API}${path}`, options)
  const data = await response.json()
  if (!response.ok) throw new Error(data?.error?.message || `Stripe request failed (${response.status})`)
  return data
}

export async function createCheckoutSession({ price_id, plan, amount_eur, origin, customer_email }, env = process.env) {
  const lineItem = price_id
    ? { price: price_id, quantity: 1 }
    : {
        quantity: 1,
        price_data: {
          currency: 'eur',
          unit_amount: Math.round(Number(amount_eur) * 100),
          recurring: { interval: 'month' },
          product_data: {
            name: `TrustReady ${plan[0].toUpperCase()}${plan.slice(1)}`,
            description: 'Evidence-backed AI procurement readiness machine access',
            metadata: { trustready_plan: plan },
          },
        },
      }

  return stripeRequest('/checkout/sessions', {
    method: 'POST', env,
    body: {
      mode: 'subscription',
      line_items: [lineItem],
      success_url: `${origin}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${origin}/#pricing`,
      customer_email: customer_email || undefined,
      allow_promotion_codes: true,
      subscription_data: { metadata: { trustready_plan: plan } },
      metadata: { trustready_plan: plan },
    },
  })
}

export async function retrieveCheckoutSession(sessionId, env = process.env) {
  return stripeRequest(`/checkout/sessions/${encodeURIComponent(sessionId)}?expand[]=subscription&expand[]=customer`, { env })
}

export async function retrieveSubscription(subscriptionId, env = process.env) {
  return stripeRequest(`/subscriptions/${encodeURIComponent(subscriptionId)}`, { env })
}

export async function createBillingPortalSession(customerId, returnUrl, env = process.env) {
  return stripeRequest('/billing_portal/sessions', { method: 'POST', env, body: { customer: customerId, return_url: returnUrl } })
}
