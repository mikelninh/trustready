import { createClient } from 'npm:@supabase/supabase-js@2.112.4'
import { collectPublicGitHubSnapshot } from './lib/github-public.mjs'
import { scanRepositorySnapshot } from './lib/scanner.mjs'
import { verifyAssuranceManifest } from './lib/trust-kernel.mjs'
import {
  PLAN_CATALOG,
  CAPABILITY_UNITS,
  buildRemediationPack,
  compactScanHistory,
  publicScanShape,
} from './lib/commercial.mjs'
import { profile } from './lib/profile.mjs'

type Json = Record<string, unknown>

const FUNCTION_NAME = 'trustready'
const API_VERSION = 'trustready-charge-ready-v1'
const STRIPE_API = 'https://api.stripe.com/v1'
const CLAIM_COOKIE = 'tr_claim'
const CLAIM_TTL_SECONDS = 60 * 60
const API_KEY_PREFIX = 'tr_live_'
const WEBHOOK_TOLERANCE_SECONDS = 300

class HttpError extends Error {
  status: number
  code: string
  details?: unknown
  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message)
    this.status = status
    this.code = code
    this.details = details
  }
}

function env(name: string): string | null {
  return Deno.env.get(name) || null
}

function supabaseSecret(): string {
  const modern = env('SUPABASE_SECRET_KEYS')
  if (modern) {
    try {
      const parsed = JSON.parse(modern)
      if (parsed?.default) return parsed.default
    } catch {
      throw new HttpError(500, 'supabase_secret_invalid', 'SUPABASE_SECRET_KEYS is not valid JSON.')
    }
  }
  const legacy = env('SUPABASE_SERVICE_ROLE_KEY')
  if (legacy) return legacy
  throw new HttpError(500, 'supabase_secret_missing', 'No Supabase backend secret is configured.')
}

const supabaseUrl = env('SUPABASE_URL')
if (!supabaseUrl) throw new Error('SUPABASE_URL is required')
const db = createClient(supabaseUrl, supabaseSecret(), {
  auth: { persistSession: false, autoRefreshToken: false },
})

function corsHeaders(request: Request): HeadersInit {
  const origin = request.headers.get('origin') || '*'
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Headers': 'authorization, content-type, idempotency-key, x-github-token, stripe-signature',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  }
}

function json(request: Request, body: unknown, status = 200, extra: HeadersInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...corsHeaders(request),
      ...extra,
    },
  })
}

function html(request: Request, body: string, status = 200, extra: HeadersInit = {}): Response {
  return new Response(body, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      ...corsHeaders(request),
      ...extra,
    },
  })
}

async function parseJson(request: Request): Promise<Json> {
  try {
    return await request.json()
  } catch {
    throw new HttpError(400, 'invalid_json', 'Request body must be valid JSON.')
  }
}

function pathFor(request: Request): string {
  const url = new URL(request.url)
  const marker = `/functions/v1/${FUNCTION_NAME}`
  const index = url.pathname.indexOf(marker)
  if (index === -1) return url.pathname
  const suffix = url.pathname.slice(index + marker.length)
  return suffix || '/'
}

function baseUrl(request: Request): string {
  const url = new URL(request.url)
  return `${url.origin}/functions/v1/${FUNCTION_NAME}`
}

function cleanEmail(value: unknown): string {
  const email = String(value || '').trim().toLowerCase()
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new HttpError(400, 'invalid_email', 'A valid billing email is required.')
  }
  return email
}

function planFor(value: unknown) {
  const id = String(value || '').toLowerCase()
  const plan = PLAN_CATALOG[id as keyof typeof PLAN_CATALOG]
  if (!plan) throw new HttpError(400, 'invalid_plan', 'Plan must be developer or team.')
  return plan
}

function stripeSecret(): string {
  const key = env('TRUSTREADY_STRIPE_SECRET_KEY') || env('STRIPE_SECRET_KEY')
  if (!key) throw new HttpError(503, 'billing_not_configured', 'Stripe billing is not configured yet.')
  return key
}

function webhookSecret(): string {
  const secret = env('TRUSTREADY_STRIPE_WEBHOOK_SECRET') || env('STRIPE_WEBHOOK_SIGNING_SECRET')
  if (!secret) throw new HttpError(503, 'webhook_not_configured', 'Stripe webhook signing secret is not configured yet.')
  return secret
}

function stripeConfigured(): boolean {
  return Boolean(env('TRUSTREADY_STRIPE_SECRET_KEY') || env('STRIPE_SECRET_KEY'))
}

async function stripeRequest(path: string, options: { method?: string; form?: URLSearchParams } = {}): Promise<any> {
  const headers: HeadersInit = {
    Authorization: `Bearer ${stripeSecret()}`,
  }
  let body: string | undefined
  if (options.form) {
    headers['content-type'] = 'application/x-www-form-urlencoded'
    body = options.form.toString()
  }
  const response = await fetch(`${STRIPE_API}${path}`, {
    method: options.method || (options.form ? 'POST' : 'GET'),
    headers,
    body,
  })
  const text = await response.text()
  let data: any = {}
  try { data = text ? JSON.parse(text) : {} } catch { data = { raw: text } }
  if (!response.ok) {
    const message = data?.error?.message || `Stripe request failed (${response.status}).`
    throw new HttpError(502, 'stripe_error', message)
  }
  return data
}

function randomToken(bytes = 32): string {
  const array = new Uint8Array(bytes)
  crypto.getRandomValues(array)
  return base64Url(array)
}

function base64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

function parseCookies(request: Request): Record<string, string> {
  const result: Record<string, string> = {}
  for (const pair of (request.headers.get('cookie') || '').split(';')) {
    const index = pair.indexOf('=')
    if (index === -1) continue
    result[pair.slice(0, index).trim()] = decodeURIComponent(pair.slice(index + 1).trim())
  }
  return result
}

function claimCookie(value: string): string {
  return `${CLAIM_COOKIE}=${encodeURIComponent(value)}; HttpOnly; Secure; SameSite=Lax; Path=/functions/v1/${FUNCTION_NAME}; Max-Age=${CLAIM_TTL_SECONDS}`
}

function bearer(request: Request): string | null {
  const header = request.headers.get('authorization') || ''
  if (!header.toLowerCase().startsWith('bearer ')) return null
  return header.slice(7).trim()
}

async function findAccountForRawKey(rawKey: string) {
  if (!rawKey.startsWith(API_KEY_PREFIX)) throw new HttpError(401, 'invalid_api_key', 'Invalid TrustReady API key.')
  const keyHash = await sha256Hex(rawKey)
  const { data: keyRow, error: keyError } = await db
    .from('trustready_api_keys')
    .select('id, account_id, key_prefix, revoked_at')
    .eq('key_hash', keyHash)
    .is('revoked_at', null)
    .maybeSingle()
  if (keyError) throw new HttpError(500, 'database_error', 'Could not validate API key.')
  if (!keyRow) throw new HttpError(401, 'invalid_api_key', 'Invalid TrustReady API key.')

  const { data: account, error: accountError } = await db
    .from('trustready_accounts')
    .select('*')
    .eq('id', keyRow.account_id)
    .maybeSingle()
  if (accountError || !account) throw new HttpError(401, 'account_not_found', 'TrustReady account is unavailable.')
  if (!['active', 'trialing'].includes(account.subscription_status)) {
    throw new HttpError(402, 'subscription_inactive', 'Your TrustReady subscription is not active.')
  }
  return { keyHash, keyRow, account }
}

async function requireAccount(request: Request) {
  const rawKey = bearer(request)
  if (!rawKey) throw new HttpError(401, 'api_key_required', 'Use Authorization: Bearer tr_live_…')
  return findAccountForRawKey(rawKey)
}

async function consumeUnits(auth: Awaited<ReturnType<typeof requireAccount>>, capability: keyof typeof CAPABILITY_UNITS, request: Request, metadata: Json = {}) {
  const units = CAPABILITY_UNITS[capability]
  const supplied = request.headers.get('idempotency-key')?.trim()
  const requestId = `${capability}:${supplied || crypto.randomUUID()}`
  const { data, error } = await db.rpc('trustready_consume_units', {
    p_key_hash: auth.keyHash,
    p_units: units,
    p_capability: capability,
    p_request_id: requestId,
    p_metadata: metadata,
  })
  if (error) {
    if (String(error.message).includes('quota_exceeded') || error.code === '22003') {
      throw new HttpError(429, 'quota_exceeded', 'Monthly TrustReady API units exhausted. Upgrade or wait for the next billing period.')
    }
    if (String(error.message).includes('subscription_inactive') || String(error.message).includes('invalid_api_key')) {
      throw new HttpError(402, 'subscription_inactive', 'Subscription or API key is no longer active.')
    }
    throw new HttpError(500, 'usage_ledger_error', 'Could not record API usage.')
  }
  return { ledger: data, requestId, units }
}

async function collectPublic(repositoryUrl: string) {
  const snapshot = await collectPublicGitHubSnapshot(repositoryUrl)
  if (snapshot.collection?.incomplete) {
    throw new HttpError(422, 'incomplete_evidence_collection', 'Evidence collection was incomplete; TrustReady refuses to score it as complete.', snapshot.collection)
  }
  return snapshot
}

function privateGitHubFetch(token: string): typeof fetch {
  return async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    const target = new URL(url)
    if (!['api.github.com', 'raw.githubusercontent.com'].includes(target.hostname)) {
      throw new Error('Private GitHub collector refused an unexpected outbound host.')
    }
    const headers = new Headers(init?.headers || {})
    headers.set('Authorization', `Bearer ${token}`)
    headers.set('X-GitHub-Api-Version', '2022-11-28')
    return fetch(input, { ...init, headers })
  }
}

async function collectPrivate(repositoryUrl: string, token: string) {
  if (!token || token.length < 20) throw new HttpError(400, 'github_token_required', 'X-GitHub-Token is required for private repository scans.')
  try {
    const snapshot = await collectPublicGitHubSnapshot(repositoryUrl, { fetchImpl: privateGitHubFetch(token) })
    if (snapshot.collection?.incomplete) {
      throw new HttpError(422, 'incomplete_evidence_collection', 'Private evidence collection was incomplete; no score was produced.', snapshot.collection)
    }
    return snapshot
  } catch (error) {
    if (error instanceof HttpError) throw error
    throw new HttpError(400, 'private_github_scan_failed', 'Private repository collection failed. The token is used only in memory and was not persisted.')
  }
}

async function saveHistory(accountId: string, requestId: string, repositoryUrl: string, isPrivate: boolean, scan: any) {
  const summary = compactScanHistory(scan, profile)
  const { error } = await db.from('trustready_scan_history').upsert({
    account_id: accountId,
    request_id: requestId,
    repository_url: repositoryUrl,
    is_private: isPrivate,
    source_revision: scan.source_revision,
    profile_id: profile.id,
    profile_version: profile.version,
    score: scan.evaluation.score,
    ready: scan.evaluation.ready,
    summary,
  }, { onConflict: 'request_id' })
  if (error) throw new HttpError(500, 'history_write_failed', 'Scan completed but history could not be recorded.')
}

function subscriptionPeriod(subscription: any): { start: string | null; end: string | null } {
  const items = subscription?.items?.data || []
  const starts = items.map((item: any) => Number(item.current_period_start)).filter(Number.isFinite)
  const ends = items.map((item: any) => Number(item.current_period_end)).filter(Number.isFinite)
  const startSeconds = starts.length ? Math.min(...starts) : Number(subscription?.current_period_start)
  const endSeconds = ends.length ? Math.max(...ends) : Number(subscription?.current_period_end)
  return {
    start: Number.isFinite(startSeconds) ? new Date(startSeconds * 1000).toISOString() : null,
    end: Number.isFinite(endSeconds) ? new Date(endSeconds * 1000).toISOString() : null,
  }
}

async function stripeCustomerEmail(customerId: string): Promise<string | null> {
  const customer = await stripeRequest(`/customers/${encodeURIComponent(customerId)}`)
  return customer?.email ? cleanEmail(customer.email) : null
}

async function reconcileSubscription(subscription: any, fallbackEmail?: string | null) {
  const planId = String(subscription?.metadata?.trustready_plan || '')
  const plan = PLAN_CATALOG[planId as keyof typeof PLAN_CATALOG]
  if (!plan) return null
  const customerId = typeof subscription.customer === 'string' ? subscription.customer : subscription.customer?.id
  if (!customerId) throw new HttpError(502, 'stripe_customer_missing', 'Stripe subscription has no customer.')
  const email = fallbackEmail || await stripeCustomerEmail(customerId)
  if (!email) throw new HttpError(502, 'stripe_email_missing', 'Stripe customer has no billing email.')
  const period = subscriptionPeriod(subscription)

  let account: any = null
  const byCustomer = await db.from('trustready_accounts').select('*').eq('stripe_customer_id', customerId).maybeSingle()
  if (byCustomer.error) throw new HttpError(500, 'database_error', 'Could not read TrustReady account.')
  account = byCustomer.data
  if (!account) {
    const byEmail = await db.from('trustready_accounts').select('*').ilike('email', email).maybeSingle()
    if (byEmail.error) throw new HttpError(500, 'database_error', 'Could not read TrustReady account by email.')
    account = byEmail.data
  }

  const payload = {
    email,
    stripe_customer_id: customerId,
    stripe_subscription_id: subscription.id,
    plan: plan.id,
    subscription_status: subscription.status || 'inactive',
    monthly_unit_limit: plan.monthly_units,
    current_period_start: period.start,
    current_period_end: period.end,
    updated_at: new Date().toISOString(),
  }

  if (account) {
    const updated = await db.from('trustready_accounts').update(payload).eq('id', account.id).select('*').single()
    if (updated.error) throw new HttpError(500, 'account_update_failed', 'Could not update TrustReady account.')
    return updated.data
  }
  const inserted = await db.from('trustready_accounts').insert(payload).select('*').single()
  if (inserted.error) throw new HttpError(500, 'account_create_failed', 'Could not create TrustReady account.')
  return inserted.data
}

async function createCheckout(request: Request): Promise<Response> {
  const body = await parseJson(request)
  const email = cleanEmail(body.email)
  const plan = planFor(body.plan)
  const nonce = randomToken(32)
  const claimHash = await sha256Hex(nonce)
  const returnBase = baseUrl(request)
  const form = new URLSearchParams()
  form.set('mode', 'subscription')
  form.set('customer_email', email)
  form.set('success_url', `${returnBase}?view=success&session_id={CHECKOUT_SESSION_ID}`)
  form.set('cancel_url', `${returnBase}?view=cancel`)
  form.set('client_reference_id', `trustready:${plan.id}`)
  form.set('metadata[trustready_plan]', plan.id)
  form.set('subscription_data[metadata][trustready_plan]', plan.id)
  form.set('line_items[0][quantity]', '1')
  form.set('line_items[0][price_data][currency]', 'eur')
  form.set('line_items[0][price_data][unit_amount]', String(plan.monthly_eur_cents))
  form.set('line_items[0][price_data][recurring][interval]', 'month')
  form.set('line_items[0][price_data][product_data][name]', plan.name)
  form.set('line_items[0][price_data][product_data][description]', plan.description)

  const session = await stripeRequest('/checkout/sessions', { method: 'POST', form })
  const expiresAt = new Date(Date.now() + CLAIM_TTL_SECONDS * 1000).toISOString()
  const { error } = await db.from('trustready_checkout_claims').insert({
    stripe_session_id: session.id,
    claim_hash: claimHash,
    plan: plan.id,
    email,
    expires_at: expiresAt,
  })
  if (error) throw new HttpError(500, 'claim_setup_failed', 'Checkout was created but secure claim setup failed. Do not pay; retry from the pricing page.')

  return json(request, {
    checkout_url: session.url,
    session_id: session.id,
    plan: plan.id,
    amount_eur: plan.monthly_eur_cents / 100,
  }, 200, { 'Set-Cookie': claimCookie(nonce) })
}

async function retrieveCheckoutSession(sessionId: string): Promise<any> {
  if (!/^cs_/.test(sessionId)) throw new HttpError(400, 'invalid_session', 'Invalid Stripe Checkout session id.')
  return stripeRequest(`/checkout/sessions/${encodeURIComponent(sessionId)}?expand[]=subscription`)
}

async function claimPurchase(request: Request): Promise<Response> {
  const body = await parseJson(request)
  const sessionId = String(body.session_id || '')
  const cookie = parseCookies(request)[CLAIM_COOKIE]
  if (!cookie) throw new HttpError(401, 'claim_cookie_missing', 'This purchase must be claimed from the same browser that started Checkout.')
  const claimHash = await sha256Hex(cookie)
  const { data: claim, error: claimError } = await db.from('trustready_checkout_claims').select('*').eq('stripe_session_id', sessionId).maybeSingle()
  if (claimError || !claim) throw new HttpError(401, 'claim_not_found', 'Secure purchase claim was not found.')
  if (claim.claim_hash !== claimHash) throw new HttpError(401, 'claim_mismatch', 'Secure purchase claim does not match this browser.')
  if (new Date(claim.expires_at).getTime() < Date.now()) throw new HttpError(410, 'claim_expired', 'Secure purchase claim expired. Contact support with your Stripe receipt.')

  const session = await retrieveCheckoutSession(sessionId)
  const subscription = typeof session.subscription === 'object' ? session.subscription : await stripeRequest(`/subscriptions/${encodeURIComponent(session.subscription)}`)
  if (session.status !== 'complete' || !['active', 'trialing'].includes(subscription?.status)) {
    throw new HttpError(402, 'subscription_not_active', 'Stripe has not confirmed an active subscription yet.')
  }
  const expectedPlan = claim.plan
  const actualPlan = String(subscription?.metadata?.trustready_plan || session?.metadata?.trustready_plan || '')
  if (actualPlan !== expectedPlan) throw new HttpError(409, 'plan_mismatch', 'Stripe plan metadata does not match the original checkout claim.')
  const sessionEmail = cleanEmail(session?.customer_details?.email || session?.customer_email || claim.email)
  if (sessionEmail !== cleanEmail(claim.email)) throw new HttpError(409, 'email_mismatch', 'Stripe checkout email does not match the secure claim.')

  const account = await reconcileSubscription(subscription, sessionEmail)
  if (!account) throw new HttpError(409, 'unsupported_subscription', 'Subscription is not a TrustReady launch plan.')

  const rawKey = `${API_KEY_PREFIX}${randomToken(32)}`
  const keyHash = await sha256Hex(rawKey)
  const keyPrefix = rawKey.slice(0, 16)
  const existing = await db.from('trustready_api_keys').select('id').eq('source_session_id', sessionId).maybeSingle()
  if (existing.error) throw new HttpError(500, 'api_key_lookup_failed', 'Could not prepare API key.')
  if (existing.data) {
    const rotated = await db.from('trustready_api_keys').update({
      key_hash: keyHash,
      key_prefix: keyPrefix,
      revoked_at: null,
      last_used_at: null,
      label: 'checkout-claim',
    }).eq('id', existing.data.id)
    if (rotated.error) throw new HttpError(500, 'api_key_rotate_failed', 'Could not rotate API key.')
  } else {
    const inserted = await db.from('trustready_api_keys').insert({
      account_id: account.id,
      label: 'checkout-claim',
      key_prefix: keyPrefix,
      key_hash: keyHash,
      source_session_id: sessionId,
    })
    if (inserted.error) throw new HttpError(500, 'api_key_create_failed', 'Could not issue API key.')
  }
  await db.from('trustready_checkout_claims').update({ account_id: account.id, last_claimed_at: new Date().toISOString() }).eq('stripe_session_id', sessionId)

  return json(request, {
    plan: account.plan,
    email: account.email,
    monthly_unit_limit: account.monthly_unit_limit,
    api_key: rawKey,
    warning: 'Copy this API key now. TrustReady stores only its SHA-256 hash. Reclaiming from this browser rotates the previous key.',
    endpoints: {
      paid_scan: `${baseUrl(request)}/scan`,
      private_scan: `${baseUrl(request)}/private-scan`,
      remediation: `${baseUrl(request)}/remediation`,
      account: `${baseUrl(request)}/account`,
      portal: `${baseUrl(request)}/portal`,
      mcp: `${baseUrl(request)}/mcp`,
    },
  }, 200)
}

async function publicScan(request: Request): Promise<Response> {
  const body = request.method === 'GET' ? Object.fromEntries(new URL(request.url).searchParams.entries()) : await parseJson(request)
  const repositoryUrl = String((body as any).repository_url || (body as any).repo || '')
  if (!repositoryUrl) throw new HttpError(400, 'repository_required', 'repository_url is required.')
  const snapshot = await collectPublic(repositoryUrl)
  const scan = scanRepositorySnapshot(snapshot, profile)
  return json(request, { ...publicScanShape(scan, profile), collection_boundary: snapshot.collection?.boundary || null })
}

async function paidScan(request: Request, isPrivate: boolean): Promise<Response> {
  const auth = await requireAccount(request)
  const body = await parseJson(request)
  const repositoryUrl = String(body.repository_url || '')
  if (!repositoryUrl) throw new HttpError(400, 'repository_required', 'repository_url is required.')
  const snapshot = isPrivate
    ? await collectPrivate(repositoryUrl, request.headers.get('x-github-token') || '')
    : await collectPublic(repositoryUrl)
  const scan = scanRepositorySnapshot(snapshot, profile)
  const capability = isPrivate ? 'private_scan' : 'public_scan'
  const usage = await consumeUnits(auth, capability, request, {
    repository_host: 'github.com',
    private: isPrivate,
    source_revision: scan.source_revision,
    score: scan.evaluation.score,
  })
  await saveHistory(auth.account.id, usage.requestId, repositoryUrl, isPrivate, scan)
  return json(request, {
    ...publicScanShape(scan, profile),
    usage: usage.ledger,
    privacy: isPrivate ? 'The GitHub token and repository file contents were used only in memory for this request and are not stored in TrustReady scan history.' : undefined,
  })
}

async function remediation(request: Request): Promise<Response> {
  const auth = await requireAccount(request)
  const body = await parseJson(request)
  const repositoryUrl = String(body.repository_url || '')
  const isPrivate = Boolean(body.private)
  if (!repositoryUrl) throw new HttpError(400, 'repository_required', 'repository_url is required.')
  const snapshot = isPrivate
    ? await collectPrivate(repositoryUrl, request.headers.get('x-github-token') || '')
    : await collectPublic(repositoryUrl)
  const scan = scanRepositorySnapshot(snapshot, profile)
  const pack = buildRemediationPack(scan, profile)
  const usage = await consumeUnits(auth, 'remediation_pack', request, {
    repository_host: 'github.com',
    private: isPrivate,
    source_revision: scan.source_revision,
    score_before: scan.evaluation.score,
    template_count: pack.template_files.length,
    proof_task_count: pack.proof_tasks.length,
  })
  return json(request, {
    ...pack,
    usage: usage.ledger,
    privacy: isPrivate ? 'Private source content and the GitHub token are not persisted by this endpoint.' : undefined,
  })
}

async function accountView(request: Request): Promise<Response> {
  const auth = await requireAccount(request)
  const periodStart = auth.account.current_period_start || new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString()
  const periodEnd = auth.account.current_period_end || new Date(new Date().getFullYear(), new Date().getMonth() + 1, 1).toISOString()
  const usageResult = await db.from('trustready_usage_events').select('units').eq('account_id', auth.account.id).gte('created_at', periodStart).lt('created_at', periodEnd)
  if (usageResult.error) throw new HttpError(500, 'usage_read_failed', 'Could not read usage.')
  const used = (usageResult.data || []).reduce((sum: number, row: any) => sum + Number(row.units || 0), 0)
  const history = await db.from('trustready_scan_history')
    .select('id, repository_url, is_private, source_revision, profile_id, profile_version, score, ready, summary, created_at')
    .eq('account_id', auth.account.id)
    .order('created_at', { ascending: false })
    .limit(20)
  if (history.error) throw new HttpError(500, 'history_read_failed', 'Could not read scan history.')
  return json(request, {
    account: {
      email: auth.account.email,
      plan: auth.account.plan,
      status: auth.account.subscription_status,
      monthly_unit_limit: auth.account.monthly_unit_limit,
      units_used: used,
      units_remaining: Math.max(0, Number(auth.account.monthly_unit_limit) - used),
      current_period_start: periodStart,
      current_period_end: periodEnd,
      key_prefix: auth.keyRow.key_prefix,
    },
    recent_scans: history.data || [],
  })
}

async function billingPortal(request: Request): Promise<Response> {
  const auth = await requireAccount(request)
  if (!auth.account.stripe_customer_id) throw new HttpError(409, 'stripe_customer_missing', 'No Stripe customer is linked to this account.')
  const form = new URLSearchParams()
  form.set('customer', auth.account.stripe_customer_id)
  form.set('return_url', baseUrl(request))
  const portal = await stripeRequest('/billing_portal/sessions', { method: 'POST', form })
  return json(request, { url: portal.url })
}

function stripeSignatureParts(header: string): { timestamp: number; signatures: string[] } {
  let timestamp = 0
  const signatures: string[] = []
  for (const part of header.split(',')) {
    const [key, value] = part.split('=', 2)
    if (key === 't') timestamp = Number(value)
    if (key === 'v1' && value) signatures.push(value)
  }
  return { timestamp, signatures }
}

async function hmacHex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message))
  return [...new Uint8Array(signature)].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

async function verifyStripeWebhook(rawBody: string, signatureHeader: string): Promise<any> {
  const { timestamp, signatures } = stripeSignatureParts(signatureHeader)
  if (!timestamp || signatures.length === 0) throw new HttpError(400, 'invalid_stripe_signature', 'Stripe-Signature header is malformed.')
  if (Math.abs(Math.floor(Date.now() / 1000) - timestamp) > WEBHOOK_TOLERANCE_SECONDS) {
    throw new HttpError(400, 'stale_stripe_signature', 'Stripe webhook timestamp is outside the accepted tolerance.')
  }
  const expected = await hmacHex(webhookSecret(), `${timestamp}.${rawBody}`)
  if (!signatures.some((value) => constantTimeEqual(value, expected))) {
    throw new HttpError(400, 'invalid_stripe_signature', 'Stripe webhook signature verification failed.')
  }
  try { return JSON.parse(rawBody) } catch { throw new HttpError(400, 'invalid_stripe_payload', 'Stripe webhook body is not valid JSON.') }
}

async function recordStripeEvent(event: any, summary: Json = {}) {
  const { error } = await db.from('trustready_stripe_events').insert({
    stripe_event_id: event.id,
    event_type: event.type,
    object_id: event.data?.object?.id || null,
    summary,
  })
  if (error && error.code !== '23505') throw new HttpError(500, 'stripe_event_record_failed', 'Could not record Stripe event.')
}

async function webhook(request: Request): Promise<Response> {
  const raw = await request.text()
  const signature = request.headers.get('stripe-signature') || ''
  const event = await verifyStripeWebhook(raw, signature)
  const existing = await db.from('trustready_stripe_events').select('stripe_event_id').eq('stripe_event_id', event.id).maybeSingle()
  if (existing.error) throw new HttpError(500, 'stripe_event_lookup_failed', 'Could not check Stripe event idempotency.')
  if (existing.data) return json(request, { received: true, duplicate: true })

  let accountId: string | null = null
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object
    if (session.subscription) {
      const subscription = await stripeRequest(`/subscriptions/${encodeURIComponent(typeof session.subscription === 'string' ? session.subscription : session.subscription.id)}`)
      const account = await reconcileSubscription(subscription, session?.customer_details?.email || session?.customer_email || null)
      accountId = account?.id || null
    }
  } else if (['customer.subscription.created', 'customer.subscription.updated', 'customer.subscription.deleted'].includes(event.type)) {
    const account = await reconcileSubscription(event.data.object, null)
    accountId = account?.id || null
  }

  await recordStripeEvent(event, { account_id: accountId })
  return json(request, { received: true })
}

async function manifestVerify(request: Request): Promise<Response> {
  const body = await parseJson(request)
  return json(request, verifyAssuranceManifest(body.manifest || body))
}

function mcpToolDefinitions() {
  return [
    {
      name: 'scan_public_repository',
      description: 'Free read-only TrustReady evidence scan of a public GitHub repository. Candidate evidence never earns verified credit.',
      inputSchema: { type: 'object', properties: { repository_url: { type: 'string' } }, required: ['repository_url'], additionalProperties: false },
      annotations: { readOnlyHint: true },
    },
    {
      name: 'scan_private_repository',
      description: 'Paid private-repository scan. Requires TrustReady API key plus X-GitHub-Token on the HTTP request. Private source content is not persisted.',
      inputSchema: { type: 'object', properties: { repository_url: { type: 'string' } }, required: ['repository_url'], additionalProperties: false },
      annotations: { readOnlyHint: true },
    },
    {
      name: 'generate_remediation_pack',
      description: 'Paid remediation plan with template-only E1/E2 artifacts, E3 runtime proof tasks and E4 attestation tasks. Templates cannot self-promote the score.',
      inputSchema: { type: 'object', properties: { repository_url: { type: 'string' }, private: { type: 'boolean' } }, required: ['repository_url'], additionalProperties: false },
      annotations: { readOnlyHint: true },
    },
    {
      name: 'verify_assurance_manifest',
      description: 'Free cryptographic integrity check of a TrustReady assurance manifest.',
      inputSchema: { type: 'object', properties: { manifest: { type: 'object' } }, required: ['manifest'], additionalProperties: false },
      annotations: { readOnlyHint: true },
    },
  ]
}

async function mcp(request: Request): Promise<Response> {
  const body = await parseJson(request)
  const id = body.id ?? null
  const method = String(body.method || '')
  const ok = (result: unknown) => json(request, { jsonrpc: '2.0', id, result }, 200, { 'MCP-Protocol-Version': '2026-07-01' })
  const fail = (code: number, message: string, data?: unknown) => json(request, { jsonrpc: '2.0', id, error: { code, message, data } }, 200, { 'MCP-Protocol-Version': '2026-07-01' })

  if (method === 'initialize') {
    return ok({ protocolVersion: '2026-07-01', capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'trustready', version: '0.4.0' } })
  }
  if (method === 'notifications/initialized') return new Response(null, { status: 202, headers: corsHeaders(request) })
  if (method === 'tools/list') return ok({ tools: mcpToolDefinitions() })
  if (method !== 'tools/call') return fail(-32601, 'Method not found')

  const params: any = body.params || {}
  const name = String(params.name || '')
  const args = params.arguments || {}
  try {
    if (name === 'scan_public_repository') {
      const snapshot = await collectPublic(String(args.repository_url || ''))
      const scan = scanRepositorySnapshot(snapshot, profile)
      return ok({ content: [{ type: 'text', text: JSON.stringify(publicScanShape(scan, profile)) }] })
    }
    if (name === 'verify_assurance_manifest') {
      return ok({ content: [{ type: 'text', text: JSON.stringify(verifyAssuranceManifest(args.manifest)) }] })
    }
    if (name === 'scan_private_repository') {
      const auth = await requireAccount(request)
      const repositoryUrl = String(args.repository_url || '')
      const snapshot = await collectPrivate(repositoryUrl, request.headers.get('x-github-token') || '')
      const scan = scanRepositorySnapshot(snapshot, profile)
      const usage = await consumeUnits(auth, 'private_scan', request, { mcp: true, private: true, source_revision: scan.source_revision, score: scan.evaluation.score })
      await saveHistory(auth.account.id, usage.requestId, repositoryUrl, true, scan)
      return ok({ content: [{ type: 'text', text: JSON.stringify({ ...publicScanShape(scan, profile), usage: usage.ledger }) }] })
    }
    if (name === 'generate_remediation_pack') {
      const auth = await requireAccount(request)
      const repositoryUrl = String(args.repository_url || '')
      const isPrivate = Boolean(args.private)
      const snapshot = isPrivate ? await collectPrivate(repositoryUrl, request.headers.get('x-github-token') || '') : await collectPublic(repositoryUrl)
      const scan = scanRepositorySnapshot(snapshot, profile)
      const pack = buildRemediationPack(scan, profile)
      const usage = await consumeUnits(auth, 'remediation_pack', request, { mcp: true, private: isPrivate, source_revision: scan.source_revision, score_before: scan.evaluation.score })
      return ok({ content: [{ type: 'text', text: JSON.stringify({ ...pack, usage: usage.ledger }) }] })
    }
    return fail(-32602, `Unknown tool: ${name}`)
  } catch (error) {
    const err = error instanceof HttpError ? error : new HttpError(500, 'internal_error', 'Tool execution failed.')
    return ok({ isError: true, content: [{ type: 'text', text: JSON.stringify({ error: err.code, message: err.message }) }] })
  }
}

function landingPage(request: Request): string {
  const url = new URL(request.url)
  const view = url.searchParams.get('view') || 'home'
  const sessionId = url.searchParams.get('session_id') || ''
  const base = baseUrl(request)
  const billingState = stripeConfigured() ? 'Live checkout configured' : 'Checkout code deployed — Stripe secret not configured yet'
  const escapedSession = sessionId.replaceAll('\\', '\\\\').replaceAll('`', '\\`').replaceAll('${', '\\${')
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TrustReady — Evidence-backed AI readiness</title>
<style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;color:#101114;background:#f6f7f9}*{box-sizing:border-box}body{margin:0}.wrap{max-width:1050px;margin:auto;padding:28px}.nav{display:flex;justify-content:space-between;align-items:center;margin-bottom:60px}.brand{font-weight:800;font-size:20px}.pill{padding:8px 12px;border-radius:999px;background:#e9ebef;font-size:12px}.hero{max-width:800px}.kicker{font-size:12px;letter-spacing:.14em;font-weight:800}.hero h1{font-size:clamp(42px,7vw,76px);line-height:.95;margin:16px 0}.hero p{font-size:19px;line-height:1.55;color:#555;max-width:680px}.panel{background:white;border:1px solid #dedfe3;border-radius:18px;padding:24px;margin-top:26px;box-shadow:0 10px 35px rgba(0,0,0,.05)}input,button,textarea{font:inherit}input{width:100%;padding:14px 16px;border:1px solid #ccc;border-radius:11px;background:white}button{border:0;border-radius:11px;padding:13px 18px;font-weight:750;cursor:pointer;background:#111;color:white}.secondary{background:#eef0f3;color:#111}.row{display:flex;gap:10px}.row>*{flex:1}.pricing{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;margin-top:22px}.price{background:white;border:1px solid #dedfe3;border-radius:18px;padding:24px}.price strong{font-size:38px}.muted{color:#696b70}.result{white-space:pre-wrap;background:#0f1115;color:#e9edf3;border-radius:12px;padding:16px;overflow:auto;max-height:480px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}.score{font-size:48px;font-weight:850}.hidden{display:none}.ok{color:#087b41}@media(max-width:720px){.pricing,.row{grid-template-columns:1fr;display:grid}.nav{margin-bottom:35px}}
</style></head><body><div class="wrap"><div class="nav"><div class="brand">TrustReady</div><div class="pill">${billingState}</div></div>
<div class="hero"><div class="kicker">EVIDENCE-BACKED AI PROCUREMENT READINESS</div><h1>Make every trust claim inspectable.</h1><p>Scan → prove → remediate → re-scan. Payment buys collection and remediation work, never a better score.</p></div>
<div class="panel"><h2>Free public scan</h2><div class="row"><input id="repo" value="https://github.com/mikelninh/trustready"><button onclick="scanPublic()">Scan repository</button></div><div id="scanout" style="margin-top:18px"></div></div>
<div class="pricing"><div class="price"><div class="kicker">DEVELOPER</div><strong>€49</strong><span class="muted"> / month</span><p>500 API units, paid scan history, remediation packs, API/MCP access.</p><button onclick="buy('developer')">Choose Developer</button></div><div class="price"><div class="kicker">TEAM</div><strong>€249</strong><span class="muted"> / month</span><p>5,000 API units for teams and higher-volume remediation/procurement workflows.</p><button onclick="buy('team')">Choose Team</button></div></div>
<div class="panel"><h2>Billing email</h2><input id="email" type="email" placeholder="you@company.com"><p class="muted">Stripe-hosted Checkout. Cancel or update payment details through Stripe Customer Portal.</p></div>
<div id="claim" class="panel ${view === 'success' ? '' : 'hidden'}"><h2>Activate your paid API</h2><p>Payment is verified directly with Stripe before an API key is issued.</p><button onclick="claimPurchase()">Verify payment & issue API key</button><div id="claimout" style="margin-top:18px"></div></div>
<div class="panel"><h2>Use your API key</h2><input id="apikey" type="password" placeholder="tr_live_…"><div class="row" style="margin-top:10px"><button class="secondary" onclick="loadAccount()">Account & usage</button><button class="secondary" onclick="openPortal()">Manage billing</button></div><div id="accountout" style="margin-top:18px"></div></div>
<p class="muted" style="margin:50px 0">100/100 means every control in the selected profile has accepted evidence or authorised attestation. It does not mean universal legal compliance, certification, zero risk or government approval.</p></div>
<script>
const BASE=${JSON.stringify(base)};const SESSION=\`${escapedSession}\`;
async function api(path,options={}){const r=await fetch(BASE+path,{headers:{'content-type':'application/json',...(options.headers||{})},...options});const t=await r.text();let d;try{d=JSON.parse(t)}catch{d={raw:t}}if(!r.ok)throw new Error(d.message||d.error||('HTTP '+r.status));return d}
async function scanPublic(){const out=document.getElementById('scanout');out.textContent='Scanning…';try{const d=await api('/public-scan',{method:'POST',body:JSON.stringify({repository_url:document.getElementById('repo').value})});out.innerHTML='<div class="score">'+Math.round(d.score)+'/100</div><p>'+d.controls.filter(x=>!['verified','attested','not_applicable'].includes(x.status)).length+' unresolved controls · '+d.blocking_findings.length+' blocking findings</p><div class="result">'+escapeHtml(JSON.stringify(d.path_to_100,null,2))+'</div>'}catch(e){out.textContent=e.message}}
async function buy(plan){try{const d=await api('/checkout',{method:'POST',body:JSON.stringify({plan,email:document.getElementById('email').value})});location.href=d.checkout_url}catch(e){alert(e.message)}}
async function claimPurchase(){const out=document.getElementById('claimout');out.textContent='Verifying with Stripe…';try{const d=await api('/claim',{method:'POST',body:JSON.stringify({session_id:SESSION})});document.getElementById('apikey').value=d.api_key;sessionStorage.setItem('trustready_api_key',d.api_key);out.innerHTML='<p class="ok"><strong>Activated.</strong> Copy the key below now.</p><div class="result">'+escapeHtml(d.api_key)+'</div><p>'+escapeHtml(d.warning)+'</p>'}catch(e){out.textContent=e.message}}
function key(){return document.getElementById('apikey').value||sessionStorage.getItem('trustready_api_key')||''}
async function loadAccount(){const out=document.getElementById('accountout');out.textContent='Loading…';try{const d=await api('/account',{headers:{authorization:'Bearer '+key()}});out.innerHTML='<div class="result">'+escapeHtml(JSON.stringify(d,null,2))+'</div>'}catch(e){out.textContent=e.message}}
async function openPortal(){try{const d=await api('/portal',{method:'POST',headers:{authorization:'Bearer '+key()},body:'{}'});location.href=d.url}catch(e){alert(e.message)}}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]))}
if(sessionStorage.getItem('trustready_api_key'))document.getElementById('apikey').value=sessionStorage.getItem('trustready_api_key');
</script></body></html>`
}

async function handler(request: Request): Promise<Response> {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(request) })
  const path = pathFor(request)
  if (path === '/' && request.method === 'GET') return html(request, landingPage(request))
  if (path === '/health' && request.method === 'GET') return json(request, { ok: true, version: API_VERSION, stripe_configured: stripeConfigured(), webhook_configured: Boolean(env('TRUSTREADY_STRIPE_WEBHOOK_SECRET') || env('STRIPE_WEBHOOK_SIGNING_SECRET')), profile: `${profile.id}@${profile.version}` })
  if (path === '/checkout' && request.method === 'POST') return createCheckout(request)
  if (path === '/claim' && request.method === 'POST') return claimPurchase(request)
  if (path === '/public-scan' && ['GET', 'POST'].includes(request.method)) return publicScan(request)
  if (path === '/scan' && request.method === 'POST') return paidScan(request, false)
  if (path === '/private-scan' && request.method === 'POST') return paidScan(request, true)
  if (path === '/remediation' && request.method === 'POST') return remediation(request)
  if (path === '/account' && request.method === 'GET') return accountView(request)
  if (path === '/portal' && request.method === 'POST') return billingPortal(request)
  if (path === '/webhook' && request.method === 'POST') return webhook(request)
  if (path === '/manifests/verify' && request.method === 'POST') return manifestVerify(request)
  if (path === '/mcp' && request.method === 'POST') return mcp(request)
  throw new HttpError(404, 'not_found', 'TrustReady endpoint not found.')
}

Deno.serve(async (request) => {
  try {
    return await handler(request)
  } catch (error) {
    const err = error instanceof HttpError ? error : new HttpError(500, 'internal_error', 'Unexpected TrustReady error.')
    console.error(JSON.stringify({ code: err.code, status: err.status, message: err.message }))
    return json(request, { error: err.code, message: err.message, details: err.details || undefined }, err.status)
  }
})
