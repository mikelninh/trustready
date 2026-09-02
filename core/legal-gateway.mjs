import crypto from 'node:crypto'

export const DATA_ZONES = Object.freeze({ PUBLIC: 0, INTERNAL: 1, PERSONAL: 2, MANDATE: 3, RESTRICTED: 4 })

export function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`
  }
  return JSON.stringify(value)
}

export function sha256(value) {
  return crypto.createHash('sha256').update(typeof value === 'string' ? value : canonicalize(value)).digest('hex')
}

function requireIsoDate(value, field) {
  const ms = Date.parse(value)
  if (!value || Number.isNaN(ms)) throw new TypeError(`${field} must be a valid date`)
  return ms
}

function signBytes(privateKey, value) {
  return crypto.sign(null, Buffer.from(canonicalize(value)), privateKey).toString('base64')
}

function verifyBytes(publicKey, value, signature) {
  try { return crypto.verify(null, Buffer.from(canonicalize(value)), publicKey, Buffer.from(signature, 'base64')) } catch { return false }
}

function isMandateZone(zone) { return DATA_ZONES[zone] >= DATA_ZONES.MANDATE }

export function signProviderPassport({ body, private_key, key_id }) {
  if (!body?.provider_id || !private_key || !key_id) throw new TypeError('body.provider_id, private_key and key_id are required')
  return { body, signature: { algorithm: 'Ed25519', key_id, value: signBytes(private_key, body) } }
}

export function verifyProviderPassport({ passport, trusted_keys, now = new Date() }) {
  const body = passport?.body
  const sig = passport?.signature
  if (!body || !sig || sig.algorithm !== 'Ed25519') return { valid: false, reason: 'signed provider passport required' }
  const publicKey = trusted_keys?.[sig.key_id]
  if (!publicKey) return { valid: false, reason: 'provider-passport signer is not trusted' }
  if (!verifyBytes(publicKey, body, sig.value)) return { valid: false, reason: 'provider-passport signature invalid' }
  if (body.status !== 'approved') return { valid: false, reason: 'provider is not approved' }
  if (requireIsoDate(body.valid_until, 'valid_until') <= now.getTime()) return { valid: false, reason: 'provider passport expired' }
  if (body.training_on_customer_data !== false) return { valid: false, reason: 'training on customer data must be disabled' }
  if (!body.use_cases || typeof body.use_cases !== 'object') return { valid: false, reason: 'use-case policies missing' }
  return { valid: true, body, signer_key_id: sig.key_id }
}

const DIRECT_IDENTIFIER_KEYS = /(^|_)(name|email|address|phone|mobile|iban|bic|account|birth|dob|passport|id_number|client_name|mandant_name)($|_)/i

function payloadBytes(payload) { return Buffer.byteLength(canonicalize(payload), 'utf8') }

export function evaluateEgress({ request, passport, trusted_keys, now = new Date() }) {
  const deny = (code, reason) => ({ allowed: false, code, reason, decided_at: now.toISOString() })
  if (!request || typeof request !== 'object') return deny('INVALID_REQUEST', 'request is required')
  if (!(request.zone in DATA_ZONES)) return deny('UNKNOWN_ZONE', 'unknown data classification')
  if (!request.tenant_id || !request.provider_id || !request.use_case || !request.purpose) return deny('CONTEXT_REQUIRED', 'tenant, provider, use case and purpose are required')
  if (isMandateZone(request.zone) && !request.matter_id) return deny('MATTER_REQUIRED', 'matter identity is required for mandate data')

  const verified = verifyProviderPassport({ passport, trusted_keys, now })
  if (!verified.valid) return deny('PROVIDER_NOT_APPROVED', verified.reason)
  const provider = verified.body
  if (provider.provider_id !== request.provider_id) return deny('PROVIDER_MISMATCH', 'provider identity mismatch')

  const policy = provider.use_cases[request.use_case]
  if (!policy) return deny('USE_CASE_DENIED', 'use case is not approved')
  if (!Array.isArray(policy.allowed_zones) || !policy.allowed_zones.includes(request.zone)) return deny('ZONE_DENIED', 'data zone is not approved for use case')

  if (isMandateZone(request.zone) && !request.region) return deny('REGION_REQUIRED', 'explicit processing region required for mandate data')
  if (request.region && (!Array.isArray(policy.regions) || !policy.regions.includes(request.region))) return deny('REGION_DENIED', 'processing region is not approved')

  const retention = request.retention_minutes ?? 0
  if (!Number.isInteger(retention) || retention < 0) return deny('RETENTION_INVALID', 'retention must be a non-negative integer')
  if (!Number.isInteger(policy.max_retention_minutes) || retention > policy.max_retention_minutes) return deny('RETENTION_EXCEEDED', 'requested retention exceeds use-case policy')

  if (isMandateZone(request.zone)) {
    if (provider.avv_status !== 'approved') return deny('AVV_REQUIRED', 'AVV/DPA approval missing')
    if (provider.brao_43e_status !== 'approved') return deny('BRAO43E_REQUIRED', '§43e service-provider approval missing')
    if (provider.subprocessor_status !== 'approved') return deny('SUBPROCESSOR_REQUIRED', 'subprocessor chain not approved')
    if (provider.third_country === true && provider.transfer_safeguards_status !== 'approved') return deny('TRANSFER_SAFEGUARDS_REQUIRED', 'third-country safeguards not approved')
  }

  if (!request.payload || typeof request.payload !== 'object' || Array.isArray(request.payload)) return deny('PAYLOAD_REQUIRED', 'structured payload is required')
  const fields = Object.keys(request.payload).sort()
  if (!Array.isArray(policy.allowed_fields)) return deny('FIELD_POLICY_REQUIRED', 'allowed-field policy missing')
  const disallowed = fields.filter((field) => !policy.allowed_fields.includes(field))
  if (disallowed.length) return deny('FIELD_DENIED', `payload contains unapproved fields: ${disallowed.join(', ')}`)
  if (policy.allow_direct_identifiers !== true) {
    const identifiers = fields.filter((field) => DIRECT_IDENTIFIER_KEYS.test(field))
    if (identifiers.length) return deny('DIRECT_IDENTIFIER_DENIED', `direct identifiers forbidden: ${identifiers.join(', ')}`)
  }
  const bytes = payloadBytes(request.payload)
  if (!Number.isInteger(policy.max_payload_bytes) || bytes > policy.max_payload_bytes) return deny('PAYLOAD_TOO_LARGE', 'payload exceeds maximum size')

  return {
    allowed: true,
    code: 'ALLOW',
    decision_id: crypto.randomUUID(),
    tenant_id: request.tenant_id,
    matter_id: request.matter_id || null,
    provider_id: request.provider_id,
    use_case: request.use_case,
    purpose: request.purpose,
    zone: request.zone,
    region: request.region || null,
    retention_minutes: retention,
    payload_fields: fields,
    payload_bytes: bytes,
    payload_fingerprint: `sha256:${sha256(request.payload)}`,
    provider_passport_signer: verified.signer_key_id,
    policy_version: request.policy_version || null,
    decided_at: now.toISOString(),
  }
}

function approvalBody(input) {
  return {
    capability_id: input.capability_id,
    actor_id: input.actor_id,
    actor_session_id: input.actor_session_id,
    tenant_id: input.tenant_id,
    matter_id: input.matter_id || null,
    action: input.action,
    payload_hash: input.payload_hash,
    auth_context: input.auth_context,
    policy_version: input.policy_version || null,
    issued_at: input.issued_at,
    expires_at: input.expires_at,
    nonce: input.nonce,
  }
}

export function issueApprovalCapability({ actor_id, actor_session_id, tenant_id, matter_id, action, payload, auth_context, policy_version, expires_at, private_key, key_id, now = new Date() }) {
  if (!actor_id || !actor_session_id || !tenant_id || !action || !private_key || !key_id) throw new TypeError('approval identity, action and signing key are required')
  if (auth_context?.mfa !== true) throw new Error('MFA-authenticated approval context required')
  const expiresMs = requireIsoDate(expires_at, 'expires_at')
  if (expiresMs <= now.getTime()) throw new Error('approval expiry must be in the future')
  if (expiresMs - now.getTime() > 5 * 60 * 1000) throw new Error('approval lifetime exceeds 5 minutes')
  const body = approvalBody({
    capability_id: crypto.randomUUID(), actor_id, actor_session_id, tenant_id, matter_id, action,
    payload_hash: `sha256:${sha256(payload)}`, auth_context: { mfa: true, method: auth_context.method || null, auth_time: auth_context.auth_time || null },
    policy_version, issued_at: now.toISOString(), expires_at, nonce: crypto.randomBytes(32).toString('hex'),
  })
  return { body, signature: { algorithm: 'Ed25519', key_id, value: signBytes(private_key, body) } }
}

export function verifyApprovalCapability({ capability, expected, trusted_keys, now = new Date() }) {
  const body = capability?.body
  const sig = capability?.signature
  if (!body || !sig || sig.algorithm !== 'Ed25519') return { valid: false, reason: 'signed approval capability required' }
  const publicKey = trusted_keys?.[sig.key_id]
  if (!publicKey || !verifyBytes(publicKey, body, sig.value)) return { valid: false, reason: 'approval signature invalid or signer untrusted' }
  if (requireIsoDate(body.expires_at, 'expires_at') <= now.getTime()) return { valid: false, reason: 'approval expired' }
  if (body.auth_context?.mfa !== true) return { valid: false, reason: 'approval is not MFA-bound' }
  for (const field of ['actor_id', 'actor_session_id', 'tenant_id', 'action']) {
    if (body[field] !== expected[field]) return { valid: false, reason: `${field} mismatch` }
  }
  if ((body.matter_id || null) !== (expected.matter_id || null)) return { valid: false, reason: 'matter_id mismatch' }
  if (body.payload_hash !== `sha256:${sha256(expected.payload)}`) return { valid: false, reason: 'payload changed after approval' }
  return { valid: true, capability_id: body.capability_id, nonce: body.nonce }
}

export async function consumeApprovalCapability({ capability, expected, trusted_keys, consume_nonce, now = new Date() }) {
  const verified = verifyApprovalCapability({ capability, expected, trusted_keys, now })
  if (!verified.valid) return verified
  if (typeof consume_nonce !== 'function') return { valid: false, reason: 'durable atomic replay protection is required' }
  const consumed = await consume_nonce({ capability_id: verified.capability_id, nonce: verified.nonce, expires_at: capability.body.expires_at })
  if (consumed !== true) return { valid: false, reason: 'approval capability already consumed or replay store unavailable' }
  return { valid: true, consumed: true, capability_id: verified.capability_id }
}

function unsafeEvidenceKey(key) {
  if (/(?:_hash|_fingerprint|_count|_type|_id)$/.test(key)) return false
  return /(prompt|body|content|document|secret|token|password|authorization|api.?key|credential|raw|email|address|phone|iban)/i.test(key)
}
function unsafeEvidenceString(value) {
  return /-----BEGIN .*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~-]+|\bsk-[A-Za-z0-9_-]{12,}|\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b/.test(value)
}
function assertSafeEvidenceValue(value, path = 'metadata') {
  if (typeof value === 'string') { if (unsafeEvidenceString(value)) throw new Error(`secret/identifier-like value forbidden in evidence metadata: ${path}`); return }
  if (Array.isArray(value)) { value.forEach((item, i) => assertSafeEvidenceValue(item, `${path}[${i}]`)); return }
  if (!value || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) {
    if (unsafeEvidenceKey(key)) throw new Error(`raw/sensitive field forbidden in evidence metadata: ${path}.${key}`)
    assertSafeEvidenceValue(child, `${path}.${key}`)
  }
}

export function appendEvidenceEvent({ previous_hash = null, sequence, event }) {
  if (!Number.isInteger(sequence) || sequence < 1) throw new TypeError('positive sequence is required')
  if (!event?.event_type || !event?.occurred_at || !event?.tenant_id) throw new TypeError('event_type, occurred_at and tenant_id are required')
  requireIsoDate(event.occurred_at, 'occurred_at')
  assertSafeEvidenceValue(event.metadata || {})
  const body = {
    schema: 'trustready-legal-evidence-event-v1', sequence, previous_hash,
    event_type: event.event_type, occurred_at: event.occurred_at, tenant_id: event.tenant_id,
    matter_id: event.matter_id || null, actor_id: event.actor_id || null, policy_version: event.policy_version || null,
    metadata: event.metadata || {},
  }
  return { ...body, event_hash: `sha256:${sha256(body)}` }
}

export function verifyEvidenceChain(events) {
  let previous = null
  let expectedSequence = 1
  for (const event of events) {
    const { event_hash, ...body } = event
    if (body.sequence !== expectedSequence) return { valid: false, reason: 'evidence sequence gap/reorder detected' }
    if (body.previous_hash !== previous) return { valid: false, reason: 'broken previous_hash link' }
    if (`sha256:${sha256(body)}` !== event_hash) return { valid: false, reason: 'event hash mismatch' }
    previous = event_hash; expectedSequence += 1
  }
  return { valid: true, head_hash: previous, events: events.length }
}

export function signEvidenceCheckpoint({ tenant_id, head_hash, sequence, generated_at, private_key, key_id }) {
  if (!tenant_id || !head_hash || !Number.isInteger(sequence) || !private_key || !key_id) throw new TypeError('checkpoint fields and signing key required')
  requireIsoDate(generated_at, 'generated_at')
  const body = { schema: 'trustready-legal-evidence-checkpoint-v1', tenant_id, head_hash, sequence, generated_at }
  return { body, signature: { algorithm: 'Ed25519', key_id, value: signBytes(private_key, body) } }
}

export function verifyEvidenceCheckpoint({ checkpoint, trusted_keys }) {
  const body = checkpoint?.body; const sig = checkpoint?.signature
  if (!body || !sig || sig.algorithm !== 'Ed25519') return { valid: false, reason: 'signed checkpoint required' }
  const publicKey = trusted_keys?.[sig.key_id]
  if (!publicKey || !verifyBytes(publicKey, body, sig.value)) return { valid: false, reason: 'checkpoint signature invalid or signer untrusted' }
  return { valid: true, head_hash: body.head_hash, sequence: body.sequence }
}

export function signEvidenceManifest({ manifest, private_key, key_id }) {
  if (!manifest || !private_key || !key_id) throw new TypeError('manifest and signing key required')
  return { algorithm: 'Ed25519', key_id, value: signBytes(private_key, manifest) }
}

export function verifyEvidenceManifest({ manifest, signature, trusted_keys }) {
  if (!manifest || !signature || signature.algorithm !== 'Ed25519') return { valid: false, reason: 'detached Ed25519 signature required' }
  const publicKey = trusted_keys?.[signature.key_id]
  if (!publicKey || !verifyBytes(publicKey, manifest, signature.value)) return { valid: false, reason: 'manifest signature invalid or signer untrusted' }
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.some((item) => !item.path || !/^sha256:[0-9a-f]{64}$/.test(item.sha256 || ''))) return { valid: false, reason: 'artifact digests missing or invalid' }
  return { valid: true, signer_key_id: signature.key_id }
}
