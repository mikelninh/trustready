import crypto from 'node:crypto'

export const ZONES = Object.freeze({ PUBLIC: 0, INTERNAL: 1, PERSONAL: 2, MANDATE: 3, RESTRICTED: 4 })
const SUPPORTED_SIGNATURE_ALGORITHMS = new Set(['Ed25519', 'ECDSA_P256_SHA256'])

export function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`
  }
  return JSON.stringify(value)
}

export function sha256(value) {
  let input
  if (Buffer.isBuffer(value)) input = value
  else if (value instanceof Uint8Array) input = Buffer.from(value)
  else input = typeof value === 'string' ? value : canonicalize(value)
  return crypto.createHash('sha256').update(input).digest('hex')
}

export function parseTime(value) {
  const time = Date.parse(value)
  if (!value || Number.isNaN(time)) throw new TypeError('invalid ISO timestamp')
  return time
}

function asPublicKey(key) {
  if (key instanceof crypto.KeyObject && key.type === 'public') return key
  return crypto.createPublicKey(key)
}

function signEd25519(privateKey, body) {
  return crypto.sign(null, Buffer.from(canonicalize(body)), privateKey).toString('base64')
}

function verifySignature(publicKey, body, signature, algorithm) {
  try {
    if (!SUPPORTED_SIGNATURE_ALGORITHMS.has(algorithm)) return false
    const data = Buffer.from(canonicalize(body))
    const sig = Buffer.from(signature, 'base64')
    if (algorithm === 'Ed25519') return crypto.verify(null, data, asPublicKey(publicKey), sig)
    // Google Cloud KMS EC_SIGN_P256_SHA256 receives SHA-256(data) and signs that digest.
    // Node's ECDSA `verify(null, digest, ...)` hashes the digest again, so it is not a raw-digest verifier.
    // Verifying with SHA-256 over the original canonical bytes produces exactly the digest KMS signed.
    return crypto.verify('sha256', data, asPublicKey(publicKey), sig)
  } catch {
    return false
  }
}

export function publicKeyFingerprint(publicKey) {
  const der = asPublicKey(publicKey).export({ type: 'spki', format: 'der' })
  return `sha256:${crypto.createHash('sha256').update(der).digest('hex')}`
}

export function createKeyTrustStore(entries = []) {
  const map = new Map()
  for (const item of entries) {
    if (!item?.key_id || !item?.purpose || !item?.public_key) throw new TypeError('key_id, purpose and public_key required')
    if (map.has(item.key_id)) throw new Error('duplicate key_id')
    map.set(item.key_id, { status: 'active', ...item })
  }
  return {
    rooted: false,
    resolve(keyId, purpose, now = new Date()) {
      const key = map.get(keyId)
      if (!key || key.status !== 'active' || key.purpose !== purpose) return null
      if (key.not_before && parseTime(key.not_before) > now.getTime()) return null
      if (key.not_after && parseTime(key.not_after) <= now.getTime()) return null
      return key.public_key
    },
    revoke(keyId) {
      const key = map.get(keyId)
      if (key) key.status = 'revoked'
    },
    snapshot() {
      return [...map.values()].map(({ public_key, ...rest }) => rest)
    },
  }
}

export function signEnvelope({ body, private_key, key_id, purpose }) {
  if (!body || !private_key || !key_id || !purpose) throw new TypeError('signed envelope fields required')
  return { body, signature: { algorithm: 'Ed25519', key_id, purpose, value: signEd25519(private_key, body) } }
}

export async function signEnvelopeWithSigner({ body, signer, purpose }) {
  if (!body || !signer || typeof signer.sign !== 'function' || !purpose) throw new TypeError('external signer and purpose required')
  const signed = await signer.sign({ body, purpose })
  if (!signed?.key_id || !SUPPORTED_SIGNATURE_ALGORITHMS.has(signed.algorithm) || typeof signed.value !== 'string') {
    throw new Error('external signer returned unsupported signature')
  }
  return { body, signature: { algorithm: signed.algorithm, key_id: signed.key_id, purpose, value: signed.value } }
}

export function verifyEnvelope({ envelope, key_store, purpose, now = new Date() }) {
  const sig = envelope?.signature
  if (!envelope?.body || !sig || !SUPPORTED_SIGNATURE_ALGORITHMS.has(sig.algorithm) || sig.purpose !== purpose) {
    return { valid: false, reason: 'signed envelope required' }
  }
  const key = key_store?.resolve?.(sig.key_id, purpose, now)
  if (!key || !verifySignature(key, envelope.body, sig.value, sig.algorithm)) {
    return { valid: false, reason: 'signature invalid, key untrusted, revoked or expired' }
  }
  return { valid: true, body: envelope.body, signer_key_id: sig.key_id, signature_algorithm: sig.algorithm }
}

function normaliseKeyringKeys(keys) {
  return keys.map((key) => {
    if (!key?.key_id || !key?.purpose || !key?.public_key) throw new TypeError('keyring key incomplete')
    return {
      key_id: key.key_id,
      purpose: key.purpose,
      public_key_pem: asPublicKey(key.public_key).export({ type: 'spki', format: 'pem' }).toString(),
      not_before: key.not_before || null,
      not_after: key.not_after || null,
    }
  })
}

export function signKeyring({ keys, version, valid_until, private_key, key_id }) {
  if (!Array.isArray(keys) || !keys.length || !version || !valid_until) throw new TypeError('keyring fields required')
  parseTime(valid_until)
  const body = { schema: 'trustready-rooted-keyring-v1', version, valid_until, keys: normaliseKeyringKeys(keys) }
  return signEnvelope({ body, private_key, key_id, purpose: 'trust_root' })
}

export async function signKeyringWithSigner({ keys, version, valid_until, signer }) {
  if (!Array.isArray(keys) || !keys.length || !version || !valid_until) throw new TypeError('keyring fields required')
  parseTime(valid_until)
  const body = { schema: 'trustready-rooted-keyring-v1', version, valid_until, keys: normaliseKeyringKeys(keys) }
  return signEnvelopeWithSigner({ body, signer, purpose: 'trust_root' })
}

export function createRootedKeyTrustStore({ signed_keyring, pinned_root_public_key, expected_root_fingerprint, now = new Date() }) {
  if (!signed_keyring?.body || !signed_keyring?.signature || !pinned_root_public_key || !expected_root_fingerprint) {
    throw new TypeError('signed keyring and pinned root required')
  }
  const fingerprint = publicKeyFingerprint(pinned_root_public_key)
  if (fingerprint !== expected_root_fingerprint) throw new Error('pinned root fingerprint mismatch')
  const sig = signed_keyring.signature
  if (sig.purpose !== 'trust_root' || !verifySignature(pinned_root_public_key, signed_keyring.body, sig.value, sig.algorithm)) {
    throw new Error('root keyring signature invalid')
  }
  const body = signed_keyring.body
  if (body.schema !== 'trustready-rooted-keyring-v1' || parseTime(body.valid_until) <= now.getTime() || !Array.isArray(body.keys) || body.keys.length === 0) {
    throw new Error('root keyring invalid or expired')
  }
  const entries = body.keys.map((key) => ({
    key_id: key.key_id,
    purpose: key.purpose,
    public_key: key.public_key_pem,
    not_before: key.not_before,
    not_after: key.not_after,
  }))
  const inner = createKeyTrustStore(entries)
  return {
    rooted: true,
    root_fingerprint: fingerprint,
    keyring_version: body.version,
    root_signature_algorithm: sig.algorithm,
    resolve: inner.resolve,
    revoke: inner.revoke,
    snapshot: inner.snapshot,
  }
}

export function issueIdentityAssertion({ subject, tenant_id, session_id, roles = [], matter_permissions = [], mfa, auth_time, expires_at, private_key, key_id, now = new Date() }) {
  if (!subject || !tenant_id || !session_id || !expires_at) throw new TypeError('identity fields required')
  const expiry = parseTime(expires_at)
  if (expiry <= now.getTime() || expiry - now.getTime() > 30 * 60 * 1000) throw new Error('identity assertion lifetime invalid')
  const body = {
    schema: 'trustready-identity-v1', subject, tenant_id, session_id, roles, matter_permissions,
    mfa: mfa === true, auth_time: auth_time || now.toISOString(), issued_at: now.toISOString(), expires_at,
  }
  return signEnvelope({ body, private_key, key_id, purpose: 'identity' })
}

export function verifyIdentityAssertion({ assertion, key_store, now = new Date() }) {
  const verified = verifyEnvelope({ envelope: assertion, key_store, purpose: 'identity', now })
  if (!verified.valid) return verified
  const body = verified.body
  if (body.schema !== 'trustready-identity-v1') return { valid: false, reason: 'identity schema unsupported' }
  if (parseTime(body.expires_at) <= now.getTime()) return { valid: false, reason: 'identity assertion expired' }
  if (!body.subject || !body.tenant_id || !body.session_id || !Array.isArray(body.matter_permissions)) return { valid: false, reason: 'identity context incomplete' }
  return { valid: true, principal: body, signer_key_id: verified.signer_key_id }
}

function hasMatterPermission(principal, matterId, operation) {
  return principal.matter_permissions.some((permission) => permission?.matter_id === matterId && Array.isArray(permission.operations) && permission.operations.includes(operation))
}

export function authorizeMatter({ principal, tenant_id, matter_id, operation, zone }) {
  if (!principal || principal.tenant_id !== tenant_id) return { allowed: false, reason: 'tenant mismatch' }
  if (ZONES[zone] >= ZONES.MANDATE) {
    if (!matter_id) return { allowed: false, reason: 'matter required' }
    if (!hasMatterPermission(principal, matter_id, operation)) return { allowed: false, reason: 'matter permission denied' }
    if (principal.mfa !== true) return { allowed: false, reason: 'MFA required for mandate access' }
  }
  return { allowed: true }
}

export function issueMatterAuthorization({ subject, tenant_id, session_id, matter_id, operations, resource_version = null, expires_at, private_key, key_id, now = new Date() }) {
  if (!subject || !tenant_id || !session_id || !matter_id || !Array.isArray(operations) || operations.length === 0 || !expires_at) {
    throw new TypeError('matter authorization fields required')
  }
  const expiry = parseTime(expires_at)
  if (expiry <= now.getTime() || expiry - now.getTime() > 60 * 1000) throw new Error('matter authorization lifetime invalid')
  const body = {
    schema: 'trustready-matter-authorization-v1', subject, tenant_id, session_id, matter_id,
    operations: [...new Set(operations)].sort(), resource_version, issued_at: now.toISOString(), expires_at,
  }
  return signEnvelope({ body, private_key, key_id, purpose: 'matter_authorization' })
}

export function verifyMatterAuthorization({ authorization, key_store, expected, operation, now = new Date() }) {
  const verified = verifyEnvelope({ envelope: authorization, key_store, purpose: 'matter_authorization', now })
  if (!verified.valid) return verified
  const body = verified.body
  if (body.schema !== 'trustready-matter-authorization-v1' || parseTime(body.expires_at) <= now.getTime()) return { valid: false, reason: 'matter authorization expired or unsupported' }
  for (const field of ['subject', 'tenant_id', 'session_id', 'matter_id']) {
    if (body[field] !== expected[field]) return { valid: false, reason: `matter authorization ${field} mismatch` }
  }
  if (!Array.isArray(body.operations) || !body.operations.includes(operation)) return { valid: false, reason: 'matter operation not authorised' }
  if (expected.resource_version !== undefined && expected.resource_version !== null && body.resource_version !== expected.resource_version) {
    return { valid: false, reason: 'matter resource version mismatch' }
  }
  return { valid: true, body, signer_key_id: verified.signer_key_id }
}
