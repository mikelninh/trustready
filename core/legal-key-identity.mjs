import crypto from 'node:crypto'
import { types as utilTypes } from 'node:util'

export const ZONES = Object.freeze({ PUBLIC: 0, INTERNAL: 1, PERSONAL: 2, MANDATE: 3, RESTRICTED: 4 })
const SUPPORTED_SIGNATURE_ALGORITHMS = new Set(['Ed25519', 'ECDSA_P256_SHA256'])
const ROOTED_KEY_STORES = new WeakSet()

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

function snapshotSignedJson(value, state = { seen: new WeakSet(), nodes: 0 }, depth = 0, path = '$') {
  if (depth > 32) throw new TypeError(`${path}: signed JSON nesting too deep`)
  state.nodes += 1
  if (state.nodes > 10000) throw new TypeError(`${path}: signed JSON node limit exceeded`)
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError(`${path}: non-finite signed number denied`)
    return value
  }
  if (typeof value !== 'object') throw new TypeError(`${path}: non-JSON signed value denied`)
  if (utilTypes.isProxy(value)) throw new TypeError(`${path}: proxy signed value denied`)
  if (state.seen.has(value)) throw new TypeError(`${path}: cyclic signed value denied`)
  state.seen.add(value)
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) throw new TypeError(`${path}: custom signed array prototype denied`)
      if (Object.getOwnPropertySymbols(value).length) throw new TypeError(`${path}: signed symbol properties denied`)
      const descriptors = Object.getOwnPropertyDescriptors(value)
      const lengthDescriptor = descriptors.length
      if (!lengthDescriptor || !Object.hasOwn(lengthDescriptor, 'value') || !Number.isSafeInteger(lengthDescriptor.value) || lengthDescriptor.value < 0) throw new TypeError(`${path}: invalid signed array length`)
      const out = []
      for (const name of Object.keys(descriptors)) {
        if (name === 'length') continue
        if (!/^(0|[1-9]\d*)$/.test(name)) throw new TypeError(`${path}: non-index signed array property denied`)
        const index = Number(name)
        if (!Number.isSafeInteger(index) || index < 0 || index >= lengthDescriptor.value) throw new TypeError(`${path}: invalid signed array index`)
      }
      for (let index = 0; index < lengthDescriptor.value; index += 1) {
        const descriptor = descriptors[String(index)]
        if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) throw new TypeError(`${path}[${index}]: sparse/accessor signed array entry denied`)
        out[index] = snapshotSignedJson(descriptor.value, state, depth + 1, `${path}[${index}]`)
      }
      return Object.freeze(out)
    }
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError(`${path}: custom signed object prototype denied`)
    if (Object.getOwnPropertySymbols(value).length) throw new TypeError(`${path}: signed symbol properties denied`)
    const descriptors = Object.getOwnPropertyDescriptors(value)
    const out = Object.create(null)
    for (const key of Object.keys(descriptors).sort()) {
      const descriptor = descriptors[key]
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) throw new TypeError(`${path}.${key}: accessor/non-enumerable signed property denied`)
      Object.defineProperty(out, key, { value: snapshotSignedJson(descriptor.value, state, depth + 1, `${path}.${key}`), enumerable: true, writable: false, configurable: false })
    }
    return Object.freeze(out)
  } finally {
    state.seen.delete(value)
  }
}

function snapshotEnvelope(envelope) {
  const snapshot = snapshotSignedJson(envelope)
  if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) throw new TypeError('signed envelope object required')
  if (!snapshot.body || !snapshot.signature || typeof snapshot.signature !== 'object' || Array.isArray(snapshot.signature)) throw new TypeError('signed envelope fields required')
  return snapshot
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

export function isRootedKeyTrustStore(store) {
  return Boolean(store && typeof store === 'object' && ROOTED_KEY_STORES.has(store))
}

export function signEnvelope({ body, private_key, key_id, purpose }) {
  if (!body || !private_key || !key_id || !purpose) throw new TypeError('signed envelope fields required')
  const bodySnapshot = snapshotSignedJson(body)
  return Object.freeze({ body: bodySnapshot, signature: Object.freeze({ algorithm: 'Ed25519', key_id, purpose, value: signEd25519(private_key, bodySnapshot) }) })
}

export async function signEnvelopeWithSigner({ body, signer, purpose }) {
  if (!body || !signer || typeof signer.sign !== 'function' || !purpose) throw new TypeError('external signer and purpose required')
  const bodySnapshot = snapshotSignedJson(body)
  const signed = await signer.sign({ body: bodySnapshot, purpose })
  if (!signed?.key_id || !SUPPORTED_SIGNATURE_ALGORITHMS.has(signed.algorithm) || typeof signed.value !== 'string') throw new Error('external signer returned unsupported signature')
  return Object.freeze({ body: bodySnapshot, signature: Object.freeze({ algorithm: signed.algorithm, key_id: signed.key_id, purpose, value: signed.value }) })
}

export function verifyEnvelope({ envelope, key_store, purpose, now = new Date() }) {
  let snapshot
  try { snapshot = snapshotEnvelope(envelope) } catch { return { valid: false, reason: 'signed envelope must be immutable plain JSON' } }
  const sig = snapshot.signature
  if (!SUPPORTED_SIGNATURE_ALGORITHMS.has(sig.algorithm) || sig.purpose !== purpose) return { valid: false, reason: 'signed envelope required' }
  const key = key_store?.resolve?.(sig.key_id, purpose, now)
  if (!key || !verifySignature(key, snapshot.body, sig.value, sig.algorithm)) return { valid: false, reason: 'signature invalid, key untrusted, revoked or expired' }
  return { valid: true, body: snapshot.body, signer_key_id: sig.key_id, signature_algorithm: sig.algorithm }
}

function normaliseKeyringKeys(keys) {
  return keys.map((key) => {
    if (!key?.key_id || !key?.purpose || !key?.public_key) throw new TypeError('keyring key incomplete')
    return { key_id: key.key_id, purpose: key.purpose, public_key_pem: asPublicKey(key.public_key).export({ type: 'spki', format: 'pem' }).toString(), not_before: key.not_before || null, not_after: key.not_after || null }
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
  if (!signed_keyring || !pinned_root_public_key || !expected_root_fingerprint) throw new TypeError('signed keyring and pinned root required')
  let snapshot
  try { snapshot = snapshotEnvelope(signed_keyring) } catch { throw new TypeError('signed keyring must be immutable plain JSON') }
  const fingerprint = publicKeyFingerprint(pinned_root_public_key)
  if (fingerprint !== expected_root_fingerprint) throw new Error('pinned root fingerprint mismatch')
  const sig = snapshot.signature
  if (sig.purpose !== 'trust_root' || !verifySignature(pinned_root_public_key, snapshot.body, sig.value, sig.algorithm)) throw new Error('root keyring signature invalid')
  const body = snapshot.body
  const keyringExpiry = parseTime(body.valid_until)
  if (body.schema !== 'trustready-rooted-keyring-v1' || keyringExpiry <= now.getTime() || !Array.isArray(body.keys) || body.keys.length === 0) throw new Error('root keyring invalid or expired')
  const entries = body.keys.map((key) => ({ key_id: key.key_id, purpose: key.purpose, public_key: key.public_key_pem, not_before: key.not_before, not_after: key.not_after }))
  const inner = createKeyTrustStore(entries)
  const store = {
    rooted: true,
    root_fingerprint: fingerprint,
    keyring_version: body.version,
    keyring_valid_until: body.valid_until,
    root_signature_algorithm: sig.algorithm,
    resolve(keyId, purpose, resolveNow = new Date()) {
      if (!(resolveNow instanceof Date) || Number.isNaN(resolveNow.getTime()) || resolveNow.getTime() >= keyringExpiry) return null
      return inner.resolve(keyId, purpose, resolveNow)
    },
    revoke: inner.revoke,
    snapshot: inner.snapshot,
  }
  ROOTED_KEY_STORES.add(store)
  return Object.freeze(store)
}

export function issueIdentityAssertion({ subject, tenant_id, session_id, roles = [], matter_permissions = [], mfa, auth_time, expires_at, private_key, key_id, now = new Date() }) {
  if (!subject || !tenant_id || !session_id || !expires_at) throw new TypeError('identity fields required')
  const expiry = parseTime(expires_at)
  if (expiry <= now.getTime() || expiry - now.getTime() > 30 * 60 * 1000) throw new Error('identity assertion lifetime invalid')
  const body = { schema: 'trustready-identity-v1', subject, tenant_id, session_id, roles, matter_permissions, mfa: mfa === true, auth_time: auth_time || now.toISOString(), issued_at: now.toISOString(), expires_at }
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
  if (!subject || !tenant_id || !session_id || !matter_id || !Array.isArray(operations) || operations.length === 0 || !expires_at) throw new TypeError('matter authorization fields required')
  const expiry = parseTime(expires_at)
  if (expiry <= now.getTime() || expiry - now.getTime() > 60 * 1000) throw new Error('matter authorization lifetime invalid')
  const body = { schema: 'trustready-matter-authorization-v1', subject, tenant_id, session_id, matter_id, operations: [...new Set(operations)].sort(), resource_version, issued_at: now.toISOString(), expires_at }
  return signEnvelope({ body, private_key, key_id, purpose: 'matter_authorization' })
}

export function verifyMatterAuthorization({ authorization, key_store, expected, operation, now = new Date() }) {
  const verified = verifyEnvelope({ envelope: authorization, key_store, purpose: 'matter_authorization', now })
  if (!verified.valid) return verified
  const body = verified.body
  if (body.schema !== 'trustready-matter-authorization-v1' || parseTime(body.expires_at) <= now.getTime()) return { valid: false, reason: 'matter authorization expired or unsupported' }
  for (const field of ['subject', 'tenant_id', 'session_id', 'matter_id']) if (body[field] !== expected[field]) return { valid: false, reason: `matter authorization ${field} mismatch` }
  if (!Array.isArray(body.operations) || !body.operations.includes(operation)) return { valid: false, reason: 'matter operation not authorised' }
  if (expected.resource_version !== undefined && expected.resource_version !== null && body.resource_version !== expected.resource_version) return { valid: false, reason: 'matter resource version mismatch' }
  return { valid: true, body, signer_key_id: verified.signer_key_id }
}
