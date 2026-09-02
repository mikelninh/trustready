import crypto from 'node:crypto'
import { canonicalize, publicKeyFingerprint } from './legal-key-identity.mjs'

const KEY_PATH = /^projects\/[^/]+\/locations\/([^/]+)\/keyRings\/[^/]+\/cryptoKeys\/[^/]+\/cryptoKeyVersions\/[^/]+$/
const HSM_SIGNER_BRAND = Symbol('trustready.gcp-hsm-signer')
const TEST_HSM_SIGNER_BRAND = Symbol('trustready.test-gcp-hsm-signer')
const PRODUCTION_HSM_SIGNERS = new WeakSet()
const TEST_HSM_SIGNERS = new WeakSet()
const NATIVE_FETCH = typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : null

async function accessToken(tokenProvider) {
  if (typeof tokenProvider !== 'function') throw new Error('GCP access token provider required')
  const token = await tokenProvider()
  if (typeof token !== 'string' || token.length < 16 || /[\r\n]/.test(token)) throw new Error('GCP access token unavailable')
  return token
}

async function jsonRequest({ fetch_impl, token_provider, url, method = 'GET', body }) {
  if (typeof fetch_impl !== 'function') throw new Error('fetch implementation required')
  const token = await accessToken(token_provider)
  let response
  try {
    response = await fetch_impl(url, {
      method,
      redirect: 'error',
      headers: {
        authorization: `Bearer ${token}`,
        accept: 'application/json',
        ...(body ? { 'content-type': 'application/json' } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    })
  } catch {
    throw new Error('GCP API request failed')
  }
  if (!response?.ok) throw new Error(`GCP API request denied (${Number(response?.status) || 0})`)
  let data
  try { data = await response.json() } catch { throw new Error('GCP API returned invalid JSON') }
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('GCP API returned invalid JSON')
  return data
}

export function evaluateCloudHsmKeyPosture({ metadata, public_key, key_version_name, allowed_locations = [] }) {
  const match = KEY_PATH.exec(key_version_name || '')
  if (!match) return { ready: false, reason: 'invalid Cloud KMS key version resource' }
  const location = match[1]
  if (allowed_locations.length && !allowed_locations.includes(location)) return { ready: false, reason: 'HSM key location not approved' }
  if (metadata?.name !== key_version_name) return { ready: false, reason: 'HSM key identity mismatch' }
  if (metadata?.state !== 'ENABLED') return { ready: false, reason: 'HSM key is not enabled' }
  if (metadata?.protectionLevel !== 'HSM') return { ready: false, reason: 'hardware HSM protection required' }
  if (metadata?.algorithm !== 'EC_SIGN_P256_SHA256') return { ready: false, reason: 'approved ECDSA P-256/SHA-256 algorithm required' }
  if (!metadata?.attestation?.content || !metadata?.attestation?.format) return { ready: false, reason: 'HSM key attestation missing' }
  if (public_key?.algorithm !== 'EC_SIGN_P256_SHA256' || typeof public_key?.pem !== 'string') return { ready: false, reason: 'HSM public key metadata invalid' }
  let fingerprint
  try { fingerprint = publicKeyFingerprint(public_key.pem) } catch { return { ready: false, reason: 'HSM public key invalid' } }
  return {
    ready: true,
    provider: 'gcp-cloud-hsm',
    key_version_name,
    location,
    protection_level: metadata.protectionLevel,
    algorithm: metadata.algorithm,
    public_key_pem: public_key.pem,
    public_key_fingerprint: fingerprint,
    attestation_format: metadata.attestation.format,
    attestation_fingerprint: `sha256:${crypto.createHash('sha256').update(metadata.attestation.content, 'base64').digest('hex')}`,
  }
}

function buildGoogleCloudHsmSigner({ key_version_name, fetch_impl, token_provider, allowed_locations, test_only }) {
  if (!KEY_PATH.test(key_version_name || '')) throw new TypeError('valid Cloud KMS CryptoKeyVersion resource required')
  if (typeof fetch_impl !== 'function') throw new TypeError('Cloud HSM fetch implementation required')
  const base = `https://cloudkms.googleapis.com/v1/${key_version_name}`
  let cachedPosture = null

  async function inspect() {
    const [metadata, publicKey] = await Promise.all([
      jsonRequest({ fetch_impl, token_provider, url: base }),
      jsonRequest({ fetch_impl, token_provider, url: `${base}/publicKey` }),
    ])
    const posture = evaluateCloudHsmKeyPosture({ metadata, public_key: publicKey, key_version_name, allowed_locations })
    if (!posture.ready) throw new Error(posture.reason)
    cachedPosture = posture
    return posture
  }

  const signer = {
    [HSM_SIGNER_BRAND]: true,
    ...(test_only ? { [TEST_HSM_SIGNER_BRAND]: true } : {}),
    backend: 'gcp-cloud-hsm',
    hardware_backed: true,
    async posture() { return inspect() },
    async sign({ body }) {
      const posture = cachedPosture || await inspect()
      const bytes = Buffer.from(canonicalize(body), 'utf8')
      const digest = crypto.createHash('sha256').update(bytes).digest('base64')
      const result = await jsonRequest({
        fetch_impl,
        token_provider,
        url: `${base}:asymmetricSign`,
        method: 'POST',
        body: { digest: { sha256: digest } },
      })
      if (typeof result.signature !== 'string' || result.signature.length < 16) throw new Error('Cloud HSM returned invalid signature')
      if (result.name && result.name !== key_version_name) throw new Error('Cloud HSM signature key mismatch')
      return {
        algorithm: 'ECDSA_P256_SHA256',
        key_id: key_version_name,
        value: result.signature,
        public_key_fingerprint: posture.public_key_fingerprint,
      }
    },
  }
  Object.freeze(signer)
  if (test_only) TEST_HSM_SIGNERS.add(signer)
  else PRODUCTION_HSM_SIGNERS.add(signer)
  return signer
}

export function isProductionGoogleCloudHsmSigner(signer) {
  return PRODUCTION_HSM_SIGNERS.has(signer)
}

export function isTestGoogleCloudHsmSigner(signer) {
  return TEST_HSM_SIGNERS.has(signer)
}

export function createGoogleCloudHsmSigner({ key_version_name, token_provider, allowed_locations = ['europe-west3', 'europe-west4', 'europe-west1'] }) {
  if (typeof NATIVE_FETCH !== 'function') throw new TypeError('native fetch required for production Cloud HSM signer')
  return buildGoogleCloudHsmSigner({ key_version_name, fetch_impl: NATIVE_FETCH, token_provider, allowed_locations, test_only: false })
}

export function createGoogleCloudHsmSignerForTest({ key_version_name, fetch_impl, token_provider, allowed_locations = ['europe-west3', 'europe-west4', 'europe-west1'] }) {
  return buildGoogleCloudHsmSigner({ key_version_name, fetch_impl, token_provider, allowed_locations, test_only: true })
}
