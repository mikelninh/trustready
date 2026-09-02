import { canonicalize, sha256, signEnvelopeWithSigner } from './legal-key-identity.mjs'
import { verifyEvidenceBundle } from './legal-evidence.mjs'

export const PRODUCTION_WORM_MIN_RETENTION_SECONDS = 30 * 24 * 60 * 60
const WORM_STORE_BRAND = Symbol('trustready.gcs-worm-store')
const TEST_WORM_STORE_BRAND = Symbol('trustready.test-gcs-worm-store')
const PRODUCTION_WORM_STORES = new WeakSet()
const TEST_WORM_STORES = new WeakSet()
const NATIVE_FETCH = typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : null

async function token(provider) {
  if (typeof provider !== 'function') throw new Error('GCP access token provider required')
  const value = await provider()
  if (typeof value !== 'string' || value.length < 16 || /[\r\n]/.test(value)) throw new Error('GCP access token unavailable')
  return value
}

async function request({ fetch_impl, token_provider, url, method = 'GET', body, content_type = 'application/json' }) {
  const accessToken = await token(token_provider)
  let response
  try {
    response = await fetch_impl(url, {
      method, redirect: 'error',
      headers: { authorization: `Bearer ${accessToken}`, accept: 'application/json', ...(body !== undefined ? { 'content-type': content_type } : {}) },
      ...(body !== undefined ? { body } : {}),
    })
  } catch { throw new Error('GCS WORM request failed') }
  if (!response?.ok) throw new Error(`GCS WORM request denied (${Number(response?.status) || 0})`)
  return response
}

export function evaluateBucketLockPosture({ bucket, min_retention_seconds = PRODUCTION_WORM_MIN_RETENTION_SECONDS }) {
  if (!bucket?.name) return { ready: false, reason: 'bucket metadata missing' }
  if (bucket?.retentionPolicy?.isLocked !== true) return { ready: false, reason: 'bucket retention policy is not permanently locked' }
  const retention = Number(bucket?.retentionPolicy?.retentionPeriod)
  if (!Number.isFinite(retention) || retention < min_retention_seconds) return { ready: false, reason: 'bucket retention period is too short' }
  if (bucket?.iamConfiguration?.uniformBucketLevelAccess?.enabled !== true) return { ready: false, reason: 'uniform bucket-level access required' }
  if (bucket?.iamConfiguration?.publicAccessPrevention !== 'enforced') return { ready: false, reason: 'public access prevention must be enforced' }
  return { ready: true, provider: 'gcs-bucket-lock', bucket: bucket.name, retention_seconds: retention, retention_locked: true, uniform_bucket_level_access: true, public_access_prevention: 'enforced' }
}

function buildStore({ bucket, fetch_impl, token_provider, min_retention_seconds, test_only }) {
  if (!/^[a-z0-9._-]{3,222}$/.test(bucket || '')) throw new TypeError('valid GCS bucket required')
  if (typeof fetch_impl !== 'function') throw new TypeError('GCS WORM fetch implementation required')
  if (!Number.isFinite(min_retention_seconds) || min_retention_seconds < 0) throw new TypeError('valid WORM retention requirement required')
  const metadataUrl = `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(bucket)}`
  const store = {
    [WORM_STORE_BRAND]: true,
    ...(test_only ? { [TEST_WORM_STORE_BRAND]: true } : {}),
    backend: 'gcs-bucket-lock', bucket,
    async posture() {
      const response = await request({ fetch_impl, token_provider, url: metadataUrl })
      let metadata
      try { metadata = await response.json() } catch { return { ready: false, reason: 'bucket metadata response invalid' } }
      return evaluateBucketLockPosture({ bucket: metadata, min_retention_seconds })
    },
    async append({ object_name, bytes, content_type = 'application/octet-stream' }) {
      if (!/^[A-Za-z0-9._/-]{1,512}$/.test(object_name || '') || object_name.includes('..') || object_name.startsWith('/')) throw new TypeError('safe immutable object name required')
      const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes)
      const posture = await store.posture()
      if (!posture.ready) return { stored: false, reason: posture.reason }
      const uploadUrl = `https://storage.googleapis.com/upload/storage/v1/b/${encodeURIComponent(bucket)}/o?uploadType=media&ifGenerationMatch=0&name=${encodeURIComponent(object_name)}`
      let response
      try { response = await request({ fetch_impl, token_provider, url: uploadUrl, method: 'POST', body: buffer, content_type }) } catch (error) { return { stored: false, reason: error.message } }
      let metadata
      try { metadata = await response.json() } catch { return { stored: false, reason: 'GCS write receipt invalid' } }
      if (metadata?.bucket !== bucket || metadata?.name !== object_name || !metadata?.generation) return { stored: false, reason: 'GCS write receipt invalid' }
      return {
        stored: true, provider: 'gcs-bucket-lock', bucket, object_name,
        generation: String(metadata.generation), metageneration: metadata.metageneration ? String(metadata.metageneration) : null,
        content_hash: `sha256:${sha256(buffer)}`, retention_expiration_time: metadata.retentionExpirationTime || null,
      }
    },
  }
  Object.freeze(store)
  if (test_only) TEST_WORM_STORES.add(store)
  else PRODUCTION_WORM_STORES.add(store)
  return store
}

export function isProductionGcsWormEvidenceStore(store) {
  return PRODUCTION_WORM_STORES.has(store)
}

export function isTestGcsWormEvidenceStore(store) {
  return TEST_WORM_STORES.has(store)
}

export function createGcsWormEvidenceStore({ bucket, token_provider, min_retention_seconds = PRODUCTION_WORM_MIN_RETENTION_SECONDS }) {
  if (typeof NATIVE_FETCH !== 'function') throw new TypeError('native fetch required for production GCS WORM store')
  if (!Number.isFinite(min_retention_seconds) || min_retention_seconds < PRODUCTION_WORM_MIN_RETENTION_SECONDS) throw new TypeError('production WORM retention cannot be lower than the mandatory floor')
  return buildStore({ bucket, fetch_impl: NATIVE_FETCH, token_provider, min_retention_seconds, test_only: false })
}

export function createGcsWormEvidenceStoreForTest({ bucket, fetch_impl, token_provider, min_retention_seconds = PRODUCTION_WORM_MIN_RETENTION_SECONDS }) {
  return buildStore({ bucket, fetch_impl, token_provider, min_retention_seconds, test_only: true })
}

export async function createSignedWormReceipt({ store, signer, object_name, bytes, tenant_id, policy_version, now = new Date() }) {
  const receipt = await store.append({ object_name, bytes })
  if (!receipt.stored) return { stored: false, receipt, attestation: null }
  if (!receipt.retention_expiration_time) return { stored: false, receipt: { ...receipt, reason: 'retention expiration missing from object receipt' }, attestation: null }
  const body = {
    schema: 'trustready-worm-receipt-v1', tenant_id, policy_version, bucket: receipt.bucket,
    object_name: receipt.object_name, generation: receipt.generation, content_hash: receipt.content_hash,
    retention_expiration_time: receipt.retention_expiration_time, stored_at: now.toISOString(),
  }
  return { stored: true, receipt, attestation: await signEnvelopeWithSigner({ body, signer, purpose: 'worm_receipt' }) }
}

function safeBundlePath(path) {
  return typeof path === 'string' && /^[A-Za-z0-9._/-]{1,256}$/.test(path) && !path.includes('..') && !path.startsWith('/') && !path.endsWith('/')
}

export async function commitEvidenceBundleToWorm({ store, signed_manifest, key_store, artifacts, bundle_id, now = new Date() }) {
  if (!store || !signed_manifest || !key_store || !artifacts || !/^[A-Za-z0-9._:-]{1,128}$/.test(bundle_id || '')) throw new TypeError('verified WORM bundle context required')
  const verified = verifyEvidenceBundle({ signed_manifest, key_store, artifacts, now })
  if (!verified.valid) return { committed: false, code: 'BUNDLE_VERIFICATION_FAILED', reason: verified.reason }
  const paths = Object.keys(artifacts).sort()
  if (paths.some((path) => !safeBundlePath(path))) return { committed: false, code: 'UNSAFE_ARTIFACT_PATH', reason: 'unsafe evidence artifact path' }

  const receipts = []
  for (const path of paths) {
    const value = artifacts[path]
    const bytes = Buffer.isBuffer(value) ? value : value instanceof Uint8Array ? Buffer.from(value) : typeof value === 'string' ? Buffer.from(value) : Buffer.from(canonicalize(value))
    const receipt = await store.append({ object_name: `bundles/${bundle_id}/artifacts/${path}`, bytes })
    if (!receipt?.stored || !receipt.retention_expiration_time) {
      return { committed: false, code: 'ARTIFACT_WRITE_FAILED', failed_path: path, receipts }
    }
    receipts.push(receipt)
  }

  const manifestBytes = Buffer.from(canonicalize(signed_manifest), 'utf8')
  const commitReceipt = await store.append({ object_name: `bundles/${bundle_id}/COMMITTED.manifest.json`, bytes: manifestBytes, content_type: 'application/json' })
  if (!commitReceipt?.stored || !commitReceipt.retention_expiration_time) return { committed: false, code: 'COMMIT_MARKER_WRITE_FAILED', receipts }
  return {
    committed: true, code: 'WORM_BUNDLE_COMMITTED', bundle_id,
    manifest_hash: `sha256:${sha256(manifestBytes)}`, artifact_receipts: receipts, commit_receipt: commitReceipt,
  }
}
