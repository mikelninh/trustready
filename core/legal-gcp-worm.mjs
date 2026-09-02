import { sha256, signEnvelopeWithSigner } from './legal-key-identity.mjs'

async function token(provider) {
  if (typeof provider !== 'function') throw new Error('GCP access token provider required')
  const value = await provider()
  if (typeof value !== 'string' || value.length < 16) throw new Error('GCP access token unavailable')
  return value
}

async function request({ fetch_impl, token_provider, url, method = 'GET', body, content_type = 'application/json' }) {
  const accessToken = await token(token_provider)
  let response
  try {
    response = await fetch_impl(url, {
      method,
      redirect: 'error',
      headers: {
        authorization: `Bearer ${accessToken}`,
        accept: 'application/json',
        ...(body !== undefined ? { 'content-type': content_type } : {}),
      },
      ...(body !== undefined ? { body } : {}),
    })
  } catch {
    throw new Error('GCS WORM request failed')
  }
  if (!response?.ok) throw new Error(`GCS WORM request denied (${Number(response?.status) || 0})`)
  return response
}

export function evaluateBucketLockPosture({ bucket, min_retention_seconds = 30 * 24 * 60 * 60 }) {
  if (!bucket?.name) return { ready: false, reason: 'bucket metadata missing' }
  if (bucket?.retentionPolicy?.isLocked !== true) return { ready: false, reason: 'bucket retention policy is not permanently locked' }
  const retention = Number(bucket?.retentionPolicy?.retentionPeriod)
  if (!Number.isFinite(retention) || retention < min_retention_seconds) return { ready: false, reason: 'bucket retention period is too short' }
  if (bucket?.iamConfiguration?.uniformBucketLevelAccess?.enabled !== true) return { ready: false, reason: 'uniform bucket-level access required' }
  if (bucket?.iamConfiguration?.publicAccessPrevention !== 'enforced') return { ready: false, reason: 'public access prevention must be enforced' }
  return {
    ready: true,
    provider: 'gcs-bucket-lock',
    bucket: bucket.name,
    retention_seconds: retention,
    retention_locked: true,
    uniform_bucket_level_access: true,
    public_access_prevention: 'enforced',
  }
}

export function createGcsWormEvidenceStore({ bucket, fetch_impl = globalThis.fetch, token_provider, min_retention_seconds = 30 * 24 * 60 * 60 }) {
  if (!/^[a-z0-9._-]{3,222}$/.test(bucket || '')) throw new TypeError('valid GCS bucket required')
  const metadataUrl = `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(bucket)}`

  return {
    backend: 'gcs-bucket-lock',
    bucket,
    async posture() {
      const response = await request({ fetch_impl, token_provider, url: metadataUrl })
      return evaluateBucketLockPosture({ bucket: await response.json(), min_retention_seconds })
    },
    async append({ object_name, bytes, content_type = 'application/octet-stream' }) {
      if (!/^[A-Za-z0-9._/-]{1,512}$/.test(object_name || '') || object_name.includes('..')) throw new TypeError('safe immutable object name required')
      const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes)
      const posture = await this.posture()
      if (!posture.ready) return { stored: false, reason: posture.reason }
      const uploadUrl = `https://storage.googleapis.com/upload/storage/v1/b/${encodeURIComponent(bucket)}/o?uploadType=media&ifGenerationMatch=0&name=${encodeURIComponent(object_name)}`
      let response
      try {
        response = await request({ fetch_impl, token_provider, url: uploadUrl, method: 'POST', body: buffer, content_type })
      } catch (error) {
        return { stored: false, reason: error.message }
      }
      const metadata = await response.json()
      if (metadata?.bucket !== bucket || metadata?.name !== object_name || !metadata?.generation) return { stored: false, reason: 'GCS write receipt invalid' }
      return {
        stored: true,
        provider: 'gcs-bucket-lock',
        bucket,
        object_name,
        generation: String(metadata.generation),
        metageneration: metadata.metageneration ? String(metadata.metageneration) : null,
        content_hash: `sha256:${sha256(buffer)}`,
        retention_expiration_time: metadata.retentionExpirationTime || null,
      }
    },
  }
}

export async function createSignedWormReceipt({ store, signer, object_name, bytes, tenant_id, policy_version, now = new Date() }) {
  const receipt = await store.append({ object_name, bytes })
  if (!receipt.stored) return { stored: false, receipt, attestation: null }
  if (!receipt.retention_expiration_time) return { stored: false, receipt: { ...receipt, reason: 'retention expiration missing from object receipt' }, attestation: null }
  const body = {
    schema: 'trustready-worm-receipt-v1',
    tenant_id,
    policy_version,
    bucket: receipt.bucket,
    object_name: receipt.object_name,
    generation: receipt.generation,
    content_hash: receipt.content_hash,
    retention_expiration_time: receipt.retention_expiration_time,
    stored_at: now.toISOString(),
  }
  return { stored: true, receipt, attestation: await signEnvelopeWithSigner({ body, signer, purpose: 'worm_receipt' }) }
}
