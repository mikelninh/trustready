import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { canonicalize, sha256 } from './legal-key-identity.mjs'
import { commitPreSendIntentToWorm } from './legal-gcp-worm.mjs'

const NOW = new Date('2026-09-02T12:00:00Z')
const pair = crypto.generateKeyPairSync('ed25519')
const signer = {
  async sign({ body }) {
    return {
      algorithm: 'Ed25519',
      key_id: 'evidence-test',
      value: crypto.sign(null, Buffer.from(canonicalize(body), 'utf8'), pair.privateKey).toString('base64'),
    }
  },
}
const INTENT = Object.freeze({
  matter_id_hash: `sha256:${'a'.repeat(64)}`,
  provider_id: 'vertex',
  transport_request_fingerprint: `sha256:${'b'.repeat(64)}`,
})

function storeWith({ bucket = 'trustready-evidence', project = '123', retention = '2026-10-03T12:00:00Z', fail = false } = {}) {
  const writes = []
  return {
    writes,
    async append({ object_name, bytes }) {
      writes.push({ object_name, bytes: Buffer.from(bytes) })
      if (fail) return { stored: false, reason: 'synthetic outage' }
      return {
        stored: true,
        bucket,
        project_number: project,
        object_name,
        generation: '1',
        content_hash: `sha256:${sha256(Buffer.from(bytes))}`,
        retention_expiration_time: retention,
      }
    },
  }
}

function call(store) {
  return commitPreSendIntentToWorm({
    store,
    signer,
    intent: INTENT,
    tenant_id: 'tenant-a',
    policy_version: 'legal-v12',
    bundle_id: 'bundle-presend-1',
    expected_bucket: 'trustready-evidence',
    expected_project_number: '123',
    now: NOW,
  })
}

test('pre-send intent is HSM-compatible signed and durably committed before egress', async () => {
  const store = storeWith()
  const result = await call(store)
  assert.equal(result.committed, true)
  assert.equal(result.code, 'PRE_SEND_INTENT_COMMITTED')
  assert.equal(result.signed_intent.body.state, 'PREPARED_FOR_EGRESS_NOT_PROOF_OF_SEND')
  assert.equal(result.receipt.bucket, 'trustready-evidence')
  assert.equal(result.receipt.project_number, '123')
  assert.match(result.receipt.object_name, /^intents\/[a-f0-9]{64}\/bundle-presend-1\.json$/)
  assert.equal(result.intent_hash, result.receipt.content_hash)
  assert.equal(store.writes.length, 1)
})

test('pre-send intent rejects a WORM receipt from another bucket or project', async () => {
  const wrongBucket = await call(storeWith({ bucket: 'other-evidence' }))
  assert.equal(wrongBucket.committed, false)
  assert.equal(wrongBucket.code, 'INTENT_RESOURCE_MISMATCH')
  const wrongProject = await call(storeWith({ project: '999' }))
  assert.equal(wrongProject.committed, false)
  assert.equal(wrongProject.code, 'INTENT_RESOURCE_MISMATCH')
})

test('pre-send intent rejects missing or insufficient immutable retention', async () => {
  const missing = await call(storeWith({ retention: null }))
  assert.equal(missing.committed, false)
  assert.equal(missing.code, 'INTENT_RETENTION_FAILED')
  const tooShort = await call(storeWith({ retention: '2026-09-03T12:00:00Z' }))
  assert.equal(tooShort.committed, false)
  assert.equal(tooShort.code, 'INTENT_RETENTION_FAILED')
})

test('pre-send intent fails closed on immutable-store outage', async () => {
  const result = await call(storeWith({ fail: true }))
  assert.equal(result.committed, false)
  assert.equal(result.code, 'INTENT_WRITE_FAILED')
})