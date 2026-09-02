import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { createKeyTrustStore, sha256 } from './legal-key-identity.mjs'
import { buildEvidenceManifest, signEvidenceManifest } from './legal-evidence.mjs'
import { commitEvidenceBundleToWorm } from './legal-gcp-worm.mjs'

const evidence = crypto.generateKeyPairSync('ed25519')
const keyStore = createKeyTrustStore([{ key_id: 'evidence-1', purpose: 'evidence_manifest', public_key: evidence.publicKey }])
const artifacts = { 'controls.json': { ready: true }, 'runtime/network.json': { deny_by_default: true } }
function signedManifest(source = artifacts) {
  const manifest = buildEvidenceManifest({ tenant: 'tenant-a', release: 'r4', policy_version: 'legal-v4', artifacts: source, generated_at: '2026-09-02T12:00:00Z' })
  return signEvidenceManifest({ manifest, private_key: evidence.privateKey, key_id: 'evidence-1' })
}
function storeWith({ failPath = null, missingRetention = false } = {}) {
  const writes = []
  return {
    writes,
    async append({ object_name, bytes }) {
      writes.push(object_name)
      if (object_name.includes(failPath || '__never__')) return { stored: false, reason: 'synthetic failure' }
      return {
        stored: true, bucket: 'evidence', object_name, generation: String(writes.length),
        content_hash: `sha256:${sha256(Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes))}`,
        retention_expiration_time: missingRetention ? null : '2026-10-02T12:00:00Z',
      }
    },
  }
}

test('verified artifacts are written before COMMITTED manifest marker', async () => {
  const store = storeWith()
  const result = await commitEvidenceBundleToWorm({ store, signed_manifest: signedManifest(), key_store: keyStore, artifacts, bundle_id: 'bundle-1', now: new Date('2026-09-02T12:00:00Z') })
  assert.equal(result.committed, true)
  assert.equal(store.writes.at(-1), 'bundles/bundle-1/COMMITTED.manifest.json')
  assert.equal(store.writes.filter((path) => path.includes('/artifacts/')).length, 2)
})

test('tampered artifact is rejected before any immutable write', async () => {
  const store = storeWith()
  const tampered = { ...artifacts, 'controls.json': { ready: false } }
  const result = await commitEvidenceBundleToWorm({ store, signed_manifest: signedManifest(), key_store: keyStore, artifacts: tampered, bundle_id: 'bundle-2' })
  assert.equal(result.code, 'BUNDLE_VERIFICATION_FAILED')
  assert.equal(store.writes.length, 0)
})

test('partial artifact write never creates commit marker', async () => {
  const store = storeWith({ failPath: 'runtime/network.json' })
  const result = await commitEvidenceBundleToWorm({ store, signed_manifest: signedManifest(), key_store: keyStore, artifacts, bundle_id: 'bundle-3' })
  assert.equal(result.code, 'ARTIFACT_WRITE_FAILED')
  assert.equal(store.writes.includes('bundles/bundle-3/COMMITTED.manifest.json'), false)
})

test('missing retention receipt fails bundle rather than pretending immutability', async () => {
  const store = storeWith({ missingRetention: true })
  const result = await commitEvidenceBundleToWorm({ store, signed_manifest: signedManifest(), key_store: keyStore, artifacts, bundle_id: 'bundle-4' })
  assert.equal(result.committed, false)
  assert.equal(store.writes.some((path) => path.endsWith('COMMITTED.manifest.json')), false)
})

test('unsafe traversal path cannot enter immutable evidence namespace', async () => {
  const unsafeArtifacts = { '../escape.json': { x: 1 } }
  const store = storeWith()
  const result = await commitEvidenceBundleToWorm({ store, signed_manifest: signedManifest(unsafeArtifacts), key_store: keyStore, artifacts: unsafeArtifacts, bundle_id: 'bundle-5' })
  assert.equal(result.code, 'UNSAFE_ARTIFACT_PATH')
  assert.equal(store.writes.length, 0)
})
