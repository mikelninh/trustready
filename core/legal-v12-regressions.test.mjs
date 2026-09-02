import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import { createRootedKeyTrustStore, publicKeyFingerprint, signEnvelope, signKeyring, verifyEnvelope } from './legal-key-identity.mjs'
import { createGceRuntimeIdentityProviderForTest } from './legal-gcp-runtime-identity.mjs'
import { evaluateBucketLockPosture, createGcsWormEvidenceStore } from './legal-gcp-worm.mjs'
import { createGoogleSensitiveDataScanner } from './legal-gcp-dlp.mjs'
import { createGcpNetworkPostureCollector } from './legal-gcp-network-enforcement.mjs'
import { qualifyGcpLegalInfrastructure } from './legal-gcp-qualification.mjs'

const token = async () => 'synthetic-access-token-long-enough'
const BEFORE = new Date('2026-09-02T20:30:00Z')
const AFTER = new Date('2026-09-02T20:32:00Z')

function metadataResponse(value) {
  return { ok: true, status: 200, headers: { get(name) { return name.toLowerCase() === 'metadata-flavor' ? 'Google' : null } }, async text() { return value } }
}

const metadata = {
  'project/project-id': 'trustready-prod',
  'instance/name': 'trustready-legal-gateway',
  'instance/id': '987654321',
  'instance/zone': 'projects/123/zones/europe-west3-a',
  'instance/network-interfaces/0/network': 'projects/123/networks/legal',
  'instance/network-interfaces/0/subnetwork': 'projects/123/regions/europe-west3/subnetworks/legal',
  'instance/service-accounts/default/email': 'trustready-legal-gateway@trustready-prod.iam.gserviceaccount.com',
  'instance/attributes/trustready-evidence-bucket': 'trustready-evidence',
}

test('root-signed keyring expiry is enforced during every later key resolution', () => {
  const root = crypto.generateKeyPairSync('ed25519')
  const leaf = crypto.generateKeyPairSync('ed25519')
  const keyring = signKeyring({
    keys: [{ key_id: 'leaf', purpose: 'identity', public_key: leaf.publicKey }],
    version: 'v12', valid_until: '2026-09-02T20:31:00Z', private_key: root.privateKey, key_id: 'offline-root',
  })
  const store = createRootedKeyTrustStore({ signed_keyring: keyring, pinned_root_public_key: root.publicKey, expected_root_fingerprint: publicKeyFingerprint(root.publicKey), now: BEFORE })
  const assertion = signEnvelope({ body: { schema: 'synthetic-identity-v1', subject: 'user-1' }, private_key: leaf.privateKey, key_id: 'leaf', purpose: 'identity' })
  assert.equal(verifyEnvelope({ envelope: assertion, key_store: store, purpose: 'identity', now: BEFORE }).valid, true)
  assert.equal(verifyEnvelope({ envelope: assertion, key_store: store, purpose: 'identity', now: AFTER }).valid, false)
  assert.equal(store.resolve('leaf', 'identity', AFTER), null)
})

test('authenticated GCE runtime identity pins the exact evidence bucket', async () => {
  const provider = createGceRuntimeIdentityProviderForTest({ fetch_impl: async (url) => metadataResponse(metadata[url.split('/computeMetadata/v1/')[1]]) })
  const identity = await provider.collect()
  assert.equal(identity.ready, true)
  assert.equal(identity.project_id, 'trustready-prod')
  assert.equal(identity.evidence_bucket, 'trustready-evidence')
})

test('WORM posture cannot qualify without concrete GCS project identity', () => {
  const base = { name: 'trustready-evidence', retentionPolicy: { isLocked: true, retentionPeriod: String(31 * 24 * 60 * 60) }, iamConfiguration: { uniformBucketLevelAccess: { enabled: true }, publicAccessPrevention: 'enforced' } }
  assert.equal(evaluateBucketLockPosture({ bucket: base }).ready, false)
  const qualified = evaluateBucketLockPosture({ bucket: { ...base, projectNumber: '123' } })
  assert.equal(qualified.ready, true)
  assert.equal(qualified.project_number, '123')
})

test('infrastructure qualification rejects caller-controlled time before runtime I/O', async () => {
  const dlp = createGoogleSensitiveDataScanner({ project_id: 'trustready-prod', token_provider: token })
  const network = createGcpNetworkPostureCollector({ project_id: 'trustready-prod', region: 'europe-west3', subnetwork: 'legal', service_perimeter_name: 'accessPolicies/1/servicePerimeters/legal', token_provider: token })
  const worm = createGcsWormEvidenceStore({ bucket: 'trustready-evidence', token_provider: token })
  const result = await qualifyGcpLegalInfrastructure({ hsm_signers: {}, dlp_scanner: dlp, network_collector: network, worm_store: worm, tenant_id: 'tenant-a', policy_version: 'v12', release: 'r12', now: BEFORE })
  assert.equal(result.status, 'NOT_READY')
  assert.equal(result.code, 'CALLER_TIME_DENIED')
})

test('infrastructure qualification authenticates runtime and WORM before any DLP canary inspection', () => {
  const source = fs.readFileSync(new URL('./legal-gcp-qualification.mjs', import.meta.url), 'utf8')
  const runtime = source.indexOf('createGceRuntimeIdentityProvider().collect()')
  const network = source.indexOf('network_collector.collect()')
  const worm = source.indexOf('worm_store.posture()')
  const dlp = source.indexOf('dlp_scanner.inspect({ payload: SAFE_CANARY })')
  assert.ok(runtime >= 0 && network > runtime && worm > network && dlp > worm)
})

test('mandate pipeline authenticates runtime network and WORM resource before mandate DLP inspection', () => {
  const source = fs.readFileSync(new URL('./legal-gcp-runtime-pipeline.mjs', import.meta.url), 'utf8')
  const runtime = source.indexOf('createGceRuntimeIdentityProvider().collect()')
  const network = source.indexOf('createSignedEgressEnforcementAttestation')
  const worm = source.indexOf('worm_store.posture()')
  const dlp = source.indexOf('createSignedDlpAttestation')
  assert.ok(runtime >= 0 && network > runtime && worm > network && dlp > worm)
})

test('IaC pins the evidence bucket into the dedicated gateway metadata', () => {
  const source = fs.readFileSync(new URL('../infra/gcp-legal-shadow/main.tf', import.meta.url), 'utf8')
  assert.match(source, /trustready-evidence-bucket\s*=\s*var\.evidence_bucket_name/)
})