import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { createRootedKeyTrustStore, publicKeyFingerprint, signKeyring } from './legal-key-identity.mjs'
import { createGoogleCloudHsmSigner, createGoogleCloudHsmSignerForTest } from './legal-gcp-hsm.mjs'
import { createGoogleSensitiveDataScanner, createGoogleSensitiveDataScannerForTest, legalDlpConfigFingerprint } from './legal-gcp-dlp.mjs'
import { createGcpNetworkPostureCollector, createGcpNetworkPostureCollectorForTest } from './legal-gcp-network-enforcement.mjs'
import { createGceRuntimeIdentityProviderForTest } from './legal-gcp-runtime-identity.mjs'
import { createRestrictedGoogleApiTransport, createRestrictedGoogleApiTransportForTest } from './legal-gcp-bound-transport.mjs'
import { createGcsWormEvidenceStore, createGcsWormEvidenceStoreForTest } from './legal-gcp-worm.mjs'
import { runGcpMandateShadowPipeline } from './legal-gcp-runtime-pipeline.mjs'

const NOW = new Date('2026-09-02T12:00:00Z')
const token = async () => 'synthetic-access-token-long-enough'
const root = crypto.generateKeyPairSync('ed25519')
const leaf = crypto.generateKeyPairSync('ed25519')
const signedKeyring = signKeyring({ keys: [{ key_id: 'leaf', purpose: 'identity', public_key: leaf.publicKey }], version: 'v8', valid_until: '2026-12-31T00:00:00Z', private_key: root.privateKey, key_id: 'offline-root' })
function rootedStore() { return createRootedKeyTrustStore({ signed_keyring: signedKeyring, pinned_root_public_key: root.publicKey, expected_root_fingerprint: publicKeyFingerprint(root.publicKey), now: NOW }) }
const keyIds = {
  dlp: 'projects/p/locations/europe-west3/keyRings/legal/cryptoKeys/dlp/cryptoKeyVersions/1',
  egress: 'projects/p/locations/europe-west3/keyRings/legal/cryptoKeys/egress/cryptoKeyVersions/1',
  network: 'projects/p/locations/europe-west3/keyRings/legal/cryptoKeys/network/cryptoKeyVersions/1',
  evidence: 'projects/p/locations/europe-west3/keyRings/legal/cryptoKeys/evidence/cryptoKeyVersions/1',
}
function productionHsm(name) { return createGoogleCloudHsmSigner({ key_version_name: keyIds[name], token_provider: token }) }
function fakeFetch() { return Promise.resolve({ ok: false, status: 500, headers: { get() { return 'Google' } }, async json() { return {} }, async text() { return 'x' } }) }
function productionAdapters() {
  const networkSigner = productionHsm('network')
  return {
    key_store: rootedStore(),
    dlp_scanner: createGoogleSensitiveDataScanner({ project_id: 'trustready-prod', token_provider: token }),
    dlp_signer: productionHsm('dlp'),
    network_collector: createGcpNetworkPostureCollector({ project_id: 'trustready-prod', region: 'europe-west3', subnetwork: 'legal', service_perimeter_name: 'accessPolicies/1/servicePerimeters/legal', token_provider: token }),
    egress_signer: productionHsm('egress'),
    restricted_transport: createRestrictedGoogleApiTransport({ signer: networkSigner }),
    evidence_signer: productionHsm('evidence'),
    worm_store: createGcsWormEvidenceStore({ bucket: 'trustready-evidence', token_provider: token }),
  }
}
function base(overrides = {}) {
  return {
    ...productionAdapters(),
    runtime_state: { production: true, external_ai_enabled: true, policy_version: 'legal-v8', release: 'r8', dlp_config_fingerprint: legalDlpConfigFingerprint(), disabled_tenants: [], disabled_providers: [] },
    request: { tenant_id: 'tenant-a', matter_id: 'm1', policy_version: 'legal-v8' },
    provider_passport: {}, release: 'r8', bundle_id: 'b1', now: NOW,
    ...overrides,
  }
}

function testDlp() { return createGoogleSensitiveDataScannerForTest({ project_id: 'trustready-prod', fetch_impl: fakeFetch, token_provider: token }) }
function testRuntimeIdentity() { return createGceRuntimeIdentityProviderForTest({ fetch_impl: fakeFetch }) }
function testNetworkCollector() { return createGcpNetworkPostureCollectorForTest({ project_id: 'trustready-prod', region: 'europe-west3', subnetwork: 'legal', service_perimeter_name: 'accessPolicies/1/servicePerimeters/legal', fetch_impl: fakeFetch, token_provider: token, runtime_identity_provider: testRuntimeIdentity() }) }
function testWorm() { return createGcsWormEvidenceStoreForTest({ bucket: 'trustready-evidence', fetch_impl: fakeFetch, token_provider: token }) }
function fakeSigner() { return { hardware_backed: true, async posture() { return { ready: true, protection_level: 'HSM', algorithm: 'EC_SIGN_P256_SHA256', key_version_name: keyIds.dlp } }, async sign() { return { algorithm: 'ECDSA_P256_SHA256', key_id: keyIds.dlp, value: 'fake' } } } }
function testHsm() { return createGoogleCloudHsmSignerForTest({ key_version_name: keyIds.network, fetch_impl: fakeFetch, token_provider: token }) }
function testTransport() { return createRestrictedGoogleApiTransportForTest({ signer: testHsm(), resolve4: async () => ['199.36.153.4'], tls_connect: () => { throw new Error('must never connect') }, https_request: () => { throw new Error('must never send') } }) }

test('production mandate pipeline rejects test transport even when NODE_ENV is test', async () => {
  const previous = process.env.NODE_ENV; process.env.NODE_ENV = 'test'
  try {
    const result = await runGcpMandateShadowPipeline(base({ restricted_transport: testTransport() }))
    assert.equal(result.code, 'PRODUCTION_TRANSPORT_REQUIRED')
  } finally { process.env.NODE_ENV = previous }
})

test('production mandate pipeline rejects fake or test DLP scanner before egress', async () => {
  assert.equal((await runGcpMandateShadowPipeline(base({ dlp_scanner: { async inspect() { return { safe: true } } } }))).code, 'PRODUCTION_DLP_ADAPTER_REQUIRED')
  assert.equal((await runGcpMandateShadowPipeline(base({ dlp_scanner: testDlp() }))).code, 'PRODUCTION_DLP_ADAPTER_REQUIRED')
})

test('production mandate pipeline rejects test network collector before egress', async () => {
  const result = await runGcpMandateShadowPipeline(base({ network_collector: testNetworkCollector() }))
  assert.equal(result.code, 'PRODUCTION_NETWORK_COLLECTOR_REQUIRED')
})

test('production mandate pipeline rejects fake or test WORM store before egress', async () => {
  assert.equal((await runGcpMandateShadowPipeline(base({ worm_store: { async posture() { return { ready: true } }, async append() { return { stored: true } } } }))).code, 'PRODUCTION_WORM_STORE_REQUIRED')
  assert.equal((await runGcpMandateShadowPipeline(base({ worm_store: testWorm() }))).code, 'PRODUCTION_WORM_STORE_REQUIRED')
})

test('production mandate pipeline rejects self-asserted hardware-backed HSM signers', async () => {
  const result = await runGcpMandateShadowPipeline(base({ dlp_signer: fakeSigner() }))
  assert.equal(result.code, 'PRODUCTION_HSM_SIGNER_REQUIRED')
})

test('production mandate pipeline rejects caller-asserted rooted key store', async () => {
  const result = await runGcpMandateShadowPipeline(base({ key_store: { rooted: true, resolve() { return null } } }))
  assert.equal(result.code, 'ROOT_TRUST_REQUIRED')
})

test('production adapter gate executes before provider, DLP, network or WORM I/O', async () => {
  let calls = 0
  const injected = createGoogleSensitiveDataScannerForTest({ project_id: 'trustready-prod', fetch_impl: async () => { calls++; return fakeFetch() }, token_provider: token })
  const result = await runGcpMandateShadowPipeline(base({ dlp_scanner: injected }))
  assert.equal(result.code, 'PRODUCTION_DLP_ADAPTER_REQUIRED')
  assert.equal(calls, 0)
})
