import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { createKeyTrustStore, createRootedKeyTrustStore, publicKeyFingerprint, signEnvelope, signKeyring, verifyEnvelope } from './legal-key-identity.mjs'
import { createGoogleCloudHsmSigner, createGoogleCloudHsmSignerForTest, isProductionGoogleCloudHsmSigner } from './legal-gcp-hsm.mjs'
import { createGoogleSensitiveDataScanner, createGoogleSensitiveDataScannerForTest, isProductionGoogleSensitiveDataScanner, productionLegalDlpConfigFingerprint } from './legal-gcp-dlp.mjs'
import { createGceRuntimeIdentityProviderForTest, isProductionGceRuntimeIdentityProvider } from './legal-gcp-runtime-identity.mjs'
import { createGcpNetworkPostureCollector, createGcpNetworkPostureCollectorForTest, isProductionGcpNetworkPostureCollector } from './legal-gcp-network-enforcement.mjs'
import { createRestrictedGoogleApiTransport, createRestrictedGoogleApiTransportForTest, isProductionRestrictedGoogleApiTransport } from './legal-gcp-bound-transport.mjs'
import { createGcsWormEvidenceStore, createGcsWormEvidenceStoreForTest, isProductionGcsWormEvidenceStore, PRODUCTION_WORM_MIN_RETENTION_SECONDS } from './legal-gcp-worm.mjs'
import { runGcpMandateShadowPipeline } from './legal-gcp-runtime-pipeline.mjs'

const NOW = new Date('2026-09-02T20:30:00Z')
const token = async () => 'synthetic-access-token-long-enough'
const keyIds = {
  dlp: 'projects/p/locations/europe-west3/keyRings/legal/cryptoKeys/dlp/cryptoKeyVersions/1',
  egress: 'projects/p/locations/europe-west3/keyRings/legal/cryptoKeys/egress/cryptoKeyVersions/1',
  network: 'projects/p/locations/europe-west3/keyRings/legal/cryptoKeys/network/cryptoKeyVersions/1',
  evidence: 'projects/p/locations/europe-west3/keyRings/legal/cryptoKeys/evidence/cryptoKeyVersions/1',
}
function productionHsm(name) { return createGoogleCloudHsmSigner({ key_version_name: keyIds[name], token_provider: token }) }
function fakeFetch() { return Promise.resolve({ ok: false, status: 500, headers: { get() { return 'Google' } }, async json() { return {} }, async text() { return 'x' } }) }
function testHsm(name = 'network') { return createGoogleCloudHsmSignerForTest({ key_version_name: keyIds[name], fetch_impl: fakeFetch, token_provider: token }) }
function testRuntime() { return createGceRuntimeIdentityProviderForTest({ fetch_impl: fakeFetch }) }
function testNetwork() { return createGcpNetworkPostureCollectorForTest({ project_id: 'trustready-prod', region: 'europe-west3', subnetwork: 'legal', service_perimeter_name: 'accessPolicies/1/servicePerimeters/legal', fetch_impl: fakeFetch, token_provider: token, runtime_identity_provider: testRuntime() }) }
function testDlp() { return createGoogleSensitiveDataScannerForTest({ project_id: 'trustready-prod', fetch_impl: fakeFetch, token_provider: token }) }
function testWorm() { return createGcsWormEvidenceStoreForTest({ bucket: 'trustready-evidence', fetch_impl: fakeFetch, token_provider: token }) }
function testTransport() { return createRestrictedGoogleApiTransportForTest({ signer: testHsm(), resolve4: async () => ['199.36.153.4'], tls_connect: () => { throw new Error('not used') }, https_request: () => { throw new Error('not used') } }) }

function cloneThroughPrototype(value) {
  const clone = Object.create(value)
  for (const symbol of Object.getOwnPropertySymbols(value)) { try { Object.defineProperty(clone, symbol, { value: false, enumerable: true, configurable: true }) } catch {} }
  return clone
}

test('inherited or copied adapter brands cannot become production adapters', () => {
  assert.equal(isProductionGoogleCloudHsmSigner(cloneThroughPrototype(testHsm())), false)
  assert.equal(isProductionGoogleSensitiveDataScanner(cloneThroughPrototype(testDlp())), false)
  assert.equal(isProductionGceRuntimeIdentityProvider(cloneThroughPrototype(testRuntime())), false)
  assert.equal(isProductionGcpNetworkPostureCollector(cloneThroughPrototype(testNetwork())), false)
  assert.equal(isProductionRestrictedGoogleApiTransport(cloneThroughPrototype(testTransport())), false)
  assert.equal(isProductionGcsWormEvidenceStore(cloneThroughPrototype(testWorm())), false)
})

test('production DLP configuration cannot be weakened by caller options', () => {
  assert.throws(() => createGoogleSensitiveDataScanner({ project_id: 'trustready-prod', token_provider: token, info_types: ['EMAIL_ADDRESS'] }), /approved legal info-type set/)
  assert.throws(() => createGoogleSensitiveDataScanner({ project_id: 'trustready-prod', token_provider: token, min_likelihood: 'VERY_LIKELY' }), /approved legal info-type set, likelihood and finding limit/)
  assert.throws(() => createGoogleSensitiveDataScanner({ project_id: 'trustready-prod', token_provider: token, max_findings: 1 }), /approved legal info-type set, likelihood and finding limit/)
  assert.throws(() => createGoogleSensitiveDataScanner({ project_id: 'trustready-prod', token_provider: token, location: 'us' }), /approved EU location/)
  assert.throws(() => createGoogleSensitiveDataScanner({ project_id: 'trustready-prod', token_provider: token, location: 'global' }), /approved EU location/)
  const scanner = createGoogleSensitiveDataScanner({ project_id: 'trustready-prod', token_provider: token })
  assert.equal(isProductionGoogleSensitiveDataScanner(scanner), true)
  assert.equal(scanner.scanner_config_fingerprint, productionLegalDlpConfigFingerprint({ project_id: 'trustready-prod' }))
  assert.notEqual(scanner.scanner_config_fingerprint, productionLegalDlpConfigFingerprint({ project_id: 'trustready-other' }))
})

test('production WORM retention cannot be lowered below mandatory floor', () => {
  assert.equal(PRODUCTION_WORM_MIN_RETENTION_SECONDS, 30 * 24 * 60 * 60)
  assert.throws(() => createGcsWormEvidenceStore({ bucket: 'trustready-evidence', token_provider: token, min_retention_seconds: 0 }), /mandatory floor/)
  assert.throws(() => createGcsWormEvidenceStore({ bucket: 'trustready-evidence', token_provider: token, min_retention_seconds: PRODUCTION_WORM_MIN_RETENTION_SECONDS - 1 }), /mandatory floor/)
  assert.equal(isProductionGcsWormEvidenceStore(createGcsWormEvidenceStore({ bucket: 'trustready-evidence', token_provider: token })), true)
})

test('signed envelope verification rejects Proxy bodies before signature trust is granted', () => {
  const pair = crypto.generateKeyPairSync('ed25519')
  const signed = signEnvelope({ body: { schema: 'test-v1', tenant_id: 'tenant-a', mfa: false }, private_key: pair.privateKey, key_id: 'identity-key', purpose: 'identity' })
  const envelope = { body: new Proxy({ schema: 'test-v1', tenant_id: 'tenant-a', mfa: false }, {}), signature: { ...signed.signature } }
  const store = createKeyTrustStore([{ key_id: 'identity-key', purpose: 'identity', public_key: pair.publicKey }])
  const verified = verifyEnvelope({ envelope, key_store: store, purpose: 'identity' })
  assert.equal(verified.valid, false)
  assert.match(verified.reason, /immutable plain JSON/)
})

test('verified signed body is an immutable snapshot rather than the caller live object', () => {
  const pair = crypto.generateKeyPairSync('ed25519')
  const signed = signEnvelope({ body: { schema: 'test-v1', permissions: ['read'], mfa: false }, private_key: pair.privateKey, key_id: 'identity-key', purpose: 'identity' })
  const liveBody = { schema: 'test-v1', permissions: ['read'], mfa: false }
  const envelope = { body: liveBody, signature: { ...signed.signature } }
  const store = createKeyTrustStore([{ key_id: 'identity-key', purpose: 'identity', public_key: pair.publicKey }])
  const verified = verifyEnvelope({ envelope, key_store: store, purpose: 'identity' })
  assert.equal(verified.valid, true)
  assert.notEqual(verified.body, liveBody)
  assert.equal(Object.isFrozen(verified.body), true)
  assert.equal(Object.isFrozen(verified.body.permissions), true)
  liveBody.mfa = true
  liveBody.permissions.push('egress')
  assert.equal(verified.body.mfa, false)
  assert.deepEqual([...verified.body.permissions], ['read'])
})

test('production mandate pipeline rejects caller-controlled now and clock before any trust decision', async () => {
  const historical = new Date('2020-01-01T00:00:00Z')
  assert.equal((await runGcpMandateShadowPipeline({ now: historical, runtime_state: { production: true } })).code, 'CALLER_TIME_DENIED')
  assert.equal((await runGcpMandateShadowPipeline({ clock: () => historical, runtime_state: { production: true } })).code, 'CALLER_TIME_DENIED')
})

function rootedStore() {
  const root = crypto.generateKeyPairSync('ed25519')
  const leaf = crypto.generateKeyPairSync('ed25519')
  const signed = signKeyring({ keys: [{ key_id: 'leaf', purpose: 'identity', public_key: leaf.publicKey }], version: 'v11', valid_until: '2026-12-31T00:00:00Z', private_key: root.privateKey, key_id: 'offline-root' })
  return createRootedKeyTrustStore({ signed_keyring: signed, pinned_root_public_key: root.publicKey, expected_root_fingerprint: publicKeyFingerprint(root.publicKey), now: NOW })
}
function productionAdapters(project_id = 'trustready-prod') {
  const networkSigner = productionHsm('network')
  return {
    key_store: rootedStore(),
    dlp_scanner: createGoogleSensitiveDataScanner({ project_id, token_provider: token }),
    dlp_signer: productionHsm('dlp'),
    network_collector: createGcpNetworkPostureCollector({ project_id, region: 'europe-west3', subnetwork: 'legal', service_perimeter_name: 'accessPolicies/1/servicePerimeters/legal', token_provider: token }),
    egress_signer: productionHsm('egress'),
    restricted_transport: createRestrictedGoogleApiTransport({ signer: networkSigner }),
    evidence_signer: productionHsm('evidence'),
    worm_store: createGcsWormEvidenceStore({ bucket: 'trustready-evidence', token_provider: token }),
  }
}

test('production DLP project must equal protected gateway project before any mandate scan', async () => {
  let downstreamCalls = 0
  const adapters = productionAdapters('trustready-prod')
  const wrongProjectScanner = createGoogleSensitiveDataScanner({ project_id: 'trustready-other', token_provider: token })
  const result = await runGcpMandateShadowPipeline({
    ...adapters,
    dlp_scanner: wrongProjectScanner,
    runtime_state: { production: true, release: 'r11', dlp_config_fingerprint: productionLegalDlpConfigFingerprint({ project_id: 'trustready-prod' }) },
    request: { tenant_id: 'tenant-a', matter_id: 'm1', policy_version: 'legal-v11', payload: { body_excerpt: 'synthetic' } },
    provider_passport: {}, release: 'r11', bundle_id: 'b1',
    provider_token_provider: async () => { downstreamCalls += 1; return 'not-reached-token' },
  })
  assert.equal(result.code, 'PROVIDER_PASSPORT_DENIED')
  assert.equal(downstreamCalls, 0)
})

test('toJSON getters functions sparse arrays and custom prototypes are denied before security I/O', async () => {
  const badPayloads = [
    { body_excerpt: { toJSON() { return 'erika@example.com' } } },
    Object.defineProperty({}, 'body_excerpt', { enumerable: true, get() { return 'erika@example.com' } }),
    { body_excerpt: () => 'erika@example.com' },
    { body_excerpt: new Date() },
    { body_excerpt: new Array(2) },
  ]
  for (const payload of badPayloads) {
    const result = await runGcpMandateShadowPipeline({
      ...productionAdapters(),
      runtime_state: { production: true, external_ai_enabled: true, policy_version: 'legal-v11', release: 'r11', dlp_config_fingerprint: productionLegalDlpConfigFingerprint({ project_id: 'trustready-prod' }), disabled_tenants: [], disabled_providers: [] },
      request: { tenant_id: 'tenant-a', matter_id: 'm1', policy_version: 'legal-v11', payload },
      provider_passport: {}, release: 'r11', bundle_id: 'b1',
    })
    assert.equal(result.code, 'PAYLOAD_SERIALIZATION_DENIED')
  }
})