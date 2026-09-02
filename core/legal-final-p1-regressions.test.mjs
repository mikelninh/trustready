import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { EventEmitter } from 'node:events'
import { canonicalize, createRootedKeyTrustStore, isRootedKeyTrustStore, publicKeyFingerprint, signKeyring } from './legal-key-identity.mjs'
import { createRestrictedGoogleApiTransport, createRestrictedGoogleApiTransportForTest, isProductionRestrictedGoogleApiTransport, prepareRestrictedGoogleApiRequest, sendPreparedGoogleApiRequest } from './legal-gcp-bound-transport.mjs'
import { createGceRuntimeIdentityProvider, createGceRuntimeIdentityProviderForTest, isProductionGceRuntimeIdentityProvider } from './legal-gcp-runtime-identity.mjs'
import { createGcpNetworkPostureCollector, createGcpNetworkPostureCollectorForTest, evaluateGcpNetworkPosture, isProductionGcpNetworkPostureCollector } from './legal-gcp-network-enforcement.mjs'
import { createGoogleSensitiveDataScanner, createGoogleSensitiveDataScannerForTest, isProductionGoogleSensitiveDataScanner } from './legal-gcp-dlp.mjs'
import { createGcsWormEvidenceStore, createGcsWormEvidenceStoreForTest, isProductionGcsWormEvidenceStore } from './legal-gcp-worm.mjs'
import { createGoogleCloudHsmSigner, createGoogleCloudHsmSignerForTest, isProductionGoogleCloudHsmSigner } from './legal-gcp-hsm.mjs'
import { evaluateLocalPromotionGates } from './legal-assurance-evidence.mjs'

const NOW = new Date('2026-09-02T17:30:00Z')
const endpoint = 'https://europe-west3-aiplatform.googleapis.com/v1/projects/p/locations/europe-west3/models/m:generateContent'
const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const keyId = 'projects/p/locations/europe-west3/keyRings/legal/cryptoKeys/network/cryptoKeyVersions/1'
const fakeSigner = {
  hardware_backed: true,
  async posture() { return { ready: true, protection_level: 'HSM', algorithm: 'EC_SIGN_P256_SHA256', key_version_name: keyId } },
  async sign({ body }) { return { algorithm: 'ECDSA_P256_SHA256', key_id: keyId, value: crypto.sign('sha256', Buffer.from(canonicalize(body)), ec.privateKey).toString('base64') } },
}
function tlsFactory() { return () => { const s = new EventEmitter(); s.authorized = true; s.remoteAddress = '199.36.153.4'; s.alpnProtocol = 'http/1.1'; s.getPeerCertificate = () => ({ raw: Buffer.from('cert') }); s.setTimeout = () => s; s.destroyed = false; s.destroy = () => { s.destroyed = true }; queueMicrotask(() => s.emit('secureConnect')); return s } }
function responseFactory(order) { return (_url, options, callback) => { order.push('https_request'); const req = new EventEmitter(); req.setTimeout = () => req; req.destroy = () => {}; req.end = () => { order.push('req_end'); const res = new EventEmitter(); res.statusCode = 200; res.socket = options.agent.createConnection({}); queueMicrotask(() => { callback(res); queueMicrotask(() => res.emit('end')) }) }; return req } }
function testTransport({ https_request = responseFactory([]), resolve4 = async () => ['199.36.153.4'], tls_connect = tlsFactory() } = {}) { return createRestrictedGoogleApiTransportForTest({ signer: fakeSigner, resolve4, tls_connect, https_request }) }

test('production transport rejects self-asserted HSM and test transport cannot become production transport', () => {
  assert.throws(() => createRestrictedGoogleApiTransport({ signer: fakeSigner }), /production Google Cloud HSM signer/)
  assert.equal(isProductionRestrictedGoogleApiTransport(testTransport()), false)
})

test('final synchronous reauthorization is the last gate before request submission', async () => {
  const order = [], transport = testTransport({ https_request: responseFactory(order) })
  const prepared = await prepareRestrictedGoogleApiRequest({ transport, endpoint, body: Buffer.from('{}'), region: 'europe-west3', now: NOW })
  const result = await sendPreparedGoogleApiRequest({ transport, prepared: prepared.prepared, clock: () => { order.push('clock'); return NOW }, before_send: () => { order.push('authorize'); return true } })
  assert.equal(result.ok, true)
  assert.deepEqual(order.slice(0, 4), ['clock', 'authorize', 'https_request', 'req_end'])
})

test('async final clock or async authorization is denied before any provider request', async () => {
  let calls = 0
  const make = () => testTransport({ https_request: (...args) => { calls++; return responseFactory([])(...args) } })
  const a = make(), pa = await prepareRestrictedGoogleApiRequest({ transport: a, endpoint, body: Buffer.from('{}'), region: 'europe-west3', now: NOW })
  assert.equal((await sendPreparedGoogleApiRequest({ transport: a, prepared: pa.prepared, clock: async () => NOW })).ok, false)
  const b = make(), pb = await prepareRestrictedGoogleApiRequest({ transport: b, endpoint, body: Buffer.from('{}'), region: 'europe-west3', now: NOW })
  assert.equal((await sendPreparedGoogleApiRequest({ transport: b, prepared: pb.prepared, clock: () => NOW, before_send: async () => true })).ok, false)
  assert.equal(calls, 0)
})

function metadataResponse(value) { return { ok: true, status: 200, headers: { get(name) { return name.toLowerCase() === 'metadata-flavor' ? 'Google' : null } }, async text() { return value } } }
const metadataValues = {
  'project/project-id': 'trustready-prod', 'instance/name': 'trustready-legal-gateway', 'instance/id': '987654321',
  'instance/zone': 'projects/123/zones/europe-west3-a', 'instance/network-interfaces/0/network': 'projects/123/networks/legal',
  'instance/network-interfaces/0/subnetwork': 'projects/123/regions/europe-west3/subnetworks/legal',
  'instance/service-accounts/default/email': 'trustready-legal-gateway@trustready-prod.iam.gserviceaccount.com',
}
function metadataFetch(url) { return Promise.resolve(metadataResponse(metadataValues[url.split('/computeMetadata/v1/')[1]])) }

test('production metadata identity is native-only and custom metadata providers stay test-only', async () => {
  const prod = createGceRuntimeIdentityProvider()
  const injected = createGceRuntimeIdentityProviderForTest({ fetch_impl: metadataFetch })
  assert.equal(isProductionGceRuntimeIdentityProvider(prod), true)
  assert.equal(isProductionGceRuntimeIdentityProvider(injected), false)
  const identity = await injected.collect()
  assert.equal(identity.ready, true)
  assert.equal(identity.instance_id, '987654321')
})

const NETWORK = 'https://www.googleapis.com/compute/v1/projects/trustready-prod/global/networks/legal'
const SUBNET = 'https://www.googleapis.com/compute/v1/projects/trustready-prod/regions/europe-west3/subnetworks/legal'
const APPROVED_SERVICES = ['accesscontextmanager.googleapis.com','aiplatform.googleapis.com','cloudkms.googleapis.com','cloudresourcemanager.googleapis.com','compute.googleapis.com','dlp.googleapis.com','storage.googleapis.com']
const FIREWALLS = [
  { name: 'allow-restricted', network: NETWORK, direction: 'EGRESS', priority: 1000, destinationRanges: ['199.36.153.4/30'], allowed: [{ IPProtocol: 'tcp', ports: ['443'] }] },
  { name: 'deny-all', network: NETWORK, direction: 'EGRESS', priority: 2000, destinationRanges: ['0.0.0.0/0'], denied: [{ IPProtocol: 'all' }] },
]
function effective() { return { firewalls: structuredClone(FIREWALLS), firewallPolicys: [] } }
function postureFixture() { return {
  effective_firewalls: effective(), regional_effective_firewalls: effective(), workload_effective_firewalls: effective(),
  subnetwork: { network: NETWORK, selfLink: SUBNET, privateIpGoogleAccess: true, stackType: 'IPV4_ONLY' },
  workload: { id: '987654321', name: 'trustready-legal-gateway', zone: 'https://www.googleapis.com/compute/v1/projects/trustready-prod/zones/europe-west3-a', networkInterfaces: [{ name: 'nic0', network: NETWORK, subnetwork: SUBNET, accessConfigs: [], ipv6AccessConfigs: [], stackType: 'IPV4_ONLY' }], serviceAccounts: [{ email: metadataValues['instance/service-accounts/default/email'] }] },
  runtime_identity: { ready: true, provider: 'gce-local-metadata', metadata_flavor_verified: true, project_id: 'trustready-prod', instance_name: 'trustready-legal-gateway', instance_id: '987654321', zone: 'europe-west3-a', network_name: 'legal', subnetwork_name: 'legal', service_account_email: metadataValues['instance/service-accounts/default/email'] },
  perimeter: { name: 'accessPolicies/1/servicePerimeters/legal', status: { resources: ['projects/123'], restrictedServices: [...APPROVED_SERVICES], vpcAccessibleServices: { enableRestriction: true, allowedServices: ['RESTRICTED-SERVICES'] } } },
  protected_resource: 'projects/123', project_id: 'trustready-prod', expected_nic: 'nic0',
} }

test('effective firewall policy rules without match fail closed', () => {
  const fixture = postureFixture()
  fixture.workload_effective_firewalls.firewallPolicys = [{ type: 'SYSTEM_GLOBAL', rules: [{ priority: 1, direction: 'EGRESS', action: 'deny' }] }]
  assert.equal(evaluateGcpNetworkPosture(fixture).ready, false)
})

test('malformed individual classic and policy firewall rules fail closed', () => {
  const classic = postureFixture(); classic.effective_firewalls.firewalls.unshift({ name: 'malformed', network: NETWORK, direction: 'EGRESS', priority: '500', destinationRanges: ['0.0.0.0/0'], allowed: [{ IPProtocol: 'tcp', ports: ['443'] }] })
  assert.equal(evaluateGcpNetworkPosture(classic).ready, false)
  const policy = postureFixture(); policy.workload_effective_firewalls.firewallPolicys = [{ type: 'SYSTEM_GLOBAL', rules: [{ priority: 1, direction: 'EGRESS', action: 'deny', match: { destIpRanges: [] } }] }]
  assert.equal(evaluateGcpNetworkPosture(policy).ready, false)
})

test('malformed VPC-SC policy fields and any extra restricted API fail closed', () => {
  const bad = postureFixture(); bad.perimeter.status.egressPolicies = {}; assert.equal(evaluateGcpNetworkPosture(bad).ready, false)
  const extra = postureFixture(); extra.perimeter.status.restrictedServices.push('bigquery.googleapis.com'); assert.equal(evaluateGcpNetworkPosture(extra).ready, false)
})

test('network posture rejects a hardened decoy workload that is not the executing instance', () => {
  const wrong = postureFixture(); wrong.runtime_identity.instance_id = '111111111'; assert.equal(evaluateGcpNetworkPosture(wrong).ready, false)
})

test('production network collector rejects injected Cloud API clients by construction', async () => {
  const runtimeIdentity = createGceRuntimeIdentityProviderForTest({ fetch_impl: metadataFetch })
  const fixture = postureFixture(), calls = []
  const fetch_impl = async (url) => {
    calls.push(url)
    const body = url.includes('/regions/europe-west3/subnetworks/legal') ? fixture.subnetwork : url.includes('accesscontextmanager.googleapis.com') ? fixture.perimeter : url.includes('cloudresourcemanager.googleapis.com') ? { projectId: 'trustready-prod', name: 'projects/123' } : url.includes('/global/networks/legal/getEffectiveFirewalls') ? fixture.effective_firewalls : url.includes('/regions/europe-west3/firewallPolicies/getEffectiveFirewalls') ? fixture.regional_effective_firewalls : url.includes('/instances/trustready-legal-gateway/getEffectiveFirewalls') ? fixture.workload_effective_firewalls : url.includes('/instances/trustready-legal-gateway') ? fixture.workload : null
    return { ok: body !== null, status: body !== null ? 200 : 404, async json() { return structuredClone(body || {}) } }
  }
  const injected = createGcpNetworkPostureCollectorForTest({ project_id: 'trustready-prod', region: 'europe-west3', subnetwork: 'legal', service_perimeter_name: 'accessPolicies/1/servicePerimeters/legal', fetch_impl, token_provider: async () => 'synthetic-access-token-long-enough', runtime_identity_provider: runtimeIdentity })
  assert.equal(isProductionGcpNetworkPostureCollector(injected), false)
  assert.equal((await injected.collect()).ready, true)
  const prod = createGcpNetworkPostureCollector({ project_id: 'trustready-prod', region: 'europe-west3', subnetwork: 'legal', service_perimeter_name: 'accessPolicies/1/servicePerimeters/legal', token_provider: async () => 'synthetic-access-token-long-enough' })
  assert.equal(isProductionGcpNetworkPostureCollector(prod), true)
})

test('production DLP and WORM adapters reject injectable test backends', () => {
  const token = async () => 'synthetic-access-token-long-enough'
  const dlpTest = createGoogleSensitiveDataScannerForTest({ project_id: 'trustready-prod', fetch_impl: async () => ({ ok: true, async json() { return { result: { findings: [] } } } }), token_provider: token })
  const wormTest = createGcsWormEvidenceStoreForTest({ bucket: 'trustready-evidence', fetch_impl: async () => ({ ok: true, async json() { return {} } }), token_provider: token })
  assert.equal(isProductionGoogleSensitiveDataScanner(dlpTest), false)
  assert.equal(isProductionGcsWormEvidenceStore(wormTest), false)
  assert.equal(isProductionGoogleSensitiveDataScanner(createGoogleSensitiveDataScanner({ project_id: 'trustready-prod', token_provider: token })), true)
  assert.equal(isProductionGcsWormEvidenceStore(createGcsWormEvidenceStore({ bucket: 'trustready-evidence', token_provider: token })), true)
})

test('caller-set rooted boolean cannot satisfy production root trust', () => {
  assert.equal(isRootedKeyTrustStore({ rooted: true, resolve() { return null } }), false)
  const root = crypto.generateKeyPairSync('ed25519'), leaf = crypto.generateKeyPairSync('ed25519')
  const signed = signKeyring({ keys: [{ key_id: 'leaf', purpose: 'identity', public_key: leaf.publicKey }], version: 'v1', valid_until: '2026-12-31T00:00:00Z', private_key: root.privateKey, key_id: 'root' })
  const actual = createRootedKeyTrustStore({ signed_keyring: signed, pinned_root_public_key: root.publicKey, expected_root_fingerprint: publicKeyFingerprint(root.publicKey), now: NOW })
  assert.equal(isRootedKeyTrustStore(actual), true)
})

test('self-asserted hardware backed signers cannot become production HSM signers', () => {
  assert.equal(isProductionGoogleCloudHsmSigner(fakeSigner), false)
  const testSigner = createGoogleCloudHsmSignerForTest({ key_version_name: keyId, fetch_impl: async () => ({ ok: false, status: 500, async json() { return {} } }), token_provider: async () => 'synthetic-access-token-long-enough' })
  assert.equal(isProductionGoogleCloudHsmSigner(testSigner), false)
  const prod = createGoogleCloudHsmSigner({ key_version_name: keyId, token_provider: async () => 'synthetic-access-token-long-enough' })
  assert.equal(isProductionGoogleCloudHsmSigner(prod), true)
})

test('local audit evidence cannot self-promote organizational independence', () => {
  const verdict = evaluateLocalPromotionGates({ engineering: true, live_complete: true, legal_complete: true, independent_evidence_complete: true, distinct_trust_anchors: true, organizational_independence_claim: true })
  assert.equal(verdict.candidate_for_external_assurance, true)
  assert.equal(verdict.real_mandate_shadow_ready, false)
  assert.equal(verdict.independently_assured, false)
  assert.equal(verdict.external_final_verdict_required, true)
})
