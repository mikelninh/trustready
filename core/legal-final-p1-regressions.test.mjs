import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { EventEmitter } from 'node:events'
import { canonicalize } from './legal-key-identity.mjs'
import { createRestrictedGoogleApiTransport, createRestrictedGoogleApiTransportForTest, prepareRestrictedGoogleApiRequest, sendPreparedGoogleApiRequest } from './legal-gcp-bound-transport.mjs'
import { createGceRuntimeIdentityProvider } from './legal-gcp-runtime-identity.mjs'
import { createGcpNetworkPostureCollector, evaluateGcpNetworkPosture } from './legal-gcp-network-enforcement.mjs'
import { evaluateLocalPromotionGates } from './legal-assurance-evidence.mjs'

process.env.NODE_ENV = 'test'

const NOW = new Date('2026-09-02T17:30:00Z')
const endpoint = 'https://europe-west3-aiplatform.googleapis.com/v1/projects/p/locations/europe-west3/models/m:generateContent'
const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const keyId = 'projects/p/locations/europe-west3/keyRings/legal/cryptoKeys/network/cryptoKeyVersions/1'
const signer = {
  hardware_backed: true,
  async posture() { return { ready: true, protection_level: 'HSM', algorithm: 'EC_SIGN_P256_SHA256', key_version_name: keyId } },
  async sign({ body }) { return { algorithm: 'ECDSA_P256_SHA256', key_id: keyId, value: crypto.sign('sha256', Buffer.from(canonicalize(body)), ec.privateKey).toString('base64') } },
}
function tlsFactory() { return () => { const s = new EventEmitter(); s.authorized = true; s.remoteAddress = '199.36.153.4'; s.alpnProtocol = 'http/1.1'; s.getPeerCertificate = () => ({ raw: Buffer.from('cert') }); s.setTimeout = () => s; s.destroyed = false; s.destroy = () => { s.destroyed = true }; queueMicrotask(() => s.emit('secureConnect')); return s } }
function responseFactory(order) { return (_url, options, callback) => { order.push('https_request'); const req = new EventEmitter(); req.setTimeout = () => req; req.destroy = () => {}; req.end = () => { order.push('req_end'); const res = new EventEmitter(); res.statusCode = 200; res.socket = options.agent.createConnection({}); queueMicrotask(() => { callback(res); queueMicrotask(() => res.emit('end')) }) }; return req } }
function testTransport({ https_request = responseFactory([]), resolve4 = async () => ['199.36.153.4'], tls_connect = tlsFactory() } = {}) {
  return createRestrictedGoogleApiTransportForTest({ signer, resolve4, tls_connect, https_request })
}

test('production transport pins native dependencies and test dependency substitution is production-blocked', () => {
  const evilResolve = async () => ['8.8.8.8']
  const production = createRestrictedGoogleApiTransport({ signer, resolve4: evilResolve, tls_connect: tlsFactory(), https_request: responseFactory([]) })
  assert.notEqual(production.resolve4, evilResolve)
  const old = process.env.NODE_ENV
  process.env.NODE_ENV = 'production'
  try {
    assert.throws(() => createRestrictedGoogleApiTransportForTest({ signer, resolve4: evilResolve, tls_connect: tlsFactory(), https_request: responseFactory([]) }), /test-only/)
  } finally { process.env.NODE_ENV = old }
})

test('final synchronous reauthorization is the last gate before request submission', async () => {
  const order = []
  const transport = testTransport({ https_request: responseFactory(order) })
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
  'project/project-id': 'trustready-prod',
  'instance/name': 'trustready-legal-gateway',
  'instance/id': '987654321',
  'instance/zone': 'projects/123/zones/europe-west3-a',
  'instance/network-interfaces/0/network': 'projects/123/networks/legal',
  'instance/network-interfaces/0/subnetwork': 'projects/123/regions/europe-west3/subnetworks/legal',
  'instance/service-accounts/default/email': 'trustready-legal-gateway@trustready-prod.iam.gserviceaccount.com',
}
function metadataFetch(url) { const key = url.split('/computeMetadata/v1/')[1]; return Promise.resolve(metadataResponse(metadataValues[key])) }

test('GCE runtime identity comes only from module-pinned metadata fetch and rejects runtime global fetch substitution', async () => {
  assert.throws(() => createGceRuntimeIdentityProvider({ fetch_impl: metadataFetch }), /test-only/)
  const original = globalThis.fetch
  const attackerFetch = async () => metadataResponse('attacker-controlled')
  globalThis.fetch = attackerFetch
  try {
    assert.throws(() => createGceRuntimeIdentityProvider({ fetch_impl: globalThis.fetch }), /test-only/)
    assert.ok(createGceRuntimeIdentityProvider())
  } finally { globalThis.fetch = original }
  const provider = createGceRuntimeIdentityProvider({ fetch_impl: metadataFetch, test_only_allow_custom_fetch: true })
  const identity = await provider.collect()
  assert.equal(identity.ready, true)
  assert.equal(identity.instance_id, '987654321')
  assert.equal(identity.metadata_endpoint, '169.254.169.254')
  assert.equal(identity.metadata_flavor_verified, true)
})

const NETWORK = 'https://www.googleapis.com/compute/v1/projects/trustready-prod/global/networks/legal'
const SUBNET = 'https://www.googleapis.com/compute/v1/projects/trustready-prod/regions/europe-west3/subnetworks/legal'
const APPROVED_SERVICES = [
  'accesscontextmanager.googleapis.com',
  'aiplatform.googleapis.com',
  'cloudkms.googleapis.com',
  'cloudresourcemanager.googleapis.com',
  'compute.googleapis.com',
  'dlp.googleapis.com',
  'storage.googleapis.com',
]
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

test('missing accessible-services or malformed effective policy collections fail closed', () => {
  const missing = postureFixture(); delete missing.perimeter.status.vpcAccessibleServices
  assert.equal(evaluateGcpNetworkPosture(missing).ready, false)
  const malformed = postureFixture(); delete malformed.effective_firewalls.firewallPolicys
  assert.equal(evaluateGcpNetworkPosture(malformed).ready, false)
})

test('malformed individual classic and policy firewall rules fail closed', () => {
  const classic = postureFixture()
  classic.effective_firewalls.firewalls.unshift({ name: 'malformed-allow', network: NETWORK, direction: 'EGRESS', priority: '500', destinationRanges: ['0.0.0.0/0'], allowed: [{ IPProtocol: 'tcp', ports: ['443'] }] })
  assert.equal(evaluateGcpNetworkPosture(classic).ready, false)
  const policy = postureFixture()
  policy.workload_effective_firewalls.firewallPolicys = [{ type: 'SYSTEM_GLOBAL', rules: [{ priority: 1, direction: 'EGRESS', match: { destIpRanges: ['0.0.0.0/0'] } }] }]
  assert.equal(evaluateGcpNetworkPosture(policy).ready, false)
})

test('malformed VPC-SC policy fields and any extra restricted API fail closed', () => {
  const malformedEgress = postureFixture(); malformedEgress.perimeter.status.egressPolicies = {}
  assert.equal(evaluateGcpNetworkPosture(malformedEgress).ready, false)
  const malformedIngress = postureFixture(); malformedIngress.perimeter.status.ingressPolicies = 'none'
  assert.equal(evaluateGcpNetworkPosture(malformedIngress).ready, false)
  const extraService = postureFixture(); extraService.perimeter.status.restrictedServices.push('bigquery.googleapis.com')
  assert.equal(evaluateGcpNetworkPosture(extraService).ready, false)
  const duplicateService = postureFixture(); duplicateService.perimeter.status.restrictedServices.push(APPROVED_SERVICES[0])
  assert.equal(evaluateGcpNetworkPosture(duplicateService).ready, false)
})

test('network posture rejects a hardened decoy workload that is not the executing instance', () => {
  const wrong = postureFixture(); wrong.runtime_identity.instance_id = '111111111'
  assert.equal(evaluateGcpNetworkPosture(wrong).ready, false)
})

test('network collector derives workload lookup from authenticated runtime metadata', async () => {
  const runtimeIdentity = createGceRuntimeIdentityProvider({ fetch_impl: metadataFetch, test_only_allow_custom_fetch: true })
  const fixture = postureFixture(), calls = []
  const fetch_impl = async (url) => {
    calls.push(url)
    const body = url.includes('/regions/europe-west3/subnetworks/legal') ? fixture.subnetwork
      : url.includes('accesscontextmanager.googleapis.com') ? fixture.perimeter
      : url.includes('cloudresourcemanager.googleapis.com') ? { projectId: 'trustready-prod', name: 'projects/123' }
      : url.includes('/global/networks/legal/getEffectiveFirewalls') ? fixture.effective_firewalls
      : url.includes('/regions/europe-west3/firewallPolicies/getEffectiveFirewalls') ? fixture.regional_effective_firewalls
      : url.includes('/instances/trustready-legal-gateway/getEffectiveFirewalls') ? fixture.workload_effective_firewalls
      : url.includes('/instances/trustready-legal-gateway') ? fixture.workload : null
    return { ok: body !== null, status: body !== null ? 200 : 404, async json() { return structuredClone(body || {}) } }
  }
  const collector = createGcpNetworkPostureCollector({ project_id: 'trustready-prod', region: 'europe-west3', subnetwork: 'legal', service_perimeter_name: 'accessPolicies/1/servicePerimeters/legal', fetch_impl, token_provider: async () => 'synthetic-access-token-long-enough', runtime_identity_provider: runtimeIdentity })
  const result = await collector.collect()
  assert.equal(result.ready, true)
  assert.equal(result.protected_workload_instance_id, '987654321')
  assert.deepEqual(result.restricted_services, [...APPROVED_SERVICES].sort())
  assert.ok(calls.some((url) => url.includes('/zones/europe-west3-a/instances/trustready-legal-gateway')))
})

test('local audit evidence cannot self-promote organizational independence', () => {
  const verdict = evaluateLocalPromotionGates({ engineering: true, live_complete: true, legal_complete: true, independent_evidence_complete: true, distinct_trust_anchors: true, organizational_independence_claim: true })
  assert.equal(verdict.candidate_for_external_assurance, true)
  assert.equal(verdict.real_mandate_shadow_ready, false)
  assert.equal(verdict.independently_assured, false)
  assert.equal(verdict.external_final_verdict_required, true)
})
