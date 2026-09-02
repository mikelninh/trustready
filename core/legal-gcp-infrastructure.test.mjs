import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { canonicalize, createKeyTrustStore, signEnvelopeWithSigner, verifyEnvelope } from './legal-key-identity.mjs'
import { createGoogleCloudHsmSignerForTest, evaluateCloudHsmKeyPosture, isProductionGoogleCloudHsmSigner } from './legal-gcp-hsm.mjs'
import { createGoogleSensitiveDataScannerForTest, legalDlpConfigFingerprint, parseDlpInspectResponse } from './legal-gcp-dlp.mjs'
import { createGcpNetworkPostureCollectorForTest, evaluateGcpNetworkPosture } from './legal-gcp-network-enforcement.mjs'
import { createGceRuntimeIdentityProviderForTest } from './legal-gcp-runtime-identity.mjs'
import { createGcsWormEvidenceStoreForTest, evaluateBucketLockPosture } from './legal-gcp-worm.mjs'
import { qualifyGcpLegalInfrastructure } from './legal-gcp-qualification.mjs'

const NOW = new Date('2026-09-02T12:00:00Z')
const KEY_NAME = 'projects/trustready-prod/locations/europe-west3/keyRings/legal/cryptoKeys/root/cryptoKeyVersions/1'
const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const publicPem = ec.publicKey.export({ type: 'spki', format: 'pem' }).toString()
const hsmMetadata = { name: KEY_NAME, state: 'ENABLED', protectionLevel: 'HSM', algorithm: 'EC_SIGN_P256_SHA256', attestation: { format: 'CAVIUM_V2_COMPRESSED', content: Buffer.from('attestation').toString('base64') } }
const hsmPublic = { algorithm: 'EC_SIGN_P256_SHA256', pem: publicPem }
const DLP_CONFIG = legalDlpConfigFingerprint({ project_id: 'trustready-prod', location: 'eu' })
const token = async () => 'test-access-token-that-is-long-enough'
function jsonResponse(body, status = 200) { return { ok: status >= 200 && status < 300, status, async json() { return structuredClone(body) } } }

test('Cloud HSM posture requires enabled hardware key approved region algorithm and attestation', () => {
  assert.equal(evaluateCloudHsmKeyPosture({ metadata: hsmMetadata, public_key: hsmPublic, key_version_name: KEY_NAME, allowed_locations: ['europe-west3'] }).ready, true)
  for (const metadata of [{ ...hsmMetadata, state: 'DISABLED' }, { ...hsmMetadata, protectionLevel: 'SOFTWARE' }, { ...hsmMetadata, algorithm: 'RSA_SIGN_PKCS1_2048_SHA256' }, { ...hsmMetadata, attestation: undefined }]) assert.equal(evaluateCloudHsmKeyPosture({ metadata, public_key: hsmPublic, key_version_name: KEY_NAME, allowed_locations: ['europe-west3'] }).ready, false)
})

test('Cloud HSM test signer verifies metadata public key and fails closed on outage without becoming production signer', async () => {
  const calls = []
  const fetch_impl = async (url) => { calls.push(url); if (url.endsWith('/publicKey')) return jsonResponse(hsmPublic); if (url.endsWith(':asymmetricSign')) return jsonResponse({ name: KEY_NAME, signature: Buffer.from('signed-by-hsm').toString('base64') }); if (url.includes(KEY_NAME)) return jsonResponse(hsmMetadata); return jsonResponse({}, 404) }
  const signer = createGoogleCloudHsmSignerForTest({ key_version_name: KEY_NAME, fetch_impl, token_provider: token, allowed_locations: ['europe-west3'] })
  assert.equal(isProductionGoogleCloudHsmSigner(signer), false)
  assert.equal((await signer.posture()).ready, true)
  assert.equal((await signer.sign({ body: { hello: 'world' } })).algorithm, 'ECDSA_P256_SHA256')
  assert.ok(calls.some((url) => url.endsWith(':asymmetricSign')))
  const broken = createGoogleCloudHsmSignerForTest({ key_version_name: KEY_NAME, fetch_impl: async () => { throw new Error('offline') }, token_provider: token })
  await assert.rejects(() => broken.posture(), /GCP API request failed/)
})

test('ECDSA HSM-style envelope verification matches Cloud KMS SHA-256 semantics', async () => {
  const signer = { async sign({ body }) { return { algorithm: 'ECDSA_P256_SHA256', key_id: 'hsm-root', value: crypto.sign('sha256', Buffer.from(canonicalize(body)), ec.privateKey).toString('base64') } } }
  const envelope = await signEnvelopeWithSigner({ body: { policy: 'legal-v11' }, signer, purpose: 'trust_root' })
  const store = createKeyTrustStore([{ key_id: 'hsm-root', purpose: 'trust_root', public_key: ec.publicKey }])
  assert.equal(verifyEnvelope({ envelope, key_store: store, purpose: 'trust_root' }).valid, true)
  const tampered = { body: { ...envelope.body, policy: 'attacker' }, signature: { ...envelope.signature } }
  assert.equal(verifyEnvelope({ envelope: tampered, key_store: store, purpose: 'trust_root' }).valid, false)
})

test('Sensitive Data Protection test scanner pins config and fails closed on malformed response PII or outage', async () => {
  let requestBody
  const safeFetch = async (_url, options) => { requestBody = JSON.parse(options.body); return jsonResponse({ result: { findings: [] } }) }
  const scanner = createGoogleSensitiveDataScannerForTest({ project_id: 'trustready-prod', location: 'eu', fetch_impl: safeFetch, token_provider: token })
  const safe = await scanner.inspect({ payload: { body_excerpt: 'Pseudonymised excerpt' } })
  assert.equal(safe.safe, true); assert.equal(safe.scanner_config_fingerprint, DLP_CONFIG); assert.equal(requestBody.inspectConfig.includeQuote, false)
  assert.equal(parseDlpInspectResponse({}).safe, false)
  assert.deepEqual(parseDlpInspectResponse({ result: { findings: [{ infoType: { name: 'EMAIL_ADDRESS' } }, { infoType: { name: 'IBAN_CODE' } }] } }).detected_categories, ['EMAIL_ADDRESS', 'IBAN_CODE'])
  const malformed = createGoogleSensitiveDataScannerForTest({ project_id: 'trustready-prod', fetch_impl: async () => jsonResponse({}), token_provider: token }); assert.equal((await malformed.inspect({ payload: { body_excerpt: 'safe' } })).safe, false)
  const finding = createGoogleSensitiveDataScannerForTest({ project_id: 'trustready-prod', fetch_impl: async () => jsonResponse({ result: { findings: [{ infoType: { name: 'EMAIL_ADDRESS' } }] } }), token_provider: token }); assert.equal((await finding.inspect({ payload: { body_excerpt: 'person@example.com' } })).safe, false)
  const offline = createGoogleSensitiveDataScannerForTest({ project_id: 'trustready-prod', fetch_impl: async () => { throw new Error('offline') }, token_provider: token }); assert.equal((await offline.inspect({ payload: { body_excerpt: 'safe' } })).safe, false)
})

const NETWORK = 'https://www.googleapis.com/compute/v1/projects/trustready-prod/global/networks/legal'
const SUBNET = 'https://www.googleapis.com/compute/v1/projects/trustready-prod/regions/europe-west3/subnetworks/legal'
const SERVICE_ACCOUNT = 'trustready-legal-gateway@trustready-prod.iam.gserviceaccount.com'
const APPROVED_SERVICES = ['accesscontextmanager.googleapis.com','aiplatform.googleapis.com','cloudkms.googleapis.com','cloudresourcemanager.googleapis.com','compute.googleapis.com','dlp.googleapis.com','storage.googleapis.com']
const FIREWALLS = [{ name: 'allow-restricted-googleapis', network: NETWORK, direction: 'EGRESS', priority: 1000, destinationRanges: ['199.36.153.4/30'], allowed: [{ IPProtocol: 'tcp', ports: ['443'] }] },{ name: 'deny-all-egress', network: NETWORK, direction: 'EGRESS', priority: 2000, destinationRanges: ['0.0.0.0/0'], denied: [{ IPProtocol: 'all' }] }]
function effective() { return { firewalls: structuredClone(FIREWALLS), firewallPolicys: [] } }
function runtimeIdentity() { return { ready: true, provider: 'gce-local-metadata', metadata_flavor_verified: true, project_id: 'trustready-prod', instance_name: 'bao-shadow', instance_id: '987654321', zone: 'europe-west3-a', network_name: 'legal', subnetwork_name: 'legal', service_account_email: SERVICE_ACCOUNT } }
function goodNetwork() { return { effective_firewalls: effective(), regional_effective_firewalls: effective(), workload_effective_firewalls: effective(), subnetwork: { network: NETWORK, selfLink: SUBNET, privateIpGoogleAccess: true, stackType: 'IPV4_ONLY' }, workload: { id: '987654321', name: 'bao-shadow', zone: 'https://www.googleapis.com/compute/v1/projects/trustready-prod/zones/europe-west3-a', networkInterfaces: [{ name: 'nic0', network: NETWORK, subnetwork: SUBNET, accessConfigs: [], ipv6AccessConfigs: [], stackType: 'IPV4_ONLY' }], serviceAccounts: [{ email: SERVICE_ACCOUNT }] }, runtime_identity: runtimeIdentity(), perimeter: { name: 'accessPolicies/1/servicePerimeters/legal', status: { resources: ['projects/123'], restrictedServices: [...APPROVED_SERVICES], vpcAccessibleServices: { enableRestriction: true, allowedServices: ['RESTRICTED-SERVICES'] } } }, protected_resource: 'projects/123', project_id: 'trustready-prod', expected_nic: 'nic0' } }

test('network enforcement is bound to exact workload effective policy layers and IPv4-only posture', () => {
  assert.equal(evaluateGcpNetworkPosture(goodNetwork()).ready, true)
  const broad = goodNetwork(); broad.effective_firewalls.firewalls.unshift({ name: 'oops', network: NETWORK, direction: 'EGRESS', priority: 500, destinationRanges: ['0.0.0.0/0'], allowed: [{ IPProtocol: 'tcp', ports: ['443'] }] }); assert.equal(evaluateGcpNetworkPosture(broad).ready, false)
  const missingMatch = goodNetwork(); missingMatch.workload_effective_firewalls.firewallPolicys = [{ type: 'SYSTEM_GLOBAL', rules: [{ priority: 1, direction: 'EGRESS', action: 'deny' }] }]; assert.equal(evaluateGcpNetworkPosture(missingMatch).ready, false)
  const extra = goodNetwork(); extra.perimeter.status.restrictedServices.push('bigquery.googleapis.com'); assert.equal(evaluateGcpNetworkPosture(extra).ready, false)
})

function metadataResponse(value) { return { ok: true, status: 200, headers: { get(name) { return name.toLowerCase() === 'metadata-flavor' ? 'Google' : null } }, async text() { return value } } }
const metadata = { 'project/project-id': 'trustready-prod', 'instance/name': 'bao-shadow', 'instance/id': '987654321', 'instance/zone': 'projects/123/zones/europe-west3-a', 'instance/network-interfaces/0/network': 'projects/123/networks/legal', 'instance/network-interfaces/0/subnetwork': 'projects/123/regions/europe-west3/subnetworks/legal', 'instance/service-accounts/default/email': SERVICE_ACCOUNT }

test('network test collector fetches exact runtime workload and policy views without becoming production collector', async () => {
  const fixture = goodNetwork(), calls = []
  const runtime_identity_provider = createGceRuntimeIdentityProviderForTest({ fetch_impl: async (url) => metadataResponse(metadata[url.split('/computeMetadata/v1/')[1]]) })
  const fetch_impl = async (url) => { calls.push(url); if (url.includes('/regions/europe-west3/subnetworks/legal')) return jsonResponse(fixture.subnetwork); if (url.includes('accesscontextmanager.googleapis.com')) return jsonResponse(fixture.perimeter); if (url.includes('cloudresourcemanager.googleapis.com')) return jsonResponse({ projectId: 'trustready-prod', name: 'projects/123' }); if (url.includes('/global/networks/legal/getEffectiveFirewalls')) return jsonResponse(fixture.effective_firewalls); if (url.includes('/regions/europe-west3/firewallPolicies/getEffectiveFirewalls')) return jsonResponse(fixture.regional_effective_firewalls); if (url.includes('/instances/bao-shadow/getEffectiveFirewalls')) return jsonResponse(fixture.workload_effective_firewalls); if (url.includes('/instances/bao-shadow')) return jsonResponse(fixture.workload); return jsonResponse({}, 404) }
  const collector = createGcpNetworkPostureCollectorForTest({ project_id: 'trustready-prod', region: 'europe-west3', subnetwork: 'legal', service_perimeter_name: 'accessPolicies/1/servicePerimeters/legal', workload_nic: 'nic0', fetch_impl, token_provider: token, runtime_identity_provider })
  assert.equal((await collector.collect()).ready, true)
  assert.ok(calls.some((url) => url.includes('/zones/europe-west3-a/instances/bao-shadow')))
})

test('WORM test store requires locked retention and immutable generation receipt', async () => {
  const bucket = { name: 'trustready-evidence', retentionPolicy: { isLocked: true, retentionPeriod: String(31 * 24 * 60 * 60) }, iamConfiguration: { uniformBucketLevelAccess: { enabled: true }, publicAccessPrevention: 'enforced' } }
  assert.equal(evaluateBucketLockPosture({ bucket }).ready, true)
  const fetch_impl = async (url) => url.includes('/upload/') ? jsonResponse({ bucket: 'trustready-evidence', name: 'proof.json', generation: '1', retentionExpirationTime: '2026-10-03T00:00:00Z' }) : jsonResponse(bucket)
  const store = createGcsWormEvidenceStoreForTest({ bucket: 'trustready-evidence', fetch_impl, token_provider: token })
  const receipt = await store.append({ object_name: 'proof.json', bytes: Buffer.from('proof') })
  assert.equal(receipt.stored, true); assert.match(receipt.content_hash, /^sha256:/)
})

test('infrastructure qualification rejects test and self-asserted adapters instead of issuing synthetic candidate', async () => {
  const fakeHsm = { hardware_backed: true, async posture() { return { ready: true, protection_level: 'HSM', algorithm: 'EC_SIGN_P256_SHA256', key_version_name: KEY_NAME, attestation_fingerprint: `sha256:${'a'.repeat(64)}` } } }
  const scanner = createGoogleSensitiveDataScannerForTest({ project_id: 'trustready-prod', fetch_impl: async () => jsonResponse({ result: { findings: [] } }), token_provider: token })
  const runtime = createGceRuntimeIdentityProviderForTest({ fetch_impl: async (url) => metadataResponse(metadata[url.split('/computeMetadata/v1/')[1]]) })
  const network = createGcpNetworkPostureCollectorForTest({ project_id: 'trustready-prod', region: 'europe-west3', subnetwork: 'legal', service_perimeter_name: 'accessPolicies/1/servicePerimeters/legal', fetch_impl: async () => jsonResponse({}), token_provider: token, runtime_identity_provider: runtime })
  const worm = createGcsWormEvidenceStoreForTest({ bucket: 'trustready-evidence', fetch_impl: async () => jsonResponse({}), token_provider: token })
  const result = await qualifyGcpLegalInfrastructure({ hsm_signers: { dlp: fakeHsm, egress: fakeHsm, network: fakeHsm, evidence: fakeHsm }, dlp_scanner: scanner, network_collector: network, worm_store: worm, tenant_id: 'tenant-a', policy_version: 'v11', release: 'r11', now: NOW })
  assert.equal(result.status, 'NOT_READY'); assert.equal(result.code, 'PRODUCTION_DLP_ADAPTER_REQUIRED')
})
