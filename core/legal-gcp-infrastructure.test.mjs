import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { canonicalize, createKeyTrustStore, signEnvelopeWithSigner, verifyEnvelope } from './legal-key-identity.mjs'
import { createGoogleCloudHsmSigner, evaluateCloudHsmKeyPosture } from './legal-gcp-hsm.mjs'
import { createGoogleSensitiveDataScanner, legalDlpConfigFingerprint, parseDlpInspectResponse } from './legal-gcp-dlp.mjs'
import { createGcpNetworkPostureCollector, evaluateGcpNetworkPosture } from './legal-gcp-network-enforcement.mjs'
import { createGceRuntimeIdentityProvider } from './legal-gcp-runtime-identity.mjs'
import { createGcsWormEvidenceStore, evaluateBucketLockPosture } from './legal-gcp-worm.mjs'
import { qualifyGcpLegalInfrastructure } from './legal-gcp-qualification.mjs'

const KEY_NAME = 'projects/trustready-prod/locations/europe-west3/keyRings/legal/cryptoKeys/root/cryptoKeyVersions/1'
const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const publicPem = ec.publicKey.export({ type: 'spki', format: 'pem' }).toString()
const hsmMetadata = { name: KEY_NAME, state: 'ENABLED', protectionLevel: 'HSM', algorithm: 'EC_SIGN_P256_SHA256', attestation: { format: 'CAVIUM_V2_COMPRESSED', content: Buffer.from('attestation').toString('base64') } }
const hsmPublic = { algorithm: 'EC_SIGN_P256_SHA256', pem: publicPem }
const DLP_CONFIG = legalDlpConfigFingerprint()

function jsonResponse(body, status = 200) { return { ok: status >= 200 && status < 300, status, async json() { return structuredClone(body) } } }
const token = async () => 'test-access-token-that-is-long-enough'

test('Cloud HSM posture requires enabled hardware key, approved region, algorithm and attestation', () => {
  assert.equal(evaluateCloudHsmKeyPosture({ metadata: hsmMetadata, public_key: hsmPublic, key_version_name: KEY_NAME, allowed_locations: ['europe-west3'] }).ready, true)
  for (const metadata of [
    { ...hsmMetadata, state: 'DISABLED' }, { ...hsmMetadata, protectionLevel: 'SOFTWARE' },
    { ...hsmMetadata, algorithm: 'RSA_SIGN_PKCS1_2048_SHA256' }, { ...hsmMetadata, attestation: undefined },
  ]) assert.equal(evaluateCloudHsmKeyPosture({ metadata, public_key: hsmPublic, key_version_name: KEY_NAME, allowed_locations: ['europe-west3'] }).ready, false)
  assert.equal(evaluateCloudHsmKeyPosture({ metadata: hsmMetadata, public_key: hsmPublic, key_version_name: KEY_NAME, allowed_locations: ['us-central1'] }).ready, false)
})

test('Cloud HSM signer performs metadata/public-key checks before asymmetric signing and fails closed on outage', async () => {
  const calls = []
  const fetch_impl = async (url, options = {}) => {
    calls.push([url, options.method || 'GET'])
    if (url.endsWith('/publicKey')) return jsonResponse(hsmPublic)
    if (url.endsWith(':asymmetricSign')) return jsonResponse({ name: KEY_NAME, signature: Buffer.from('signed-by-hsm').toString('base64') })
    if (url.includes(KEY_NAME)) return jsonResponse(hsmMetadata)
    return jsonResponse({}, 404)
  }
  const signer = createGoogleCloudHsmSigner({ key_version_name: KEY_NAME, fetch_impl, token_provider: token, allowed_locations: ['europe-west3'] })
  const posture = await signer.posture()
  assert.equal(posture.ready, true)
  const signature = await signer.sign({ body: { hello: 'world' } })
  assert.equal(signature.algorithm, 'ECDSA_P256_SHA256')
  assert.ok(calls.some(([url]) => url.endsWith(':asymmetricSign')))
  const broken = createGoogleCloudHsmSigner({ key_version_name: KEY_NAME, fetch_impl: async () => { throw new Error('offline') }, token_provider: token })
  await assert.rejects(() => broken.posture(), /GCP API request failed/)
})

test('ECDSA HSM-style envelope verification matches Cloud KMS SHA-256 semantics', async () => {
  const signer = {
    async sign({ body }) {
      const canonical = Buffer.from(canonicalize(body))
      const signature = crypto.sign('sha256', canonical, ec.privateKey).toString('base64')
      return { algorithm: 'ECDSA_P256_SHA256', key_id: 'hsm-root', value: signature }
    },
  }
  const envelope = await signEnvelopeWithSigner({ body: { policy: 'legal-v4' }, signer, purpose: 'trust_root' })
  const store = createKeyTrustStore([{ key_id: 'hsm-root', purpose: 'trust_root', public_key: ec.publicKey }])
  assert.equal(verifyEnvelope({ envelope, key_store: store, purpose: 'trust_root' }).valid, true)
  envelope.body.policy = 'attacker'
  assert.equal(verifyEnvelope({ envelope, key_store: store, purpose: 'trust_root' }).valid, false)
})

test('Sensitive Data Protection scanner pins config and fails closed on malformed response, PII or outage', async () => {
  let requestBody
  const safeFetch = async (_url, options) => { requestBody = JSON.parse(options.body); return jsonResponse({ result: { findings: [] } }) }
  const scanner = createGoogleSensitiveDataScanner({ project_id: 'trustready-prod', location: 'eu', fetch_impl: safeFetch, token_provider: token })
  const safe = await scanner.inspect({ payload: { body_excerpt: 'Pseudonymised excerpt' } })
  assert.equal(safe.safe, true)
  assert.equal(safe.scanner_config_fingerprint, DLP_CONFIG)
  assert.equal(requestBody.inspectConfig.includeQuote, false)
  assert.equal(parseDlpInspectResponse({}).safe, false)
  assert.equal(parseDlpInspectResponse({}).valid, false)
  assert.deepEqual(parseDlpInspectResponse({ result: { findings: [{ infoType: { name: 'EMAIL_ADDRESS' } }, { infoType: { name: 'IBAN_CODE' } }] } }).detected_categories, ['EMAIL_ADDRESS', 'IBAN_CODE'])
  const malformed = createGoogleSensitiveDataScanner({ project_id: 'trustready-prod', fetch_impl: async () => jsonResponse({}), token_provider: token })
  assert.equal((await malformed.inspect({ payload: { body_excerpt: 'safe' } })).safe, false)
  const findingScanner = createGoogleSensitiveDataScanner({ project_id: 'trustready-prod', fetch_impl: async () => jsonResponse({ result: { findings: [{ infoType: { name: 'EMAIL_ADDRESS' } }] } }), token_provider: token })
  assert.equal((await findingScanner.inspect({ payload: { body_excerpt: 'person@example.com' } })).safe, false)
  const offline = createGoogleSensitiveDataScanner({ project_id: 'trustready-prod', fetch_impl: async () => { throw new Error('offline') }, token_provider: token })
  assert.equal((await offline.inspect({ payload: { body_excerpt: 'safe' } })).safe, false)
})

const NETWORK = 'https://www.googleapis.com/compute/v1/projects/trustready-prod/global/networks/legal'
const SUBNET = 'https://www.googleapis.com/compute/v1/projects/trustready-prod/regions/europe-west3/subnetworks/legal'
const SERVICE_ACCOUNT = 'trustready-legal-gateway@trustready-prod.iam.gserviceaccount.com'
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
  { name: 'allow-restricted-googleapis', network: NETWORK, direction: 'EGRESS', priority: 1000, destinationRanges: ['199.36.153.4/30'], allowed: [{ IPProtocol: 'tcp', ports: ['443'] }] },
  { name: 'deny-all-egress', network: NETWORK, direction: 'EGRESS', priority: 2000, destinationRanges: ['0.0.0.0/0'], denied: [{ IPProtocol: 'all' }] },
]
function effective() { return { firewalls: structuredClone(FIREWALLS), firewallPolicys: [] } }
function runtimeIdentity() { return { ready: true, provider: 'gce-local-metadata', metadata_flavor_verified: true, project_id: 'trustready-prod', instance_name: 'bao-shadow', instance_id: '987654321', zone: 'europe-west3-a', network_name: 'legal', subnetwork_name: 'legal', service_account_email: SERVICE_ACCOUNT } }
function goodNetwork() {
  return {
    effective_firewalls: effective(),
    regional_effective_firewalls: effective(),
    workload_effective_firewalls: effective(),
    subnetwork: { network: NETWORK, selfLink: SUBNET, privateIpGoogleAccess: true, stackType: 'IPV4_ONLY' },
    workload: { id: '987654321', name: 'bao-shadow', zone: 'https://www.googleapis.com/compute/v1/projects/trustready-prod/zones/europe-west3-a', networkInterfaces: [{ name: 'nic0', network: NETWORK, subnetwork: SUBNET, accessConfigs: [], ipv6AccessConfigs: [], stackType: 'IPV4_ONLY' }], serviceAccounts: [{ email: SERVICE_ACCOUNT }] },
    runtime_identity: runtimeIdentity(),
    perimeter: { name: 'accessPolicies/1/servicePerimeters/legal', status: { resources: ['projects/123'], restrictedServices: [...APPROVED_SERVICES], vpcAccessibleServices: { enableRestriction: true, allowedServices: ['RESTRICTED-SERVICES'] } } },
    protected_resource: 'projects/123',
    project_id: 'trustready-prod',
    expected_nic: 'nic0',
  }
}

test('network enforcement is bound to exact workload effective policy layers and IPv4-only posture', () => {
  const good = evaluateGcpNetworkPosture(goodNetwork())
  assert.equal(good.ready, true)
  assert.equal(good.protected_workload, 'bao-shadow')
  assert.equal(good.protected_workload_instance_id, '987654321')
  assert.equal(good.effective_policy_layers_checked, true)
  assert.deepEqual(good.restricted_services, [...APPROVED_SERVICES].sort())

  const broad = goodNetwork(); broad.effective_firewalls.firewalls.unshift({ name: 'oops', network: NETWORK, direction: 'EGRESS', priority: 500, destinationRanges: ['0.0.0.0/0'], allowed: [{ IPProtocol: 'tcp', ports: ['443'] }] })
  assert.equal(evaluateGcpNetworkPosture(broad).ready, false)
  const wrongVpc = goodNetwork(); wrongVpc.effective_firewalls.firewalls = wrongVpc.effective_firewalls.firewalls.map((rule) => ({ ...rule, network: `${NETWORK}-other` }))
  assert.equal(evaluateGcpNetworkPosture(wrongVpc).ready, false)
  const targeted = goodNetwork(); targeted.effective_firewalls.firewalls[1].targetServiceAccounts = ['only-one@project.iam.gserviceaccount.com']
  assert.equal(evaluateGcpNetworkPosture(targeted).ready, false)

  const hierarchy = goodNetwork(); hierarchy.effective_firewalls.firewallPolicys = [{ type: 'HIERARCHY', name: 'org-policy', rules: [{ priority: 100, direction: 'EGRESS', action: 'allow', match: { destIpRanges: ['0.0.0.0/0'] } }] }]
  assert.equal(evaluateGcpNetworkPosture(hierarchy).ready, false)
  const regionalPolicy = goodNetwork(); regionalPolicy.regional_effective_firewalls.firewallPolicys = [{ type: 'NETWORK_REGIONAL', name: 'region-policy', rules: [{ priority: 100, direction: 'EGRESS', action: 'allow' }] }]
  assert.equal(evaluateGcpNetworkPosture(regionalPolicy).ready, false)
  const systemAllow = goodNetwork(); systemAllow.workload_effective_firewalls.firewallPolicys = [{ type: 'SYSTEM_GLOBAL', name: 'system', rules: [{ priority: 1, direction: 'EGRESS', action: 'allow' }] }]
  assert.equal(evaluateGcpNetworkPosture(systemAllow).ready, false)

  const wrongWorkload = goodNetwork(); wrongWorkload.workload.name = 'unrelated-vm'
  assert.equal(evaluateGcpNetworkPosture(wrongWorkload).ready, false)
  const wrongInstanceId = goodNetwork(); wrongInstanceId.runtime_identity.instance_id = '1'
  assert.equal(evaluateGcpNetworkPosture(wrongInstanceId).ready, false)
  const extraNic = goodNetwork(); extraNic.workload.networkInterfaces.push({ name: 'nic1', network: `${NETWORK}-other`, stackType: 'IPV4_ONLY' })
  assert.equal(evaluateGcpNetworkPosture(extraNic).ready, false)
  const publicIp = goodNetwork(); publicIp.workload.networkInterfaces[0].accessConfigs = [{ natIP: '1.2.3.4' }]
  assert.equal(evaluateGcpNetworkPosture(publicIp).ready, false)
  const publicIpv6 = goodNetwork(); publicIpv6.workload.networkInterfaces[0].ipv6AccessConfigs = [{ externalIpv6: '2001:db8::1' }]
  assert.equal(evaluateGcpNetworkPosture(publicIpv6).ready, false)
  const dualStack = goodNetwork(); dualStack.subnetwork.stackType = 'IPV4_IPV6'; dualStack.workload.networkInterfaces[0].stackType = 'IPV4_IPV6'
  assert.equal(evaluateGcpNetworkPosture(dualStack).ready, false)
  const dry = goodNetwork(); dry.perimeter.useExplicitDryRunSpec = true
  assert.equal(evaluateGcpNetworkPosture(dry).ready, false)
  const escape = goodNetwork(); escape.perimeter.status.egressPolicies = [{ egressTo: { resources: ['*'] } }]
  assert.equal(evaluateGcpNetworkPosture(escape).ready, false)
  const missingAccessible = goodNetwork(); delete missingAccessible.perimeter.status.vpcAccessibleServices
  assert.equal(evaluateGcpNetworkPosture(missingAccessible).ready, false)
  const malformedPolicy = goodNetwork(); delete malformedPolicy.workload_effective_firewalls.firewallPolicys
  assert.equal(evaluateGcpNetworkPosture(malformedPolicy).ready, false)
})

function metadataResponse(value) { return { ok: true, status: 200, headers: { get(name) { return name.toLowerCase() === 'metadata-flavor' ? 'Google' : null } }, async text() { return value } } }
const metadata = {
  'project/project-id': 'trustready-prod', 'instance/name': 'bao-shadow', 'instance/id': '987654321',
  'instance/zone': 'projects/123/zones/europe-west3-a', 'instance/network-interfaces/0/network': 'projects/123/networks/legal',
  'instance/network-interfaces/0/subnetwork': 'projects/123/regions/europe-west3/subnetworks/legal', 'instance/service-accounts/default/email': SERVICE_ACCOUNT,
}

test('network collector fetches effective global regional and exact runtime workload NIC firewall views', async () => {
  const fixture = goodNetwork()
  const calls = []
  const metadataFetch = async (url) => metadataResponse(metadata[url.split('/computeMetadata/v1/')[1]])
  const runtime_identity_provider = createGceRuntimeIdentityProvider({ fetch_impl: metadataFetch, test_only_allow_custom_fetch: true })
  const fetch_impl = async (url) => {
    calls.push(url)
    if (url.includes('/regions/europe-west3/subnetworks/legal')) return jsonResponse(fixture.subnetwork)
    if (url.includes('accesscontextmanager.googleapis.com')) return jsonResponse(fixture.perimeter)
    if (url.includes('cloudresourcemanager.googleapis.com')) return jsonResponse({ projectId: 'trustready-prod', name: 'projects/123' })
    if (url.includes('/global/networks/legal/getEffectiveFirewalls')) return jsonResponse(fixture.effective_firewalls)
    if (url.includes('/regions/europe-west3/firewallPolicies/getEffectiveFirewalls')) return jsonResponse(fixture.regional_effective_firewalls)
    if (url.includes('/instances/bao-shadow/getEffectiveFirewalls')) return jsonResponse(fixture.workload_effective_firewalls)
    if (url.includes('/instances/bao-shadow')) return jsonResponse(fixture.workload)
    return jsonResponse({}, 404)
  }
  const collector = createGcpNetworkPostureCollector({ project_id: 'trustready-prod', region: 'europe-west3', subnetwork: 'legal', service_perimeter_name: 'accessPolicies/1/servicePerimeters/legal', workload_nic: 'nic0', fetch_impl, token_provider: token, runtime_identity_provider })
  const posture = await collector.collect()
  assert.equal(posture.ready, true)
  assert.equal(posture.protected_workload_instance_id, '987654321')
  assert.deepEqual(posture.restricted_services, [...APPROVED_SERVICES].sort())
  assert.ok(calls.some((url) => url.includes('/global/networks/legal/getEffectiveFirewalls')))
  assert.ok(calls.some((url) => url.includes('/regions/europe-west3/firewallPolicies/getEffectiveFirewalls')))
  assert.ok(calls.some((url) => url.includes('/instances/bao-shadow/getEffectiveFirewalls')))
})

test('WORM posture requires permanently locked retention, uniform access and public-access prevention', async () => {
  const bucket = { name: 'trustready-legal-evidence', retentionPolicy: { isLocked: true, retentionPeriod: '2592000' }, iamConfiguration: { uniformBucketLevelAccess: { enabled: true }, publicAccessPrevention: 'enforced' } }
  assert.equal(evaluateBucketLockPosture({ bucket }).ready, true)
  assert.equal(evaluateBucketLockPosture({ bucket: { ...bucket, retentionPolicy: { isLocked: false, retentionPeriod: '2592000' } } }).ready, false)
  const fetch_impl = async (url) => {
    if (url.includes('/upload/storage/v1/b/')) return jsonResponse({ bucket: bucket.name, name: 'proof.json', generation: '7', metageneration: '1', retentionExpirationTime: '2026-10-02T12:00:00Z' })
    if (url.includes('/storage/v1/b/')) return jsonResponse(bucket)
    return jsonResponse({}, 404)
  }
  const store = createGcsWormEvidenceStore({ bucket: bucket.name, fetch_impl, token_provider: token })
  const result = await store.append({ object_name: 'proof.json', bytes: Buffer.from('proof') })
  assert.equal(result.stored, true)
})

function qualificationSigner(name) {
  const keyName = `projects/trustready-prod/locations/europe-west3/keyRings/legal/cryptoKeys/${name}/cryptoKeyVersions/1`
  return { hardware_backed: true, async posture() { return { ready: true, provider: 'gcp-cloud-hsm', protection_level: 'HSM', key_version_name: keyName, location: 'europe-west3', algorithm: 'EC_SIGN_P256_SHA256', public_key_fingerprint: `sha256:${'1'.repeat(64)}`, attestation_fingerprint: `sha256:${'2'.repeat(64)}` } }, async sign() { return { algorithm: 'ECDSA_P256_SHA256', key_id: keyName, value: Buffer.from('synthetic-signature-that-is-long-enough').toString('base64') } } }
}
function qualificationSigners() { return { dlp: qualificationSigner('dlp'), egress: qualificationSigner('egress'), network: qualificationSigner('network'), evidence: qualificationSigner('evidence') } }

test('end-to-end qualification requires four purpose-separated HSM CryptoKeys plus DLP network and WORM proof', async () => {
  let scans = 0
  const dlp_scanner = { async inspect() { scans++; return scans === 1 ? { safe: true, payload_fingerprint: 'sha256:safe', scanner_id: 'gcp-sensitive-data-protection', scanner_version: 'google-sensitive-data-protection-v3', scanner_location: 'eu', scanner_config_fingerprint: DLP_CONFIG, detected_categories: [] } : { safe: false, payload_fingerprint: 'sha256:pii', scanner_id: 'gcp-sensitive-data-protection', scanner_version: 'google-sensitive-data-protection-v3', scanner_location: 'eu', scanner_config_fingerprint: DLP_CONFIG, detected_categories: ['EMAIL_ADDRESS', 'IBAN_CODE'] } } }
  const network_collector = { async collect() { return { ready: true, deny_by_default: true, only_restricted_google_apis: true, provider: 'gcp-vpc-service-controls', restricted_vip: '199.36.153.4/30', restricted_services: [...APPROVED_SERVICES], perimeter_name: 'legal', protected_network: NETWORK, protected_subnetwork: SUBNET, protected_workload: 'bao-shadow', protected_workload_instance_id: '987654321', protected_workload_zone: 'europe-west3-a', protected_workload_nic: 'nic0', protected_service_account: SERVICE_ACCOUNT, runtime_identity_provider: 'gce-local-metadata', runtime_metadata_flavor_verified: true, ipv4_only: true, effective_policy_layers_checked: true, protected_resource: 'projects/123', deny_rule: 'deny-all', allow_rule: 'restricted-only' } } }
  const worm_store = { async posture() { return { ready: true, retention_locked: true, provider: 'gcs-bucket-lock', bucket: 'evidence', retention_seconds: 2592000 } }, async append({ bytes }) { return { stored: true, bucket: 'evidence', object_name: 'proof', generation: '1', content_hash: `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`, retention_expiration_time: '2026-10-02T12:00:00Z' } } }
  const result = await qualifyGcpLegalInfrastructure({ hsm_signers: qualificationSigners(), dlp_scanner, network_collector, worm_store, tenant_id: 'tenant-a', policy_version: 'legal-v4', release: 'r4', now: new Date('2026-09-02T12:00:00Z') })
  assert.equal(result.status, 'CANDIDATE')
  assert.equal(result.controls.hsm_key_separation, true)
  const reused = qualificationSigners(); reused.network = reused.dlp
  assert.equal((await qualifyGcpLegalInfrastructure({ hsm_signers: reused, dlp_scanner, network_collector, worm_store, tenant_id: 'tenant-a', policy_version: 'legal-v4', release: 'r4' })).code, 'HSM_NOT_READY')
  const falseNegative = { async inspect() { return { safe: true, payload_fingerprint: 'sha256:x', scanner_config_fingerprint: DLP_CONFIG, detected_categories: [] } } }
  assert.equal((await qualifyGcpLegalInfrastructure({ hsm_signers: qualificationSigners(), dlp_scanner: falseNegative, network_collector, worm_store, tenant_id: 'tenant-a', policy_version: 'legal-v4', release: 'r4' })).code, 'DLP_FALSE_NEGATIVE')
})
