import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { canonicalize, createKeyTrustStore, signEnvelopeWithSigner, verifyEnvelope } from './legal-key-identity.mjs'
import { createGoogleCloudHsmSigner, evaluateCloudHsmKeyPosture } from './legal-gcp-hsm.mjs'
import { createGoogleSensitiveDataScanner, parseDlpInspectResponse } from './legal-gcp-dlp.mjs'
import { evaluateGcpNetworkPosture } from './legal-gcp-network-enforcement.mjs'
import { createGcsWormEvidenceStore, evaluateBucketLockPosture } from './legal-gcp-worm.mjs'
import { qualifyGcpLegalInfrastructure } from './legal-gcp-qualification.mjs'

const KEY_NAME = 'projects/trustready-prod/locations/europe-west3/keyRings/legal/cryptoKeys/root/cryptoKeyVersions/1'
const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const publicPem = ec.publicKey.export({ type: 'spki', format: 'pem' }).toString()
const hsmMetadata = { name: KEY_NAME, state: 'ENABLED', protectionLevel: 'HSM', algorithm: 'EC_SIGN_P256_SHA256', attestation: { format: 'CAVIUM_V2_COMPRESSED', content: Buffer.from('attestation').toString('base64') } }
const hsmPublic = { algorithm: 'EC_SIGN_P256_SHA256', pem: publicPem }

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

test('ECDSA HSM-style envelope verification checks the precomputed SHA-256 digest exactly once', async () => {
  const signer = {
    async sign({ body }) {
      const digest = crypto.createHash('sha256').update(Buffer.from(canonicalize(body))).digest()
      const signature = crypto.sign(null, digest, ec.privateKey).toString('base64')
      return { algorithm: 'ECDSA_P256_SHA256', key_id: 'hsm-root', value: signature }
    },
  }
  const envelope = await signEnvelopeWithSigner({ body: { policy: 'legal-v4' }, signer, purpose: 'trust_root' })
  const store = createKeyTrustStore([{ key_id: 'hsm-root', purpose: 'trust_root', public_key: ec.publicKey }])
  assert.equal(verifyEnvelope({ envelope, key_store: store, purpose: 'trust_root' }).valid, true)
  envelope.body.policy = 'attacker'
  assert.equal(verifyEnvelope({ envelope, key_store: store, purpose: 'trust_root' }).valid, false)
})

test('Sensitive Data Protection scanner sends no quotes and fails closed on detected PII or outage', async () => {
  let requestBody
  const safeFetch = async (_url, options) => { requestBody = JSON.parse(options.body); return jsonResponse({ result: { findings: [] } }) }
  const scanner = createGoogleSensitiveDataScanner({ project_id: 'trustready-prod', location: 'eu', fetch_impl: safeFetch, token_provider: token, info_types: ['EMAIL_ADDRESS', 'IBAN_CODE'] })
  const safe = await scanner.inspect({ payload: { body_excerpt: 'Pseudonymised excerpt' } })
  assert.equal(safe.safe, true)
  assert.equal(requestBody.inspectConfig.includeQuote, false)
  assert.deepEqual(parseDlpInspectResponse({ result: { findings: [{ infoType: { name: 'EMAIL_ADDRESS' } }, { infoType: { name: 'IBAN_CODE' } }] } }).detected_categories, ['EMAIL_ADDRESS', 'IBAN_CODE'])
  const findingScanner = createGoogleSensitiveDataScanner({ project_id: 'trustready-prod', fetch_impl: async () => jsonResponse({ result: { findings: [{ infoType: { name: 'EMAIL_ADDRESS' } }] } }), token_provider: token, info_types: ['EMAIL_ADDRESS'] })
  assert.equal((await findingScanner.inspect({ payload: { body_excerpt: 'person@example.com' } })).safe, false)
  const offline = createGoogleSensitiveDataScanner({ project_id: 'trustready-prod', fetch_impl: async () => { throw new Error('offline') }, token_provider: token, info_types: ['EMAIL_ADDRESS'] })
  assert.equal((await offline.inspect({ payload: { body_excerpt: 'safe' } })).safe, false)
})

function goodNetwork() {
  return {
    firewalls: { items: [
      { name: 'allow-restricted-googleapis', direction: 'EGRESS', priority: 1000, destinationRanges: ['199.36.153.4/30'], allowed: [{ IPProtocol: 'tcp', ports: ['443'] }] },
      { name: 'deny-all-egress', direction: 'EGRESS', priority: 2000, destinationRanges: ['0.0.0.0/0'], denied: [{ IPProtocol: 'all' }] },
    ] },
    subnetwork: { privateIpGoogleAccess: true },
    instances: { items: { 'zones/europe-west3-a': { instances: [{ networkInterfaces: [{ accessConfigs: [] }] }] } } },
    perimeter: { name: 'accessPolicies/1/servicePerimeters/legal', status: { resources: ['projects/123'], restrictedServices: ['aiplatform.googleapis.com', 'storage.googleapis.com', 'dlp.googleapis.com', 'cloudkms.googleapis.com'] } },
    protected_resource: 'projects/123',
  }
}

test('network enforcement requires deny-all, only restricted VIP allow, no public IP and enforced service perimeter', () => {
  assert.equal(evaluateGcpNetworkPosture(goodNetwork()).ready, true)
  const broad = goodNetwork(); broad.firewalls.items.unshift({ name: 'oops', direction: 'EGRESS', priority: 500, destinationRanges: ['0.0.0.0/0'], allowed: [{ IPProtocol: 'tcp', ports: ['443'] }] })
  assert.equal(evaluateGcpNetworkPosture(broad).ready, false)
  const publicIp = goodNetwork(); publicIp.instances.items['zones/europe-west3-a'].instances[0].networkInterfaces[0].accessConfigs = [{ natIP: '1.2.3.4' }]
  assert.equal(evaluateGcpNetworkPosture(publicIp).ready, false)
  const dry = goodNetwork(); dry.perimeter.useExplicitDryRunSpec = true
  assert.equal(evaluateGcpNetworkPosture(dry).ready, false)
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

test('end-to-end qualification becomes CANDIDATE only after HSM + DLP + network + immutable write all prove themselves', async () => {
  const hsm_signer = { async posture() { return { ready: true, provider: 'gcp-cloud-hsm', protection_level: 'HSM', key_version_name: KEY_NAME, location: 'europe-west3', algorithm: 'EC_SIGN_P256_SHA256', public_key_fingerprint: 'sha256:key', attestation_fingerprint: 'sha256:att' } }, async sign() { return { algorithm: 'ECDSA_P256_SHA256', key_id: KEY_NAME, value: Buffer.from('sig').toString('base64') } } }
  let scans = 0
  const dlp_scanner = { async inspect() { scans++; return scans === 1 ? { safe: true, payload_fingerprint: 'sha256:safe', scanner_id: 'gcp-sensitive-data-protection', scanner_location: 'eu', detected_categories: [] } : { safe: false, payload_fingerprint: 'sha256:pii', scanner_id: 'gcp-sensitive-data-protection', scanner_location: 'eu', detected_categories: ['EMAIL_ADDRESS', 'IBAN_CODE'] } } }
  const network_collector = { async collect() { return { ready: true, deny_by_default: true, only_restricted_google_apis: true, provider: 'gcp-vpc-service-controls', restricted_vip: '199.36.153.4/30', perimeter_name: 'legal', deny_rule: 'deny-all', allow_rule: 'restricted-only' } } }
  const worm_store = { async posture() { return { ready: true, retention_locked: true, provider: 'gcs-bucket-lock', bucket: 'evidence', retention_seconds: 2592000 } }, async append({ bytes }) { return { stored: true, bucket: 'evidence', object_name: 'proof', generation: '1', content_hash: `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`, retention_expiration_time: '2026-10-02T12:00:00Z' } } }
  const result = await qualifyGcpLegalInfrastructure({ hsm_signer, dlp_scanner, network_collector, worm_store, tenant_id: 'tenant-a', policy_version: 'legal-v4', release: 'r4', now: new Date('2026-09-02T12:00:00Z') })
  assert.equal(result.status, 'CANDIDATE')
  assert.deepEqual(result.controls, { hsm: true, dlp: true, network: true, worm: true })
  const falseNegative = { ...dlp_scanner, async inspect() { return { safe: true, payload_fingerprint: 'sha256:x', detected_categories: [] } } }
  assert.equal((await qualifyGcpLegalInfrastructure({ hsm_signer, dlp_scanner: falseNegative, network_collector, worm_store, tenant_id: 'tenant-a', policy_version: 'legal-v4', release: 'r4' })).code, 'DLP_FALSE_NEGATIVE')
})
