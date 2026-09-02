import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { canonicalize, createRootedKeyTrustStore, issueIdentityAssertion, issueMatterAuthorization, publicKeyFingerprint, signEnvelopeWithSigner, signKeyring, sha256 } from './legal-key-identity.mjs'
import { signProviderPassport } from './legal-runtime-fortress.mjs'
import { runGcpMandateShadowPipeline } from './legal-gcp-runtime-pipeline.mjs'

const NOW = new Date('2026-09-02T12:00:00Z')
const root = crypto.generateKeyPairSync('ed25519')
const idp = crypto.generateKeyPairSync('ed25519')
const matter = crypto.generateKeyPairSync('ed25519')
const reviewer = crypto.generateKeyPairSync('ed25519')
const hsmDlp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const hsmEgress = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const hsmNetwork = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const hsmEvidence = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const keyIds = {
  dlp: 'projects/p/locations/europe-west3/keyRings/legal/cryptoKeys/dlp/cryptoKeyVersions/1',
  egress: 'projects/p/locations/europe-west3/keyRings/legal/cryptoKeys/egress/cryptoKeyVersions/1',
  network: 'projects/p/locations/europe-west3/keyRings/legal/cryptoKeys/network/cryptoKeyVersions/1',
  evidence: 'projects/p/locations/europe-west3/keyRings/legal/cryptoKeys/evidence/cryptoKeyVersions/1',
}

function hsmSigner(key_id, pair) {
  return {
    hardware_backed: true,
    async posture() { return { ready: true, provider: 'gcp-cloud-hsm', protection_level: 'HSM', algorithm: 'EC_SIGN_P256_SHA256', key_version_name: key_id, location: 'europe-west3', attestation_fingerprint: `sha256:${'a'.repeat(64)}` } },
    async sign({ body }) {
      const digest = crypto.createHash('sha256').update(Buffer.from(canonicalize(body))).digest()
      return { algorithm: 'ECDSA_P256_SHA256', key_id, value: crypto.sign(null, digest, pair.privateKey).toString('base64') }
    },
  }
}
const dlpSigner = hsmSigner(keyIds.dlp, hsmDlp)
const egressSigner = hsmSigner(keyIds.egress, hsmEgress)
const networkSigner = hsmSigner(keyIds.network, hsmNetwork)
const evidenceSigner = hsmSigner(keyIds.evidence, hsmEvidence)

const keyEntries = [
  { key_id: 'idp-1', purpose: 'identity', public_key: idp.publicKey },
  { key_id: 'matter-1', purpose: 'matter_authorization', public_key: matter.publicKey },
  { key_id: 'review-1', purpose: 'provider_review', public_key: reviewer.publicKey },
  { key_id: keyIds.dlp, purpose: 'dlp_attestation', public_key: hsmDlp.publicKey },
  { key_id: keyIds.egress, purpose: 'egress_enforcement', public_key: hsmEgress.publicKey },
  { key_id: keyIds.network, purpose: 'network_attestation', public_key: hsmNetwork.publicKey },
  { key_id: keyIds.evidence, purpose: 'evidence_manifest', public_key: hsmEvidence.publicKey },
].map((entry) => ({ ...entry, not_after: '2027-01-01T00:00:00Z' }))
const signedKeyring = signKeyring({ keys: keyEntries, version: 'legal-keys-v4', valid_until: '2026-12-31T00:00:00Z', private_key: root.privateKey, key_id: 'offline-root' })
function keyStore() { return createRootedKeyTrustStore({ signed_keyring: signedKeyring, pinned_root_public_key: root.publicKey, expected_root_fingerprint: publicKeyFingerprint(root.publicKey), now: NOW }) }

function identity() { return issueIdentityAssertion({ subject: 'bao', tenant_id: 'tenant-a', session_id: 's1', roles: ['lawyer'], matter_permissions: [{ matter_id: 'm1', operations: ['egress'] }], mfa: true, auth_time: '2026-09-02T11:59:00Z', expires_at: '2026-09-02T12:10:00Z', private_key: idp.privateKey, key_id: 'idp-1', now: NOW }) }
function matterAuth() { return issueMatterAuthorization({ subject: 'bao', tenant_id: 'tenant-a', session_id: 's1', matter_id: 'm1', operations: ['egress'], resource_version: 'matter-v9', expires_at: '2026-09-02T12:00:45Z', private_key: matter.privateKey, key_id: 'matter-1', now: NOW }) }
const safePayload = { subject_hash: `sha256:${'b'.repeat(64)}`, body_excerpt: 'Pseudonymised correspondence about a contractual deadline.' }
function provider() {
  return signProviderPassport({
    body: {
      policy_version: 'legal-v4', provider_id: 'vertex-eu', status: 'approved', valid_until: '2026-12-31T00:00:00Z', training_on_customer_data: false,
      avv_status: 'approved', brao_43e_status: 'approved', subprocessor_status: 'approved', third_country: false,
      use_cases: {
        summarise_mail: {
          allowed_zones: ['MANDATE'], regions: ['europe-west3'], max_retention_minutes: 0,
          allowed_fields: ['subject_hash', 'body_excerpt'], allowed_sensitive_keys: [], max_payload_bytes: 4096,
          endpoints: { 'europe-west3': ['https://europe-west3-aiplatform.googleapis.com'] }, network_profile: 'gcp-restricted-googleapis',
        },
      },
    }, private_key: reviewer.privateKey, key_id: 'review-1',
  })
}
function request() { return { actor_session_id: 's1', tenant_id: 'tenant-a', matter_id: 'm1', matter_version: 'matter-v9', provider_id: 'vertex-eu', zone: 'MANDATE', use_case: 'summarise_mail', purpose: 'triage correspondence', policy_version: 'legal-v4', region: 'europe-west3', endpoint: 'https://europe-west3-aiplatform.googleapis.com/v1/projects/p/locations/europe-west3/publishers/google/models/gemini:generateContent', retention_minutes: 0, payload: safePayload } }
const runtimeState = { production: true, external_ai_enabled: true, outbound_actions_enabled: false, policy_version: 'legal-v4', disabled_tenants: [], disabled_providers: [] }
const dlpScanner = { async inspect({ payload }) { return { safe: true, findings_count: 0, detected_categories: [], payload_fingerprint: `sha256:${sha256(canonicalize(payload))}`, payload_bytes: Buffer.byteLength(canonicalize(payload)), scanner_id: 'gcp-sensitive-data-protection', scanner_version: 'google-sensitive-data-protection-v2', scanner_location: 'eu' } } }
const networkCollector = { async collect() { return { ready: true, provider: 'gcp-vpc-service-controls', deny_by_default: true, only_restricted_google_apis: true, restricted_vip: '199.36.153.4/30', perimeter_name: 'legal', protected_resource: 'projects/123', deny_rule: 'deny-all', allow_rule: 'restricted-only' } } }
async function runtimeProbe({ endpoint, hostname, region, now }) { return signEnvelopeWithSigner({ body: { schema: 'trustready-network-attestation-v1', endpoint, hostname, region, tls: true, certificate_valid: true, redirected: false, route_class: 'restricted-googleapis', resolved_addresses: ['199.36.153.4'], peer_fingerprint: `sha256:${'c'.repeat(64)}`, observed_at: now.toISOString(), expires_at: new Date(now.getTime() + 30_000).toISOString() }, signer: networkSigner, purpose: 'network_attestation' }) }
function wormStore({ fail = false } = {}) {
  const writes = []
  return {
    writes,
    async append({ object_name, bytes }) {
      writes.push(object_name)
      if (fail) return { stored: false, reason: 'synthetic immutable-store outage' }
      return { stored: true, bucket: 'evidence', object_name, generation: String(writes.length), content_hash: `sha256:${sha256(Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes))}`, retention_expiration_time: '2026-10-02T12:00:00Z' }
    },
  }
}
function base(overrides = {}) { return { identity_assertion: identity(), matter_authorization: matterAuth(), request: request(), provider_passport: provider(), key_store: keyStore(), runtime_state: runtimeState, dlp_scanner: dlpScanner, dlp_signer: dlpSigner, network_collector: networkCollector, egress_signer: egressSigner, runtime_network_probe: runtimeProbe, evidence_signer: evidenceSigner, worm_store: wormStore(), release: 'r4', bundle_id: 'bao-shadow-001', now: NOW, ...overrides } }

test('full GCP mandate shadow pipeline produces CANDIDATE only after all runtime proofs and WORM commit', async () => {
  const args = base()
  const result = await runGcpMandateShadowPipeline(args)
  assert.equal(result.status, 'CANDIDATE')
  assert.equal(result.decision.allowed, true)
  assert.equal(result.proofs.network_profile, 'gcp-restricted-googleapis')
  assert.equal(args.worm_store.writes.at(-1), 'bundles/bao-shadow-001/COMMITTED.manifest.json')
})

test('HSM key reuse across security purposes blocks the pipeline', async () => {
  const reused = hsmSigner(keyIds.dlp, hsmDlp)
  const result = await runGcpMandateShadowPipeline(base({ egress_signer: reused }))
  assert.equal(result.code, 'HSM_KEY_REUSE_DENIED')
})

test('DLP outage or finding blocks before external egress and before WORM commit', async () => {
  for (const scanner of [
    { async inspect() { return { safe: false, reason: 'DLP service unavailable', payload_fingerprint: null } } },
    { async inspect() { return { safe: false, findings_count: 1, detected_categories: ['EMAIL_ADDRESS'], payload_fingerprint: 'sha256:x' } } },
  ]) {
    const store = wormStore()
    const result = await runGcpMandateShadowPipeline(base({ dlp_scanner: scanner, worm_store: store }))
    assert.equal(result.code, 'DLP_DENIED')
    assert.equal(store.writes.length, 0)
  }
})

test('forged route class or non-restricted resolved IP is rejected by existing legal network gate', async () => {
  const badProbe = async ({ endpoint, hostname, region, now }) => signEnvelopeWithSigner({ body: { schema: 'trustready-network-attestation-v1', endpoint, hostname, region, tls: true, certificate_valid: true, redirected: false, route_class: 'internet', resolved_addresses: ['8.8.8.8'], observed_at: now.toISOString(), expires_at: new Date(now.getTime() + 30_000).toISOString() }, signer: networkSigner, purpose: 'network_attestation' })
  const result = await runGcpMandateShadowPipeline(base({ runtime_network_probe: badProbe }))
  assert.equal(result.code, 'LEGAL_EGRESS_DENIED')
})

test('immutable evidence outage blocks CANDIDATE even after legal egress was allowed', async () => {
  const result = await runGcpMandateShadowPipeline(base({ worm_store: wormStore({ fail: true }) }))
  assert.equal(result.code, 'WORM_COMMIT_FAILED')
  assert.equal(result.status, 'NOT_READY')
})

test('provider without explicit restricted network profile cannot enter GCP production pipeline', async () => {
  const passport = provider(); passport.body.use_cases.summarise_mail.network_profile = undefined
  const result = await runGcpMandateShadowPipeline(base({ provider_passport: passport }))
  assert.equal(result.code, 'GCP_RESTRICTED_PROFILE_REQUIRED')
})
