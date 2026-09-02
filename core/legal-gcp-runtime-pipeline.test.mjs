import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { EventEmitter } from 'node:events'
import { canonicalize, createRootedKeyTrustStore, issueIdentityAssertion, issueMatterAuthorization, publicKeyFingerprint, signKeyring, sha256 } from './legal-key-identity.mjs'
import { legalDlpConfigFingerprint } from './legal-gcp-dlp.mjs'
import { signProviderPassport } from './legal-runtime-fortress.mjs'
import { createRestrictedGoogleApiTransport } from './legal-gcp-bound-transport.mjs'
import { runGcpMandateShadowPipeline } from './legal-gcp-runtime-pipeline.mjs'

const NOW = new Date('2026-09-02T12:00:00Z')
const DLP_CONFIG = legalDlpConfigFingerprint()
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
    async posture() { return { ready: true, provider: 'gcp-cloud-hsm', protection_level: 'HSM', algorithm: 'EC_SIGN_P256_SHA256', key_version_name: key_id, location: 'europe-west3', public_key_fingerprint: `sha256:${'9'.repeat(64)}`, attestation_fingerprint: `sha256:${'a'.repeat(64)}` } },
    async sign({ body }) { return { algorithm: 'ECDSA_P256_SHA256', key_id, value: crypto.sign('sha256', Buffer.from(canonicalize(body)), pair.privateKey).toString('base64') } },
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
const ENDPOINT = 'https://europe-west3-aiplatform.googleapis.com/v1/projects/p/locations/europe-west3/publishers/google/models/gemini:generateContent'
function provider() {
  return signProviderPassport({ body: { policy_version: 'legal-v4', provider_id: 'vertex-eu', status: 'approved', valid_until: '2026-12-31T00:00:00Z', training_on_customer_data: false, avv_status: 'approved', brao_43e_status: 'approved', subprocessor_status: 'approved', third_country: false, use_cases: { summarise_mail: { allowed_zones: ['MANDATE'], regions: ['europe-west3'], max_retention_minutes: 0, allowed_fields: ['subject_hash', 'body_excerpt'], allowed_sensitive_keys: [], max_payload_bytes: 4096, endpoints: { 'europe-west3': ['https://europe-west3-aiplatform.googleapis.com'] }, request_urls: { 'europe-west3': [ENDPOINT] }, network_profile: 'gcp-restricted-googleapis' } } }, private_key: reviewer.privateKey, key_id: 'review-1' })
}
function request() { return { actor_session_id: 's1', tenant_id: 'tenant-a', matter_id: 'm1', matter_version: 'matter-v9', provider_id: 'vertex-eu', zone: 'MANDATE', use_case: 'summarise_mail', purpose: 'triage correspondence', policy_version: 'legal-v4', region: 'europe-west3', endpoint: ENDPOINT, retention_minutes: 0, payload: safePayload } }
const runtimeState = { production: true, external_ai_enabled: true, outbound_actions_enabled: false, policy_version: 'legal-v4', release: 'r4', dlp_config_fingerprint: DLP_CONFIG, disabled_tenants: [], disabled_providers: [] }
const dlpScanner = { async inspect({ payload }) { const value=canonicalize(payload); return { safe: true, findings_count: 0, detected_categories: [], payload_fingerprint: `sha256:${sha256(value)}`, payload_bytes: Buffer.byteLength(value), scanner_id: 'gcp-sensitive-data-protection', scanner_version: 'google-sensitive-data-protection-v3', scanner_location: 'eu', scanner_config_fingerprint: DLP_CONFIG } } }
const networkCollector = { async collect() { return { ready: true, provider: 'gcp-vpc-service-controls', deny_by_default: true, only_restricted_google_apis: true, restricted_vip: '199.36.153.4/30', perimeter_name: 'legal', protected_resource: 'projects/123', protected_network: 'https://www.googleapis.com/compute/v1/projects/p/global/networks/legal', protected_subnetwork: 'https://www.googleapis.com/compute/v1/projects/p/regions/europe-west3/subnetworks/legal', protected_workload: 'bao-shadow', protected_workload_zone: 'europe-west3-a', protected_workload_nic: 'nic0', ipv4_only: true, effective_policy_layers_checked: true, deny_rule: 'deny-all', allow_rule: 'restricted-only' } } }

function tlsFactory({ remote='199.36.153.4', authorised=true }={}) { return () => { const socket=new EventEmitter();socket.authorized=authorised;socket.remoteAddress=remote;socket.alpnProtocol='http/1.1';socket.getPeerCertificate=()=>({raw:Buffer.from('pipeline-cert')});socket.setTimeout=()=>socket;socket.destroyed=false;socket.destroy=()=>{socket.destroyed=true};queueMicrotask(()=>socket.emit('secureConnect'));return socket } }
const validResponse=()=>JSON.stringify({candidates:[{content:{parts:[{text:JSON.stringify({type:'summary',text:'A neutral summary.',source_refs:['doc-1']})}]}}]})
function httpsFactory({responseBody=validResponse(),status=200,swapSocket=false,onRequest=null}={}) { return (_url,options,callback)=>{const req=new EventEmitter();req.setTimeout=()=>req;req.destroy=()=>{};req.end=(bytes)=>{onRequest?.(bytes);const socket=options.agent.createConnection({});const res=new EventEmitter();res.statusCode=status;res.socket=swapSocket?{remoteAddress:'199.36.153.4'}:socket;queueMicrotask(()=>{callback(res);queueMicrotask(()=>{if(responseBody)res.emit('data',Buffer.from(responseBody));res.emit('end')})})};return req} }
function transport({ signer=networkSigner, resolve4=async()=>['199.36.153.4'], tls_connect=tlsFactory(), https_request=httpsFactory() }={}) { return createRestrictedGoogleApiTransport({signer,resolve4,tls_connect,https_request}) }
function wormStore({ fail = false } = {}) { const writes=[];return {writes,async append({object_name,bytes}){writes.push(object_name);if(fail)return{stored:false,reason:'synthetic immutable-store outage'};return{stored:true,bucket:'evidence',object_name,generation:String(writes.length),content_hash:`sha256:${sha256(Buffer.isBuffer(bytes)?bytes:Buffer.from(bytes))}`,retention_expiration_time:'2026-10-02T12:00:00Z'}}} }
function base(overrides = {}) { const state={...runtimeState,disabled_tenants:[...runtimeState.disabled_tenants],disabled_providers:[...runtimeState.disabled_providers]};return { identity_assertion: identity(), matter_authorization: matterAuth(), request: request(), provider_passport: provider(), key_store: keyStore(), runtime_state: state, dlp_scanner: dlpScanner, dlp_signer: dlpSigner, network_collector: networkCollector, egress_signer: egressSigner, restricted_transport: transport(), provider_token_provider: async()=> 'synthetic-provider-token-123456789', evidence_signer: evidenceSigner, worm_store: wormStore(), release: 'r4', bundle_id: 'bao-shadow-001', now: NOW, clock:()=>NOW, ...overrides } }

test('full GCP mandate shadow pipeline sends proposal-only bytes on attested socket then commits evidence', async()=>{const args=base();const result=await runGcpMandateShadowPipeline(args);assert.equal(result.status,'CANDIDATE');assert.equal(result.decision.allowed,true);assert.equal(result.proposal.type,'summary');assert.match(result.proofs.transport_request_fingerprint,/^sha256:/);assert.equal(args.worm_store.writes.at(-1),'bundles/bao-shadow-001/COMMITTED.manifest.json')})
test('HSM CryptoKey reuse including network transport blocks pipeline before egress',async()=>{const reusedTransport=transport({signer:dlpSigner});assert.equal((await runGcpMandateShadowPipeline(base({restricted_transport:reusedTransport}))).code,'HSM_KEY_REUSE_DENIED')})
test('DLP outage finding or scanner config drift blocks before provider request and WORM commit',async()=>{for(const scanner of[{async inspect(){return{safe:false,reason:'DLP unavailable'}}},{async inspect(){return{safe:false,findings_count:1,detected_categories:['EMAIL_ADDRESS'],payload_fingerprint:'sha256:x'}}},{async inspect({payload}){return{safe:true,findings_count:0,detected_categories:[],payload_fingerprint:`sha256:${sha256(canonicalize(payload))}`,scanner_id:'gcp-sensitive-data-protection',scanner_version:'v3',scanner_config_fingerprint:`sha256:${'f'.repeat(64)}`}}}]){const store=wormStore(),result=await runGcpMandateShadowPipeline(base({dlp_scanner:scanner,worm_store:store}));assert.ok(['DLP_DENIED','DLP_CONFIG_MISMATCH'].includes(result.code));assert.equal(store.writes.length,0)}})
test('DNS poisoning blocks connection-bound transport before legal egress',async()=>{const bad=transport({resolve4:async()=>['8.8.8.8']});assert.equal((await runGcpMandateShadowPipeline(base({restricted_transport:bad}))).code,'RUNTIME_NETWORK_DENIED')})
test('socket substitution or redirect cannot become CANDIDATE',async()=>{for(const https_request of[httpsFactory({swapSocket:true}),httpsFactory({status:302,responseBody:''})]){const result=await runGcpMandateShadowPipeline(base({restricted_transport:transport({https_request})}));assert.equal(result.code,'PROVIDER_REQUEST_FAILED')}})
test('kill switch change after token acquisition is rechecked immediately before send',async()=>{let sends=0;const args=base();args.restricted_transport=transport({https_request:httpsFactory({onRequest:()=>sends++})});args.provider_token_provider=async()=>{args.runtime_state.external_ai_enabled=false;return 'synthetic-provider-token-123456789'};const result=await runGcpMandateShadowPipeline(args);assert.equal(result.code,'FRESH_LEGAL_EGRESS_DENIED');assert.equal(sends,0)})
test('stalled token acquisition cannot send after network attestation expiry',async()=>{let sends=0;const args=base();args.restricted_transport=transport({https_request:httpsFactory({onRequest:()=>sends++})});args.clock=()=>new Date(NOW.getTime()+30_001);const result=await runGcpMandateShadowPipeline(args);assert.equal(result.code,'PROVIDER_REQUEST_FAILED');assert.match(result.reason,/expired/);assert.equal(sends,0)})
test('invalid or tool-shaped model output is rejected before WORM commit',async()=>{const invalid=JSON.stringify({candidates:[{content:{parts:[{text:JSON.stringify({type:'summary',text:'x',recipient:'victim'})}]}}]});const store=wormStore(),result=await runGcpMandateShadowPipeline(base({restricted_transport:transport({https_request:httpsFactory({responseBody:invalid})}),worm_store:store}));assert.equal(result.code,'MODEL_PROPOSAL_DENIED');assert.equal(store.writes.length,0)})
test('immutable evidence outage blocks CANDIDATE after safe provider proposal',async()=>{const result=await runGcpMandateShadowPipeline(base({worm_store:wormStore({fail:true})}));assert.equal(result.code,'WORM_COMMIT_FAILED');assert.equal(result.status,'NOT_READY')})
test('provider without exact restricted profile or exact signed target URL cannot enter pipeline',async()=>{const p1=provider();p1.body.use_cases.summarise_mail.network_profile=undefined;assert.equal((await runGcpMandateShadowPipeline(base({provider_passport:p1}))).code,'GCP_RESTRICTED_PROFILE_REQUIRED');const p2=provider();p2.body.use_cases.summarise_mail.request_urls={'europe-west3':['https://europe-west3-aiplatform.googleapis.com/v1/other']};assert.equal((await runGcpMandateShadowPipeline(base({provider_passport:p2}))).code,'SIGNED_TARGET_URL_REQUIRED')})
