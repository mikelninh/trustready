import { isRootedKeyTrustStore, sha256, signEnvelopeWithSigner } from './legal-key-identity.mjs'
import { createSignedDlpAttestation, isProductionGoogleSensitiveDataScanner, PRODUCTION_DLP_LOCATION } from './legal-gcp-dlp.mjs'
import { createSignedEgressEnforcementAttestation, isProductionGcpNetworkPostureCollector } from './legal-gcp-network-enforcement.mjs'
import { createGceRuntimeIdentityProvider } from './legal-gcp-runtime-identity.mjs'
import { authorizeLegalEgress, verifyProviderPassport } from './legal-runtime-fortress.mjs'
import { buildEvidenceManifest } from './legal-evidence.mjs'
import { commitEvidenceBundleToWorm, isProductionGcsWormEvidenceStore } from './legal-gcp-worm.mjs'
import { cancelPreparedGoogleApiRequest, isProductionRestrictedGoogleApiTransport, prepareRestrictedGoogleApiRequest, restrictedTransportPosture, sendPreparedGoogleApiRequest } from './legal-gcp-bound-transport.mjs'
import { isProductionGoogleCloudHsmSigner } from './legal-gcp-hsm.mjs'
import { buildVertexProposalRequest, parseVertexProposalResponse } from './legal-vertex-proposal.mjs'

const NativeDate = Date
const PRODUCTION_CLOCK = () => new NativeDate()
function notReady(code, reason, extra = {}) { return { status: 'NOT_READY', code, reason, ...extra } }
function cryptoKeyIdentity(keyVersionName) { return typeof keyVersionName === 'string' && keyVersionName.includes('/cryptoKeyVersions/') ? keyVersionName.split('/cryptoKeyVersions/')[0] : null }
function projectNumberFromResource(value) { const match = /^projects\/(\d+)$/.exec(value || ''); return match?.[1] || null }
function projectIdFromKmsName(value) { const match = /^projects\/([^/]+)\/locations\//.exec(value || ''); return match?.[1] || null }

function normalizeStrictJson(value, state = { seen: new WeakSet(), nodes: 0 }, depth = 0, path = '$') {
  if (depth > 32) throw new TypeError(`${path}: JSON nesting too deep`)
  state.nodes += 1
  if (state.nodes > 10000) throw new TypeError(`${path}: JSON node limit exceeded`)
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value
  if (typeof value === 'number') { if (!Number.isFinite(value)) throw new TypeError(`${path}: non-finite number denied`); return value }
  if (typeof value !== 'object') throw new TypeError(`${path}: non-JSON value denied`)
  if (state.seen.has(value)) throw new TypeError(`${path}: cyclic value denied`)
  state.seen.add(value)
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) throw new TypeError(`${path}: custom array prototype denied`)
      if (Object.getOwnPropertySymbols(value).length) throw new TypeError(`${path}: symbol properties denied`)
      const descriptors = Object.getOwnPropertyDescriptors(value), out = []
      const length = descriptors.length?.value
      if (!Number.isSafeInteger(length) || length < 0) throw new TypeError(`${path}: invalid array length denied`)
      for (const name of Object.keys(descriptors)) {
        if (name === 'length') continue
        if (!/^(0|[1-9]\d*)$/.test(name)) throw new TypeError(`${path}: non-index array property denied`)
        const index = Number(name)
        if (!Number.isSafeInteger(index) || index < 0 || index >= length) throw new TypeError(`${path}: invalid array index denied`)
      }
      for (let index = 0; index < length; index += 1) {
        const descriptor = descriptors[String(index)]
        if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) throw new TypeError(`${path}[${index}]: sparse/accessor array entry denied`)
        out[index] = normalizeStrictJson(descriptor.value, state, depth + 1, `${path}[${index}]`)
      }
      return Object.freeze(out)
    }
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError(`${path}: custom object prototype denied`)
    if (Object.getOwnPropertySymbols(value).length) throw new TypeError(`${path}: symbol properties denied`)
    const descriptors = Object.getOwnPropertyDescriptors(value), out = Object.create(null)
    for (const key of Object.keys(descriptors).sort()) {
      const descriptor = descriptors[key]
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) throw new TypeError(`${path}.${key}: accessor/non-enumerable property denied`)
      Object.defineProperty(out, key, { value: normalizeStrictJson(descriptor.value, state, depth + 1, `${path}.${key}`), enumerable: true, writable: false, configurable: false })
    }
    return Object.freeze(out)
  } finally { state.seen.delete(value) }
}

async function hsmPosture(signer, label) {
  if (!isProductionGoogleCloudHsmSigner(signer)) throw new Error(`${label} must be a production Google Cloud HSM signer`)
  const posture = await signer.posture()
  if (!posture?.ready || posture.protection_level !== 'HSM' || posture.algorithm !== 'EC_SIGN_P256_SHA256' || !posture.key_version_name || !cryptoKeyIdentity(posture.key_version_name)) throw new Error(`${label} HSM posture invalid`)
  return posture
}
function signatureIsHsm(envelope, expectedKey) { return envelope?.signature?.algorithm === 'ECDSA_P256_SHA256' && envelope?.signature?.key_id === expectedKey }
async function providerToken(provider) {
  if (typeof provider !== 'function') throw new Error('provider token source required')
  const value = await provider()
  if (typeof value !== 'string' || value.length < 16 || /[\r\n]/.test(value)) throw new Error('provider token unavailable')
  return value
}

function productionAdaptersReady({ key_store, dlp_scanner, dlp_signer, network_collector, egress_signer, restricted_transport, evidence_signer, worm_store }) {
  if (!isRootedKeyTrustStore(key_store)) return { ready: false, code: 'ROOT_TRUST_REQUIRED', reason: 'production mandate pipeline requires internally verified rooted key trust' }
  if (!isProductionGoogleSensitiveDataScanner(dlp_scanner)) return { ready: false, code: 'PRODUCTION_DLP_ADAPTER_REQUIRED', reason: 'production mandate pipeline requires production Google Sensitive Data Protection scanner' }
  if (!isProductionGcpNetworkPostureCollector(network_collector)) return { ready: false, code: 'PRODUCTION_NETWORK_COLLECTOR_REQUIRED', reason: 'production mandate pipeline requires production GCP network posture collector' }
  if (dlp_scanner.location !== PRODUCTION_DLP_LOCATION) return { ready: false, code: 'DLP_LOCATION_MISMATCH', reason: 'production DLP must use the approved EU location' }
  if (!isProductionRestrictedGoogleApiTransport(restricted_transport)) return { ready: false, code: 'PRODUCTION_TRANSPORT_REQUIRED', reason: 'production mandate pipeline rejects test or untrusted restricted transports' }
  if (!isProductionGcsWormEvidenceStore(worm_store)) return { ready: false, code: 'PRODUCTION_WORM_STORE_REQUIRED', reason: 'production mandate pipeline requires production GCS Bucket Lock evidence store' }
  for (const [label, signer] of [['DLP', dlp_signer], ['egress', egress_signer], ['evidence', evidence_signer]]) {
    if (!isProductionGoogleCloudHsmSigner(signer)) return { ready: false, code: 'PRODUCTION_HSM_SIGNER_REQUIRED', reason: `${label} signer must be a production Google Cloud HSM signer` }
  }
  return { ready: true }
}

function sameRuntime(network, runtime) {
  return network?.project_id === runtime?.project_id &&
    network?.protected_workload === runtime?.instance_name &&
    String(network?.protected_workload_instance_id || '') === String(runtime?.instance_id || '') &&
    network?.protected_workload_zone === runtime?.zone &&
    network?.protected_service_account === runtime?.service_account_email
}

export async function runGcpMandateShadowPipeline(input = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return notReady('PIPELINE_INPUT_REQUIRED', 'production pipeline input object required')
  if (Object.hasOwn(input, 'now') || Object.hasOwn(input, 'clock')) return notReady('CALLER_TIME_DENIED', 'production pipeline time is internally controlled and cannot be injected')
  const {
    identity_assertion, matter_authorization, request, provider_passport, key_store, runtime_state,
    dlp_scanner, dlp_signer, network_collector, egress_signer, restricted_transport, provider_token_provider,
    evidence_signer, worm_store, release, bundle_id,
  } = input
  const pipelineNow = PRODUCTION_CLOCK()
  if (runtime_state?.production !== true) return notReady('PRODUCTION_STATE_REQUIRED', 'production runtime state required')
  const adapters = productionAdaptersReady({ key_store, dlp_scanner, dlp_signer, network_collector, egress_signer, restricted_transport, evidence_signer, worm_store })
  if (!adapters.ready) return notReady(adapters.code, adapters.reason)

  let pipelineRequest
  try { pipelineRequest = normalizeStrictJson(request) } catch (error) { return notReady('PAYLOAD_SERIALIZATION_DENIED', error.message) }
  if (!pipelineRequest?.tenant_id || !pipelineRequest?.matter_id || !pipelineRequest?.policy_version || !release || !bundle_id) return notReady('CONTEXT_REQUIRED', 'complete mandate pipeline context required')
  if (runtime_state.release !== release) return notReady('RELEASE_MISMATCH', 'pipeline release must equal active runtime release')
  if (!runtime_state.dlp_config_fingerprint) return notReady('DLP_CONFIG_REQUIRED', 'active runtime DLP configuration fingerprint required')

  const providerVerified = verifyProviderPassport({ passport: provider_passport, key_store, policy_version: pipelineRequest.policy_version, now: pipelineNow })
  if (!providerVerified.valid) return notReady('PROVIDER_PASSPORT_DENIED', providerVerified.reason)
  const providerSnapshot = providerVerified.body
  if (providerSnapshot.provider_id !== pipelineRequest.provider_id) return notReady('PROVIDER_MISMATCH', 'provider passport does not match request provider')
  const useCase = providerSnapshot.use_cases?.[pipelineRequest.use_case]
  if (useCase?.network_profile !== 'gcp-restricted-googleapis') return notReady('GCP_RESTRICTED_PROFILE_REQUIRED', 'provider use case must require restricted Google APIs')
  const exactUrls = useCase?.request_urls?.[pipelineRequest.region]
  if (!Array.isArray(exactUrls) || !exactUrls.includes(pipelineRequest.endpoint)) return notReady('SIGNED_TARGET_URL_REQUIRED', 'exact provider request URL must be approved in signed use-case policy')

  let runtimeIdentity
  try { runtimeIdentity = await createGceRuntimeIdentityProvider().collect() } catch (error) { return notReady('RUNTIME_IDENTITY_DENIED', error.message) }
  if (!runtimeIdentity?.ready) return notReady('RUNTIME_IDENTITY_DENIED', runtimeIdentity?.reason || 'authenticated local GCE runtime identity unavailable')
  if (dlp_scanner.project_id !== runtimeIdentity.project_id) return notReady('DLP_PROJECT_MISMATCH', 'DLP project differs from authenticated executing gateway project')
  if (worm_store.bucket !== runtimeIdentity.evidence_bucket) return notReady('WORM_BUCKET_MISMATCH', 'WORM bucket differs from evidence bucket pinned to the executing gateway')

  let postures
  try {
    const [dlpPosture, egressPosture, evidencePosture, networkPosture] = await Promise.all([
      hsmPosture(dlp_signer, 'DLP signer'), hsmPosture(egress_signer, 'egress signer'), hsmPosture(evidence_signer, 'evidence signer'), restrictedTransportPosture(restricted_transport),
    ])
    if (!networkPosture?.ready || networkPosture.protection_level !== 'HSM' || networkPosture.algorithm !== 'EC_SIGN_P256_SHA256' || !networkPosture.key_version_name) throw new Error('network signer HSM posture invalid')
    postures = { dlp: dlpPosture, egress: egressPosture, network: networkPosture, evidence: evidencePosture }
  } catch (error) { return notReady('HSM_SIGNER_NOT_READY', error.message) }
  const hsmKeys = Object.values(postures).map((p) => p.key_version_name)
  const cryptoKeys = Object.values(postures).map((p) => cryptoKeyIdentity(p.key_version_name))
  if (new Set(hsmKeys).size !== 4 || new Set(cryptoKeys).size !== 4) return notReady('HSM_KEY_REUSE_DENIED', 'DLP, egress, network and evidence must use four separate HSM CryptoKeys')
  for (const [purpose, posture] of Object.entries(postures)) {
    if (projectIdFromKmsName(posture.key_version_name) !== runtimeIdentity.project_id) return notReady('HSM_PROJECT_MISMATCH', `${purpose} HSM key belongs to a different GCP project`)
  }

  const enforcement = await createSignedEgressEnforcementAttestation({ collector: network_collector, signer: egress_signer, tenant_id: pipelineRequest.tenant_id, policy_version: pipelineRequest.policy_version, release, now: pipelineNow })
  if (!enforcement.ready || !enforcement.attestation) return notReady('NETWORK_ENFORCEMENT_DENIED', enforcement.posture?.reason || 'network perimeter did not qualify')
  if (!sameRuntime(enforcement.posture, runtimeIdentity)) return notReady('RUNTIME_NETWORK_IDENTITY_MISMATCH', 'network qualification does not describe the authenticated executing gateway')
  if (enforcement.posture?.project_id !== dlp_scanner.project_id) return notReady('NETWORK_PROJECT_PROOF_MISMATCH', 'qualified runtime project differs from DLP project')
  if (!signatureIsHsm(enforcement.attestation, postures.egress.key_version_name)) return notReady('EGRESS_HSM_PROOF_INVALID', 'egress posture was not signed by expected HSM key')

  const protectedProjectNumber = projectNumberFromResource(enforcement.posture?.protected_resource)
  if (!protectedProjectNumber) return notReady('PROJECT_IDENTITY_PROOF_MISSING', 'qualified project number missing from VPC Service Controls evidence')
  let wormPosture
  try { wormPosture = await worm_store.posture() } catch (error) { return notReady('WORM_NOT_READY', error.message) }
  if (!wormPosture?.ready || wormPosture.retention_locked !== true) return notReady('WORM_NOT_READY', wormPosture?.reason || 'immutable evidence store proof incomplete')
  if (wormPosture.bucket !== runtimeIdentity.evidence_bucket) return notReady('WORM_BUCKET_MISMATCH', 'qualified WORM bucket differs from gateway-pinned evidence bucket')
  if (wormPosture.project_number !== protectedProjectNumber) return notReady('WORM_PROJECT_MISMATCH', 'qualified WORM bucket belongs to a different GCP project')

  const dlp = await createSignedDlpAttestation({ scanner: dlp_scanner, signer: dlp_signer, tenant_id: pipelineRequest.tenant_id, matter_id: pipelineRequest.matter_id, payload: pipelineRequest.payload, policy_version: pipelineRequest.policy_version, now: pipelineNow })
  if (!dlp.safe || !dlp.attestation) return notReady('DLP_DENIED', dlp.scan?.reason || 'payload did not pass independent DLP', { scan: dlp.scan })
  if (dlp.scan?.scanner_project_id !== runtimeIdentity.project_id || dlp.scan?.scanner_location !== PRODUCTION_DLP_LOCATION) return notReady('DLP_DEPLOYMENT_PROOF_MISMATCH', 'DLP attestation deployment differs from authenticated EU gateway deployment')
  if (dlp.scan?.scanner_config_fingerprint !== runtime_state.dlp_config_fingerprint) return notReady('DLP_CONFIG_MISMATCH', 'runtime scanner configuration differs from pinned deployment policy')
  if (!signatureIsHsm(dlp.attestation, postures.dlp.key_version_name)) return notReady('DLP_HSM_PROOF_INVALID', 'DLP attestation was not signed by expected HSM key')

  let vertex
  try { vertex = buildVertexProposalRequest({ payload: pipelineRequest.payload, use_case: pipelineRequest.use_case }) } catch (error) { return notReady('MODEL_REQUEST_DENIED', error.message) }
  const prepared = await prepareRestrictedGoogleApiRequest({ transport: restricted_transport, endpoint: pipelineRequest.endpoint, body: vertex.bytes, region: pipelineRequest.region, now: pipelineNow })
  if (!prepared.ready || !prepared.network_attestation) return notReady('RUNTIME_NETWORK_DENIED', prepared.reason || 'connection-bound restricted TLS preparation failed')
  if (prepared.body_fingerprint !== vertex.request_fingerprint) { cancelPreparedGoogleApiRequest(prepared.prepared); return notReady('TRANSPORT_BODY_FINGERPRINT_MISMATCH', 'prepared socket is not bound to exact proposal request body') }
  if (prepared.network_attestation.body?.target_url !== pipelineRequest.endpoint || prepared.network_attestation.body?.request_fingerprint !== prepared.request_fingerprint) { cancelPreparedGoogleApiRequest(prepared.prepared); return notReady('TRANSPORT_TARGET_BINDING_FAILED', 'network attestation is not bound to exact approved target URL') }
  if (!signatureIsHsm(prepared.network_attestation, postures.network.key_version_name)) { cancelPreparedGoogleApiRequest(prepared.prepared); return notReady('NETWORK_HSM_PROOF_INVALID', 'network attestation was not signed by qualified network HSM key') }

  const boundRequest = Object.freeze({ ...pipelineRequest, transport_request_fingerprint: prepared.request_fingerprint })
  const initialDecision = authorizeLegalEgress({ identity_assertion, matter_authorization, dlp_attestation: dlp.attestation, request: boundRequest, provider_passport, key_store, runtime_state, network_probe: () => prepared.network_attestation, egress_enforcement_attestation: enforcement.attestation, now: pipelineNow })
  if (!initialDecision.allowed) { cancelPreparedGoogleApiRequest(prepared.prepared); return notReady('LEGAL_EGRESS_DENIED', initialDecision.reason, { decision: initialDecision }) }

  let accessToken
  try { accessToken = await providerToken(provider_token_provider) } catch (error) { cancelPreparedGoogleApiRequest(prepared.prepared); return notReady('PROVIDER_AUTH_DENIED', error.message) }
  let finalDecision = initialDecision
  const providerResponse = await sendPreparedGoogleApiRequest({
    transport: restricted_transport,
    prepared: prepared.prepared,
    headers: { authorization: `Bearer ${accessToken}` },
    clock: PRODUCTION_CLOCK,
    before_send: (sendNow) => {
      finalDecision = authorizeLegalEgress({ identity_assertion, matter_authorization, dlp_attestation: dlp.attestation, request: boundRequest, provider_passport, key_store, runtime_state, network_probe: () => prepared.network_attestation, egress_enforcement_attestation: enforcement.attestation, now: sendNow })
      return finalDecision.allowed ? true : { allowed: false, reason: `fresh legal egress denied: ${finalDecision.reason}` }
    },
  })
  if (!finalDecision.allowed) return notReady('FRESH_LEGAL_EGRESS_DENIED', finalDecision.reason || 'fresh pre-send authorization denied', { decision: finalDecision })
  if (!providerResponse.ok) return notReady('PROVIDER_REQUEST_FAILED', providerResponse.reason || `provider status ${providerResponse.status || 0}`, { decision: finalDecision })
  if (providerResponse.request_fingerprint !== prepared.request_fingerprint || providerResponse.body_fingerprint !== vertex.request_fingerprint) return notReady('TRANSPORT_BINDING_FAILED', 'provider request did not preserve the attested target/body binding')
  const proposal = parseVertexProposalResponse(providerResponse.body)
  if (!proposal.valid) return notReady('MODEL_PROPOSAL_DENIED', proposal.reason)

  const evidenceNow = PRODUCTION_CLOCK()
  const artifacts = {
    'decision.json': finalDecision,
    'dlp-attestation.json': dlp.attestation,
    'egress-enforcement.json': enforcement.attestation,
    'network-attestation.json': prepared.network_attestation,
    'proposal-proof.json': {
      proposal_type: proposal.proposal.type,
      proposal_hash: proposal.proposal_hash,
      provider_response_fingerprint: providerResponse.response_fingerprint,
      transport_request_fingerprint: prepared.request_fingerprint,
      source_ref_count: Array.isArray(proposal.proposal.source_refs) ? proposal.proposal.source_refs.length : 0,
    },
    'runtime-summary.json': {
      tenant_id: pipelineRequest.tenant_id,
      matter_id_hash: `sha256:${sha256(pipelineRequest.matter_id)}`,
      provider_id: pipelineRequest.provider_id,
      use_case: pipelineRequest.use_case,
      policy_version: pipelineRequest.policy_version,
      release,
      decision_id: finalDecision.decision_id,
      gateway_project_id: runtimeIdentity.project_id,
      evidence_bucket: runtimeIdentity.evidence_bucket,
      evidence_project_number: protectedProjectNumber,
      recorded_at: evidenceNow.toISOString(),
    },
  }
  const manifest = buildEvidenceManifest({ tenant: pipelineRequest.tenant_id, release, policy_version: pipelineRequest.policy_version, artifacts, generated_at: evidenceNow.toISOString() })
  let signedManifest
  try { signedManifest = await signEnvelopeWithSigner({ body: manifest, signer: evidence_signer, purpose: 'evidence_manifest' }) } catch (error) { return notReady('EVIDENCE_SIGNING_FAILED', error.message) }
  if (!signatureIsHsm(signedManifest, postures.evidence.key_version_name)) return notReady('EVIDENCE_HSM_PROOF_INVALID', 'evidence manifest was not signed by expected HSM key')
  const committed = await commitEvidenceBundleToWorm({ store: worm_store, signed_manifest: signedManifest, key_store, artifacts, bundle_id, now: evidenceNow })
  if (!committed.committed) return notReady('WORM_COMMIT_FAILED', committed.reason || committed.code, { committed })

  return {
    status: 'CANDIDATE',
    code: 'CANDIDATE_FOR_REAL_MANDATE_SHADOW_PILOT',
    decision: finalDecision,
    proposal: proposal.proposal,
    evidence: { bundle_id, manifest_hash: committed.manifest_hash, commit_receipt: committed.commit_receipt },
    proofs: {
      dlp_hsm_key: postures.dlp.key_version_name,
      egress_hsm_key: postures.egress.key_version_name,
      network_hsm_key: postures.network.key_version_name,
      evidence_hsm_key: postures.evidence.key_version_name,
      gateway_project_id: runtimeIdentity.project_id,
      evidence_bucket: runtimeIdentity.evidence_bucket,
      network_profile: useCase.network_profile,
      transport_request_fingerprint: prepared.request_fingerprint,
    },
  }
}