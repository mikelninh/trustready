import { sha256, signEnvelopeWithSigner } from './legal-key-identity.mjs'
import { createSignedDlpAttestation } from './legal-gcp-dlp.mjs'
import { createSignedEgressEnforcementAttestation } from './legal-gcp-network-enforcement.mjs'
import { authorizeLegalEgress } from './legal-runtime-fortress.mjs'
import { buildEvidenceManifest } from './legal-evidence.mjs'
import { commitEvidenceBundleToWorm } from './legal-gcp-worm.mjs'
import { cancelPreparedGoogleApiRequest, prepareRestrictedGoogleApiRequest, restrictedTransportPosture, sendPreparedGoogleApiRequest } from './legal-gcp-bound-transport.mjs'
import { buildVertexProposalRequest, parseVertexProposalResponse } from './legal-vertex-proposal.mjs'

function notReady(code, reason, extra = {}) { return { status: 'NOT_READY', code, reason, ...extra } }
function cryptoKeyIdentity(keyVersionName) { return typeof keyVersionName === 'string' && keyVersionName.includes('/cryptoKeyVersions/') ? keyVersionName.split('/cryptoKeyVersions/')[0] : null }

async function hsmPosture(signer, label) {
  if (!signer || signer.hardware_backed !== true || typeof signer.posture !== 'function') throw new Error(`${label} must be a hardware-backed signer`)
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

export async function runGcpMandateShadowPipeline({
  identity_assertion, matter_authorization, request, provider_passport, key_store, runtime_state,
  dlp_scanner, dlp_signer, network_collector, egress_signer, restricted_transport, provider_token_provider,
  evidence_signer, worm_store, release, bundle_id, now = new Date(),
}) {
  if (runtime_state?.production !== true) return notReady('PRODUCTION_STATE_REQUIRED', 'production runtime state required')
  if (!request?.tenant_id || !request?.matter_id || !request?.policy_version || !release || !bundle_id) return notReady('CONTEXT_REQUIRED', 'complete mandate pipeline context required')
  if (runtime_state.release !== release) return notReady('RELEASE_MISMATCH', 'pipeline release must equal active runtime release')
  if (!runtime_state.dlp_config_fingerprint) return notReady('DLP_CONFIG_REQUIRED', 'active runtime DLP configuration fingerprint required')
  const useCase = provider_passport?.body?.use_cases?.[request.use_case]
  if (useCase?.network_profile !== 'gcp-restricted-googleapis') return notReady('GCP_RESTRICTED_PROFILE_REQUIRED', 'provider use case must require restricted Google APIs')

  let postures
  try {
    const [dlpPosture, egressPosture, evidencePosture, networkPosture] = await Promise.all([
      hsmPosture(dlp_signer, 'DLP signer'), hsmPosture(egress_signer, 'egress signer'), hsmPosture(evidence_signer, 'evidence signer'), restrictedTransportPosture(restricted_transport),
    ])
    if (!networkPosture?.ready || networkPosture.protection_level !== 'HSM' || networkPosture.algorithm !== 'EC_SIGN_P256_SHA256' || !networkPosture.key_version_name) throw new Error('network signer HSM posture invalid')
    postures = { dlp: dlpPosture, egress: egressPosture, network: networkPosture, evidence: evidencePosture }
  } catch (error) { return notReady('HSM_SIGNER_NOT_READY', error.message) }
  const hsmKeys = Object.values(postures).map((posture) => posture.key_version_name)
  const cryptoKeys = Object.values(postures).map((posture) => cryptoKeyIdentity(posture.key_version_name))
  if (new Set(hsmKeys).size !== 4 || new Set(cryptoKeys).size !== 4) return notReady('HSM_KEY_REUSE_DENIED', 'DLP, egress, network and evidence must use four separate HSM CryptoKeys')

  const dlp = await createSignedDlpAttestation({
    scanner: dlp_scanner, signer: dlp_signer, tenant_id: request.tenant_id, matter_id: request.matter_id,
    payload: request.payload, policy_version: request.policy_version, now,
  })
  if (!dlp.safe || !dlp.attestation) return notReady('DLP_DENIED', dlp.scan?.reason || 'payload did not pass independent DLP', { scan: dlp.scan })
  if (dlp.scan?.scanner_config_fingerprint !== runtime_state.dlp_config_fingerprint) return notReady('DLP_CONFIG_MISMATCH', 'runtime scanner configuration differs from pinned deployment policy')
  if (!signatureIsHsm(dlp.attestation, postures.dlp.key_version_name)) return notReady('DLP_HSM_PROOF_INVALID', 'DLP attestation was not signed by expected HSM key')

  const enforcement = await createSignedEgressEnforcementAttestation({
    collector: network_collector, signer: egress_signer, tenant_id: request.tenant_id,
    policy_version: request.policy_version, release, now,
  })
  if (!enforcement.ready || !enforcement.attestation) return notReady('NETWORK_ENFORCEMENT_DENIED', enforcement.posture?.reason || 'network perimeter did not qualify')
  if (!signatureIsHsm(enforcement.attestation, postures.egress.key_version_name)) return notReady('EGRESS_HSM_PROOF_INVALID', 'egress posture was not signed by expected HSM key')

  let vertex
  try { vertex = buildVertexProposalRequest({ payload: request.payload, use_case: request.use_case }) } catch (error) { return notReady('MODEL_REQUEST_DENIED', error.message) }
  const prepared = await prepareRestrictedGoogleApiRequest({ transport: restricted_transport, endpoint: request.endpoint, body: vertex.bytes, region: request.region, now })
  if (!prepared.ready || !prepared.network_attestation) return notReady('RUNTIME_NETWORK_DENIED', prepared.reason || 'connection-bound restricted TLS preparation failed')
  if (prepared.request_fingerprint !== vertex.request_fingerprint) { cancelPreparedGoogleApiRequest(prepared.prepared); return notReady('TRANSPORT_FINGERPRINT_MISMATCH', 'prepared socket is not bound to exact proposal request bytes') }
  if (!signatureIsHsm(prepared.network_attestation, postures.network.key_version_name)) { cancelPreparedGoogleApiRequest(prepared.prepared); return notReady('NETWORK_HSM_PROOF_INVALID', 'network attestation was not signed by qualified network HSM key') }

  const boundRequest = { ...request, transport_request_fingerprint: prepared.request_fingerprint }
  const decision = authorizeLegalEgress({
    identity_assertion, matter_authorization, dlp_attestation: dlp.attestation, request: boundRequest, provider_passport,
    key_store, runtime_state, network_probe: () => prepared.network_attestation,
    egress_enforcement_attestation: enforcement.attestation, now,
  })
  if (!decision.allowed) { cancelPreparedGoogleApiRequest(prepared.prepared); return notReady('LEGAL_EGRESS_DENIED', decision.reason, { decision }) }

  let accessToken
  try { accessToken = await providerToken(provider_token_provider) } catch (error) { cancelPreparedGoogleApiRequest(prepared.prepared); return notReady('PROVIDER_AUTH_DENIED', error.message) }
  const providerResponse = await sendPreparedGoogleApiRequest({ transport: restricted_transport, prepared: prepared.prepared, headers: { authorization: `Bearer ${accessToken}` } })
  if (!providerResponse.ok) return notReady('PROVIDER_REQUEST_FAILED', providerResponse.reason || `provider status ${providerResponse.status || 0}`)
  if (providerResponse.request_fingerprint !== prepared.request_fingerprint || providerResponse.peer_fingerprint !== prepared.prepared.peer_fingerprint) return notReady('TRANSPORT_BINDING_FAILED', 'provider response did not use the attested request/socket')
  const proposal = parseVertexProposalResponse(providerResponse.body)
  if (!proposal.valid) return notReady('MODEL_PROPOSAL_DENIED', proposal.reason)

  const artifacts = {
    'decision.json': decision,
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
      tenant_id: request.tenant_id, matter_id_hash: `sha256:${sha256(request.matter_id)}`,
      provider_id: request.provider_id, use_case: request.use_case, policy_version: request.policy_version,
      release, decision_id: decision.decision_id, recorded_at: now.toISOString(),
    },
  }
  const manifest = buildEvidenceManifest({ tenant: request.tenant_id, release, policy_version: request.policy_version, artifacts, generated_at: now.toISOString() })
  let signedManifest
  try { signedManifest = await signEnvelopeWithSigner({ body: manifest, signer: evidence_signer, purpose: 'evidence_manifest' }) } catch (error) { return notReady('EVIDENCE_SIGNING_FAILED', error.message) }
  if (!signatureIsHsm(signedManifest, postures.evidence.key_version_name)) return notReady('EVIDENCE_HSM_PROOF_INVALID', 'evidence manifest was not signed by expected HSM key')

  const committed = await commitEvidenceBundleToWorm({ store: worm_store, signed_manifest: signedManifest, key_store, artifacts, bundle_id, now })
  if (!committed.committed) return notReady('WORM_COMMIT_FAILED', committed.reason || committed.code, { committed })

  return {
    status: 'CANDIDATE', code: 'CANDIDATE_FOR_REAL_MANDATE_SHADOW_PILOT',
    decision, proposal: proposal.proposal,
    evidence: { bundle_id, manifest_hash: committed.manifest_hash, commit_receipt: committed.commit_receipt },
    proofs: {
      dlp_hsm_key: postures.dlp.key_version_name, egress_hsm_key: postures.egress.key_version_name,
      network_hsm_key: postures.network.key_version_name, evidence_hsm_key: postures.evidence.key_version_name,
      network_profile: useCase.network_profile, transport_request_fingerprint: prepared.request_fingerprint,
    },
  }
}
