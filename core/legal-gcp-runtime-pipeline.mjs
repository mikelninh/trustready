import { canonicalize, sha256, signEnvelopeWithSigner } from './legal-key-identity.mjs'
import { createSignedDlpAttestation } from './legal-gcp-dlp.mjs'
import { createSignedEgressEnforcementAttestation } from './legal-gcp-network-enforcement.mjs'
import { authorizeLegalEgress } from './legal-runtime-fortress.mjs'
import { buildEvidenceManifest } from './legal-evidence.mjs'
import { commitEvidenceBundleToWorm } from './legal-gcp-worm.mjs'

function notReady(code, reason, extra = {}) { return { status: 'NOT_READY', code, reason, ...extra } }

async function hsmPosture(signer, label) {
  if (!signer || signer.hardware_backed !== true || typeof signer.posture !== 'function') throw new Error(`${label} must be a hardware-backed signer`)
  const posture = await signer.posture()
  if (!posture?.ready || posture.protection_level !== 'HSM' || posture.algorithm !== 'EC_SIGN_P256_SHA256' || !posture.key_version_name) throw new Error(`${label} HSM posture invalid`)
  return posture
}

function signatureIsHsm(envelope, expectedKey) {
  return envelope?.signature?.algorithm === 'ECDSA_P256_SHA256' && envelope?.signature?.key_id === expectedKey
}

export async function runGcpMandateShadowPipeline({
  identity_assertion, matter_authorization, request, provider_passport, key_store, runtime_state,
  dlp_scanner, dlp_signer, network_collector, egress_signer, runtime_network_probe,
  evidence_signer, worm_store, release, bundle_id, now = new Date(),
}) {
  if (runtime_state?.production !== true) return notReady('PRODUCTION_STATE_REQUIRED', 'production runtime state required')
  if (!request?.tenant_id || !request?.matter_id || !request?.policy_version || !release || !bundle_id) return notReady('CONTEXT_REQUIRED', 'complete mandate pipeline context required')
  const useCase = provider_passport?.body?.use_cases?.[request.use_case]
  if (useCase?.network_profile !== 'gcp-restricted-googleapis') return notReady('GCP_RESTRICTED_PROFILE_REQUIRED', 'provider use case must require restricted Google APIs')
  if (typeof runtime_network_probe !== 'function') return notReady('RUNTIME_NETWORK_PROBE_REQUIRED', 'per-request DNS/TLS proof required')

  let postures
  try {
    postures = await Promise.all([
      hsmPosture(dlp_signer, 'DLP signer'), hsmPosture(egress_signer, 'egress signer'), hsmPosture(evidence_signer, 'evidence signer'),
    ])
  } catch (error) { return notReady('HSM_SIGNER_NOT_READY', error.message) }
  const hsmKeys = postures.map((posture) => posture.key_version_name)
  if (new Set(hsmKeys).size !== hsmKeys.length) return notReady('HSM_KEY_REUSE_DENIED', 'DLP, egress and evidence must use separate HSM key versions')

  const dlp = await createSignedDlpAttestation({
    scanner: dlp_scanner, signer: dlp_signer, tenant_id: request.tenant_id, matter_id: request.matter_id,
    payload: request.payload, policy_version: request.policy_version, now,
  })
  if (!dlp.safe || !dlp.attestation) return notReady('DLP_DENIED', dlp.scan?.reason || 'payload did not pass independent DLP', { scan: dlp.scan })
  if (!signatureIsHsm(dlp.attestation, postures[0].key_version_name)) return notReady('DLP_HSM_PROOF_INVALID', 'DLP attestation was not signed by expected HSM key')

  const enforcement = await createSignedEgressEnforcementAttestation({
    collector: network_collector, signer: egress_signer, tenant_id: request.tenant_id,
    policy_version: request.policy_version, release, now,
  })
  if (!enforcement.ready || !enforcement.attestation) return notReady('NETWORK_ENFORCEMENT_DENIED', enforcement.posture?.reason || 'network perimeter did not qualify')
  if (!signatureIsHsm(enforcement.attestation, postures[1].key_version_name)) return notReady('EGRESS_HSM_PROOF_INVALID', 'egress posture was not signed by expected HSM key')

  const endpoint = new URL(request.endpoint)
  const networkAttestation = await runtime_network_probe({ endpoint: endpoint.origin, hostname: endpoint.hostname, region: request.region, now })
  if (!networkAttestation?.signature || networkAttestation.signature.algorithm !== 'ECDSA_P256_SHA256') return notReady('RUNTIME_NETWORK_DENIED', 'runtime DNS/TLS attestation missing or not HSM signed')
  const allSecurityKeys = [...hsmKeys, networkAttestation.signature.key_id]
  if (new Set(allSecurityKeys).size !== allSecurityKeys.length) return notReady('HSM_KEY_REUSE_DENIED', 'runtime network attestation must use a separate HSM key')

  const decision = authorizeLegalEgress({
    identity_assertion, matter_authorization, dlp_attestation: dlp.attestation, request, provider_passport,
    key_store, runtime_state, network_probe: () => networkAttestation,
    egress_enforcement_attestation: enforcement.attestation, now,
  })
  if (!decision.allowed) return notReady('LEGAL_EGRESS_DENIED', decision.reason, { decision })

  const artifacts = {
    'decision.json': decision,
    'dlp-attestation.json': dlp.attestation,
    'egress-enforcement.json': enforcement.attestation,
    'network-attestation.json': networkAttestation,
    'runtime-summary.json': {
      tenant_id: request.tenant_id, matter_id_hash: `sha256:${sha256(request.matter_id)}`,
      provider_id: request.provider_id, use_case: request.use_case, policy_version: request.policy_version,
      release, decision_id: decision.decision_id, recorded_at: now.toISOString(),
    },
  }
  const manifest = buildEvidenceManifest({
    tenant: request.tenant_id, release, policy_version: request.policy_version, artifacts, generated_at: now.toISOString(),
  })
  let signedManifest
  try { signedManifest = await signEnvelopeWithSigner({ body: manifest, signer: evidence_signer, purpose: 'evidence_manifest' }) } catch (error) {
    return notReady('EVIDENCE_SIGNING_FAILED', error.message)
  }
  if (!signatureIsHsm(signedManifest, postures[2].key_version_name)) return notReady('EVIDENCE_HSM_PROOF_INVALID', 'evidence manifest was not signed by expected HSM key')

  const committed = await commitEvidenceBundleToWorm({ store: worm_store, signed_manifest: signedManifest, key_store, artifacts, bundle_id, now })
  if (!committed.committed) return notReady('WORM_COMMIT_FAILED', committed.reason || committed.code, { committed })

  return {
    status: 'CANDIDATE', code: 'CANDIDATE_FOR_REAL_MANDATE_SHADOW_PILOT',
    decision, evidence: { bundle_id, manifest_hash: committed.manifest_hash, commit_receipt: committed.commit_receipt },
    proofs: {
      dlp_hsm_key: postures[0].key_version_name, egress_hsm_key: postures[1].key_version_name,
      network_hsm_key: networkAttestation.signature.key_id, evidence_hsm_key: postures[2].key_version_name,
      network_profile: useCase.network_profile,
    },
  }
}
