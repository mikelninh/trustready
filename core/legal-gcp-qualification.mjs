import { canonicalize, sha256, signEnvelopeWithSigner } from './legal-key-identity.mjs'

export const SAFE_CANARY = Object.freeze({ subject_hash: `sha256:${'a'.repeat(64)}`, body_excerpt: 'Pseudonymised neutral legal correspondence.' })
export const PII_CANARY = Object.freeze({ body_excerpt: 'Erika Müller, erika.mueller@example.com, IBAN DE89370400440532013000' })

function fail(code, detail, evidence = {}) {
  return { status: 'NOT_READY', code, detail, evidence }
}

export async function qualifyGcpLegalInfrastructure({ hsm_signer, dlp_scanner, network_collector, worm_store, tenant_id, policy_version, release, now = new Date() }) {
  if (!hsm_signer || !dlp_scanner || !network_collector || !worm_store || !tenant_id || !policy_version || !release) {
    throw new TypeError('complete production infrastructure context required')
  }

  let hsm
  try { hsm = await hsm_signer.posture() } catch (error) { return fail('HSM_NOT_READY', error.message) }
  if (!hsm?.ready || hsm.protection_level !== 'HSM' || !hsm.attestation_fingerprint) return fail('HSM_NOT_READY', hsm?.reason || 'HSM proof incomplete')

  const safeScan = await dlp_scanner.inspect({ payload: SAFE_CANARY })
  if (!safeScan?.safe) return fail('DLP_FALSE_POSITIVE_OR_OUTAGE', safeScan?.reason || 'safe canary was not accepted')
  const piiScan = await dlp_scanner.inspect({ payload: PII_CANARY })
  if (piiScan?.safe !== false || !Array.isArray(piiScan.detected_categories) || piiScan.detected_categories.length === 0) {
    return fail('DLP_FALSE_NEGATIVE', 'PII canary was not detected')
  }

  let network
  try { network = await network_collector.collect() } catch (error) { return fail('NETWORK_NOT_READY', error.message) }
  if (!network?.ready || network.deny_by_default !== true || network.only_restricted_google_apis !== true) {
    return fail('NETWORK_NOT_READY', network?.reason || 'network proof incomplete')
  }

  let worm
  try { worm = await worm_store.posture() } catch (error) { return fail('WORM_NOT_READY', error.message) }
  if (!worm?.ready || worm.retention_locked !== true) return fail('WORM_NOT_READY', worm?.reason || 'immutable evidence store proof incomplete')

  const qualificationBody = {
    schema: 'trustready-gcp-legal-infrastructure-qualification-v1',
    tenant_id,
    policy_version,
    release,
    qualified_at: now.toISOString(),
    hsm: {
      provider: hsm.provider,
      key_version_name: hsm.key_version_name,
      location: hsm.location,
      algorithm: hsm.algorithm,
      public_key_fingerprint: hsm.public_key_fingerprint,
      attestation_fingerprint: hsm.attestation_fingerprint,
    },
    dlp: {
      scanner_id: safeScan.scanner_id,
      scanner_location: safeScan.scanner_location,
      safe_canary_fingerprint: safeScan.payload_fingerprint,
      pii_canary_fingerprint: piiScan.payload_fingerprint,
      pii_categories: piiScan.detected_categories,
    },
    network: {
      provider: network.provider,
      restricted_vip: network.restricted_vip,
      perimeter_name: network.perimeter_name,
      deny_rule: network.deny_rule,
      allow_rule: network.allow_rule,
    },
    worm: {
      provider: worm.provider,
      bucket: worm.bucket,
      retention_seconds: worm.retention_seconds,
    },
  }

  let signedQualification
  try { signedQualification = await signEnvelopeWithSigner({ body: qualificationBody, signer: hsm_signer, purpose: 'infrastructure_qualification' }) } catch (error) {
    return fail('HSM_SIGNING_FAILED', error.message, { qualification_hash: `sha256:${sha256(qualificationBody)}` })
  }

  const bytes = Buffer.from(canonicalize(signedQualification), 'utf8')
  const objectName = `qualifications/${tenant_id}/${release}/${now.toISOString().replace(/[:.]/g, '-')}.json`
  const stored = await worm_store.append({ object_name: objectName, bytes, content_type: 'application/json' })
  if (!stored?.stored || !stored.retention_expiration_time) return fail('WORM_WRITE_FAILED', stored?.reason || 'immutable qualification write failed')
  if (stored.content_hash !== `sha256:${sha256(bytes)}`) return fail('WORM_RECEIPT_MISMATCH', 'immutable store receipt hash mismatch')

  return {
    status: 'CANDIDATE',
    code: 'CANDIDATE_FOR_REAL_MANDATE_SHADOW_PILOT',
    qualification_hash: `sha256:${sha256(qualificationBody)}`,
    signed_qualification: signedQualification,
    immutable_receipt: stored,
    controls: { hsm: true, dlp: true, network: true, worm: true },
  }
}
