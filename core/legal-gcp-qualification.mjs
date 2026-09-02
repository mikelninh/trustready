import { canonicalize, sha256, signEnvelopeWithSigner } from './legal-key-identity.mjs'
import { isProductionGoogleCloudHsmSigner } from './legal-gcp-hsm.mjs'
import { isProductionGoogleSensitiveDataScanner } from './legal-gcp-dlp.mjs'
import { isProductionGcpNetworkPostureCollector } from './legal-gcp-network-enforcement.mjs'
import { isProductionGcsWormEvidenceStore } from './legal-gcp-worm.mjs'

export const SAFE_CANARY = Object.freeze({ subject_hash: `sha256:${'a'.repeat(64)}`, body_excerpt: 'Pseudonymised neutral legal correspondence.' })
export const PII_CANARY = Object.freeze({ body_excerpt: 'Erika Müller, erika.mueller@example.com, IBAN DE89370400440532013000' })
const REQUIRED_HSM_PURPOSES = Object.freeze(['dlp', 'egress', 'network', 'evidence'])

function fail(code, detail, evidence = {}) { return { status: 'NOT_READY', code, detail, evidence } }
function cryptoKeyIdentity(keyVersionName) { return typeof keyVersionName === 'string' && keyVersionName.includes('/cryptoKeyVersions/') ? keyVersionName.split('/cryptoKeyVersions/')[0] : null }

async function collectHsmPostures(hsmSigners) {
  if (!hsmSigners || typeof hsmSigners !== 'object') throw new Error('four purpose-separated HSM signers required')
  const postures = {}
  for (const purpose of REQUIRED_HSM_PURPOSES) {
    const signer = hsmSigners[purpose]
    if (!isProductionGoogleCloudHsmSigner(signer)) throw new Error(`${purpose} production HSM signer missing`)
    const posture = await signer.posture()
    if (!posture?.ready || posture.protection_level !== 'HSM' || posture.algorithm !== 'EC_SIGN_P256_SHA256' || !posture.attestation_fingerprint || !posture.key_version_name) throw new Error(`${purpose} HSM proof incomplete`)
    const cryptoKey = cryptoKeyIdentity(posture.key_version_name)
    if (!cryptoKey) throw new Error(`${purpose} HSM CryptoKey identity invalid`)
    postures[purpose] = { ...posture, crypto_key_name: cryptoKey }
  }
  if (new Set(Object.values(postures).map((p) => p.crypto_key_name)).size !== REQUIRED_HSM_PURPOSES.length) throw new Error('HSM CryptoKey reuse across security purposes denied')
  if (new Set(Object.values(postures).map((p) => p.key_version_name)).size !== REQUIRED_HSM_PURPOSES.length) throw new Error('HSM key-version reuse across security purposes denied')
  return postures
}

export async function qualifyGcpLegalInfrastructure({ hsm_signers, dlp_scanner, network_collector, worm_store, tenant_id, policy_version, release, now = new Date() }) {
  if (!hsm_signers || !dlp_scanner || !network_collector || !worm_store || !tenant_id || !policy_version || !release) throw new TypeError('complete production infrastructure context required')
  if (!isProductionGoogleSensitiveDataScanner(dlp_scanner)) return fail('PRODUCTION_DLP_ADAPTER_REQUIRED', 'qualification requires production Google Sensitive Data Protection scanner')
  if (!isProductionGcpNetworkPostureCollector(network_collector)) return fail('PRODUCTION_NETWORK_COLLECTOR_REQUIRED', 'qualification requires production GCP network posture collector')
  if (!isProductionGcsWormEvidenceStore(worm_store)) return fail('PRODUCTION_WORM_STORE_REQUIRED', 'qualification requires production GCS Bucket Lock evidence store')

  let hsm
  try { hsm = await collectHsmPostures(hsm_signers) } catch (error) { return fail('HSM_NOT_READY', error.message) }

  const safeScan = await dlp_scanner.inspect({ payload: SAFE_CANARY })
  if (!safeScan?.safe || !safeScan.scanner_config_fingerprint) return fail('DLP_FALSE_POSITIVE_OR_OUTAGE', safeScan?.reason || 'safe canary was not accepted with a pinned scanner configuration')
  const piiScan = await dlp_scanner.inspect({ payload: PII_CANARY })
  if (piiScan?.safe !== false || !Array.isArray(piiScan.detected_categories) || piiScan.detected_categories.length === 0) return fail('DLP_FALSE_NEGATIVE', 'PII canary was not detected')
  if (piiScan.scanner_config_fingerprint !== safeScan.scanner_config_fingerprint) return fail('DLP_CONFIG_DRIFT', 'DLP scanner configuration changed during qualification')

  let network
  try { network = await network_collector.collect() } catch (error) { return fail('NETWORK_NOT_READY', error.message) }
  if (!network?.ready || network.deny_by_default !== true || network.only_restricted_google_apis !== true || !network.protected_network || !network.protected_resource) return fail('NETWORK_NOT_READY', network?.reason || 'network proof incomplete')

  let worm
  try { worm = await worm_store.posture() } catch (error) { return fail('WORM_NOT_READY', error.message) }
  if (!worm?.ready || worm.retention_locked !== true) return fail('WORM_NOT_READY', worm?.reason || 'immutable evidence store proof incomplete')

  const qualificationBody = {
    schema: 'trustready-gcp-legal-infrastructure-qualification-v3', tenant_id, policy_version, release, qualified_at: now.toISOString(),
    hsm: Object.fromEntries(REQUIRED_HSM_PURPOSES.map((purpose) => [purpose, { provider: hsm[purpose].provider, key_version_name: hsm[purpose].key_version_name, crypto_key_name: hsm[purpose].crypto_key_name, location: hsm[purpose].location, algorithm: hsm[purpose].algorithm, public_key_fingerprint: hsm[purpose].public_key_fingerprint, attestation_fingerprint: hsm[purpose].attestation_fingerprint }])),
    dlp: { scanner_id: safeScan.scanner_id, scanner_version: safeScan.scanner_version, scanner_location: safeScan.scanner_location, scanner_config_fingerprint: safeScan.scanner_config_fingerprint, safe_canary_fingerprint: safeScan.payload_fingerprint, pii_canary_fingerprint: piiScan.payload_fingerprint, pii_categories: piiScan.detected_categories },
    network: { provider: network.provider, restricted_vip: network.restricted_vip, perimeter_name: network.perimeter_name, protected_network: network.protected_network, protected_resource: network.protected_resource, deny_rule: network.deny_rule, allow_rule: network.allow_rule },
    worm: { provider: worm.provider, bucket: worm.bucket, retention_seconds: worm.retention_seconds },
  }

  let signedQualification
  try { signedQualification = await signEnvelopeWithSigner({ body: qualificationBody, signer: hsm_signers.evidence, purpose: 'infrastructure_qualification' }) } catch (error) { return fail('HSM_SIGNING_FAILED', error.message, { qualification_hash: `sha256:${sha256(qualificationBody)}` }) }
  if (signedQualification?.signature?.key_id !== hsm.evidence.key_version_name || signedQualification?.signature?.algorithm !== 'ECDSA_P256_SHA256') return fail('HSM_SIGNING_FAILED', 'qualification was not signed by the qualified evidence HSM key')

  const bytes = Buffer.from(canonicalize(signedQualification), 'utf8')
  const objectName = `qualifications/${tenant_id}/${release}/${now.toISOString().replace(/[:.]/g, '-')}.json`
  const stored = await worm_store.append({ object_name: objectName, bytes, content_type: 'application/json' })
  if (!stored?.stored || !stored.retention_expiration_time) return fail('WORM_WRITE_FAILED', stored?.reason || 'immutable qualification write failed')
  if (stored.content_hash !== `sha256:${sha256(bytes)}`) return fail('WORM_RECEIPT_MISMATCH', 'immutable store receipt hash mismatch')

  return { status: 'CANDIDATE', code: 'CANDIDATE_FOR_REAL_MANDATE_SHADOW_PILOT', qualification_hash: `sha256:${sha256(qualificationBody)}`, signed_qualification: signedQualification, immutable_receipt: stored, controls: { hsm: true, hsm_key_separation: true, dlp: true, network: true, worm: true } }
}
