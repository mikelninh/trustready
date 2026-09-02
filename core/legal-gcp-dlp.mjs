import { canonicalize, sha256, signEnvelopeWithSigner } from './legal-key-identity.mjs'

export const DEFAULT_LEGAL_INFOTYPES = Object.freeze([
  'PERSON_NAME', 'EMAIL_ADDRESS', 'PHONE_NUMBER', 'STREET_ADDRESS', 'DATE_OF_BIRTH',
  'IBAN_CODE', 'FINANCIAL_ACCOUNT_NUMBER', 'CREDIT_CARD_NUMBER', 'PASSPORT',
  'GERMANY_IDENTITY_CARD_NUMBER', 'GERMANY_TAXPAYER_IDENTIFICATION_NUMBER',
  'MEDICAL_RECORD_NUMBER', 'IP_ADDRESS', 'OPENAI_API_KEY', 'GCP_API_KEY', 'ANTHROPIC_API_KEY',
])
export const GCP_DLP_SCANNER_VERSION = 'google-sensitive-data-protection-v3'

export function legalDlpConfigFingerprint({ info_types = DEFAULT_LEGAL_INFOTYPES, min_likelihood = 'POSSIBLE', max_findings = 1000 } = {}) {
  if (!Array.isArray(info_types) || info_types.length === 0) throw new TypeError('DLP infoTypes required')
  const config = {
    provider: 'google-sensitive-data-protection',
    api_version: 'v2',
    info_types: [...new Set(info_types)].sort(),
    min_likelihood,
    include_quote: false,
    max_findings_per_request: max_findings,
  }
  return `sha256:${sha256(config)}`
}

async function token(tokenProvider) {
  if (typeof tokenProvider !== 'function') throw new Error('GCP access token provider required')
  const value = await tokenProvider()
  if (typeof value !== 'string' || value.length < 16) throw new Error('GCP access token unavailable')
  return value
}

export function parseDlpInspectResponse(response) {
  if (!response || typeof response !== 'object' || !response.result || !Array.isArray(response.result.findings)) {
    return { valid: false, safe: false, findings_count: null, detected_categories: [], reason: 'DLP response schema invalid' }
  }
  const findings = response.result.findings
  const categories = [...new Set(findings.map((finding) => finding?.infoType?.name).filter(Boolean))].sort()
  if (findings.some((finding) => !finding || typeof finding !== 'object' || !finding.infoType?.name)) {
    return { valid: false, safe: false, findings_count: findings.length, detected_categories: categories, reason: 'DLP finding schema invalid' }
  }
  return { valid: true, safe: findings.length === 0, findings_count: findings.length, detected_categories: categories }
}

export function createGoogleSensitiveDataScanner({ project_id, location = 'eu', fetch_impl = globalThis.fetch, token_provider, info_types = DEFAULT_LEGAL_INFOTYPES, min_likelihood = 'POSSIBLE', max_payload_bytes = 256 * 1024, max_findings = 1000 }) {
  if (!/^[a-z][a-z0-9-]{4,62}$/.test(project_id || '')) throw new TypeError('valid GCP project id required')
  if (!/^[a-z0-9-]{2,32}$/.test(location || '')) throw new TypeError('valid DLP location required')
  if (!Array.isArray(info_types) || info_types.length === 0) throw new TypeError('DLP infoTypes required')
  if (!Number.isInteger(max_findings) || max_findings < 1 || max_findings > 1000) throw new TypeError('bounded DLP max findings required')
  const endpoint = `https://dlp.googleapis.com/v2/projects/${project_id}/locations/${location}/content:inspect`
  const scannerConfigFingerprint = legalDlpConfigFingerprint({ info_types, min_likelihood, max_findings })

  return {
    backend: 'gcp-sensitive-data-protection', location, info_types: [...info_types], scanner_version: GCP_DLP_SCANNER_VERSION,
    scanner_config_fingerprint: scannerConfigFingerprint,
    async inspect({ payload }) {
      let value
      try { value = canonicalize(payload) } catch { return { safe: false, reason: 'payload cannot be safely serialised', payload_fingerprint: null, scanner_config_fingerprint: scannerConfigFingerprint } }
      const bytes = Buffer.byteLength(value, 'utf8')
      if (bytes > max_payload_bytes) return { safe: false, reason: 'payload exceeds DLP inspection limit', payload_fingerprint: `sha256:${sha256(value)}`, scanner_config_fingerprint: scannerConfigFingerprint }
      let accessToken
      try { accessToken = await token(token_provider) } catch { return { safe: false, reason: 'DLP authentication unavailable', payload_fingerprint: `sha256:${sha256(value)}`, scanner_config_fingerprint: scannerConfigFingerprint } }
      let response
      try {
        response = await fetch_impl(endpoint, {
          method: 'POST', redirect: 'error',
          headers: { authorization: `Bearer ${accessToken}`, 'content-type': 'application/json', accept: 'application/json' },
          body: JSON.stringify({ inspectConfig: { infoTypes: info_types.map((name) => ({ name })), minLikelihood: min_likelihood, includeQuote: false, limits: { maxFindingsPerRequest: max_findings } }, item: { value } }),
        })
      } catch { return { safe: false, reason: 'DLP service unavailable', payload_fingerprint: `sha256:${sha256(value)}`, scanner_config_fingerprint: scannerConfigFingerprint } }
      if (!response?.ok) return { safe: false, reason: `DLP request denied (${Number(response?.status) || 0})`, payload_fingerprint: `sha256:${sha256(value)}`, scanner_config_fingerprint: scannerConfigFingerprint }
      let body
      try { body = await response.json() } catch { return { safe: false, reason: 'DLP response was not valid JSON', payload_fingerprint: `sha256:${sha256(value)}`, scanner_config_fingerprint: scannerConfigFingerprint } }
      const parsed = parseDlpInspectResponse(body)
      if (!parsed.valid) return { ...parsed, payload_fingerprint: `sha256:${sha256(value)}`, payload_bytes: bytes, scanner_config_fingerprint: scannerConfigFingerprint }
      return {
        ...parsed, payload_fingerprint: `sha256:${sha256(value)}`, payload_bytes: bytes,
        scanner_id: 'gcp-sensitive-data-protection', scanner_version: GCP_DLP_SCANNER_VERSION, scanner_location: location,
        scanner_config_fingerprint: scannerConfigFingerprint,
      }
    },
  }
}

export async function createSignedDlpAttestation({ scanner, signer, tenant_id, matter_id, payload, policy_version, now = new Date(), ttl_ms = 45_000 }) {
  if (!scanner || !signer || !tenant_id || !matter_id || !policy_version) throw new TypeError('DLP attestation context required')
  const result = await scanner.inspect({ payload })
  if (!result.safe) return { safe: false, scan: result, attestation: null }
  if (!result.scanner_id || !result.scanner_version || !result.scanner_config_fingerprint) return { safe: false, scan: { ...result, reason: 'DLP scanner identity/version/config missing' }, attestation: null }
  const body = {
    schema: 'trustready-dlp-attestation-v2', safe: true, tenant_id, matter_id,
    payload_fingerprint: result.payload_fingerprint, policy_version,
    detected_categories: result.detected_categories || [], findings_count: result.findings_count,
    scanner_id: result.scanner_id, scanner_version: result.scanner_version, scanner_location: result.scanner_location,
    scanner_config_fingerprint: result.scanner_config_fingerprint,
    observed_at: now.toISOString(), expires_at: new Date(now.getTime() + ttl_ms).toISOString(),
  }
  const attestation = await signEnvelopeWithSigner({ body, signer, purpose: 'dlp_attestation' })
  return { safe: true, scan: result, attestation }
}
