import { canonicalize, sha256, signEnvelopeWithSigner } from './legal-key-identity.mjs'

export const DEFAULT_LEGAL_INFOTYPES = Object.freeze([
  'PERSON_NAME', 'EMAIL_ADDRESS', 'PHONE_NUMBER', 'STREET_ADDRESS', 'DATE_OF_BIRTH',
  'IBAN_CODE', 'FINANCIAL_ACCOUNT_NUMBER', 'CREDIT_CARD_NUMBER', 'PASSPORT',
  'GERMANY_IDENTITY_CARD_NUMBER', 'GERMANY_TAXPAYER_IDENTIFICATION_NUMBER',
  'MEDICAL_RECORD_NUMBER', 'IP_ADDRESS', 'OPENAI_API_KEY', 'GCP_API_KEY', 'ANTHROPIC_API_KEY',
])

async function token(tokenProvider) {
  if (typeof tokenProvider !== 'function') throw new Error('GCP access token provider required')
  const value = await tokenProvider()
  if (typeof value !== 'string' || value.length < 16) throw new Error('GCP access token unavailable')
  return value
}

export function parseDlpInspectResponse(response) {
  const findings = Array.isArray(response?.result?.findings) ? response.result.findings : []
  const categories = [...new Set(findings.map((finding) => finding?.infoType?.name).filter(Boolean))].sort()
  return { safe: findings.length === 0, findings_count: findings.length, detected_categories: categories }
}

export function createGoogleSensitiveDataScanner({ project_id, location = 'eu', fetch_impl = globalThis.fetch, token_provider, info_types = DEFAULT_LEGAL_INFOTYPES, min_likelihood = 'POSSIBLE', max_payload_bytes = 256 * 1024 }) {
  if (!/^[a-z][a-z0-9-]{4,62}$/.test(project_id || '')) throw new TypeError('valid GCP project id required')
  if (!/^[a-z0-9-]{2,32}$/.test(location || '')) throw new TypeError('valid DLP location required')
  if (!Array.isArray(info_types) || info_types.length === 0) throw new TypeError('DLP infoTypes required')
  const endpoint = `https://dlp.googleapis.com/v2/projects/${project_id}/locations/${location}/content:inspect`

  return {
    backend: 'gcp-sensitive-data-protection',
    location,
    info_types: [...info_types],
    async inspect({ payload }) {
      let value
      try { value = canonicalize(payload) } catch { return { safe: false, reason: 'payload cannot be safely serialised', payload_fingerprint: null } }
      const bytes = Buffer.byteLength(value, 'utf8')
      if (bytes > max_payload_bytes) return { safe: false, reason: 'payload exceeds DLP inspection limit', payload_fingerprint: `sha256:${sha256(value)}` }
      const accessToken = await token(token_provider)
      let response
      try {
        response = await fetch_impl(endpoint, {
          method: 'POST',
          redirect: 'error',
          headers: { authorization: `Bearer ${accessToken}`, 'content-type': 'application/json', accept: 'application/json' },
          body: JSON.stringify({
            inspectConfig: {
              infoTypes: info_types.map((name) => ({ name })),
              minLikelihood: min_likelihood,
              includeQuote: false,
              limits: { maxFindingsPerRequest: 1000 },
            },
            item: { value },
          }),
        })
      } catch {
        return { safe: false, reason: 'DLP service unavailable', payload_fingerprint: `sha256:${sha256(value)}` }
      }
      if (!response?.ok) return { safe: false, reason: `DLP request denied (${Number(response?.status) || 0})`, payload_fingerprint: `sha256:${sha256(value)}` }
      const parsed = parseDlpInspectResponse(await response.json())
      return {
        ...parsed,
        payload_fingerprint: `sha256:${sha256(value)}`,
        payload_bytes: bytes,
        scanner_id: 'gcp-sensitive-data-protection',
        scanner_location: location,
      }
    },
  }
}

export async function createSignedDlpAttestation({ scanner, signer, tenant_id, matter_id, payload, policy_version, now = new Date(), ttl_ms = 45_000 }) {
  if (!scanner || !signer || !tenant_id || !matter_id || !policy_version) throw new TypeError('DLP attestation context required')
  const result = await scanner.inspect({ payload })
  if (!result.safe) return { safe: false, scan: result, attestation: null }
  const body = {
    schema: 'trustready-dlp-attestation-v1',
    safe: true,
    tenant_id,
    matter_id,
    payload_fingerprint: result.payload_fingerprint,
    policy_version,
    detected_categories: result.detected_categories || [],
    findings_count: result.findings_count || 0,
    scanner_id: result.scanner_id,
    scanner_location: result.scanner_location,
    observed_at: now.toISOString(),
    expires_at: new Date(now.getTime() + ttl_ms).toISOString(),
  }
  const attestation = await signEnvelopeWithSigner({ body, signer, purpose: 'dlp_attestation' })
  return { safe: true, scan: result, attestation }
}
