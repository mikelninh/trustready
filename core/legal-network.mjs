import { parseTime, verifyEnvelope } from './legal-key-identity.mjs'

const RESTRICTED_VIP = new Set(['199.36.153.4', '199.36.153.5', '199.36.153.6', '199.36.153.7'])

function safeHttpsEndpoint(urlString) {
  try {
    const url = new URL(urlString)
    if (url.protocol !== 'https:' || url.username || url.password) return null
    if (url.port && url.port !== '443') return null
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(url.hostname) || url.hostname.includes(':')) return null
    return url
  } catch { return null }
}

function validateNetworkProfile(policy, proof) {
  if (policy?.network_profile !== 'gcp-restricted-googleapis') return { valid: true }
  if (proof.route_class !== 'restricted-googleapis') return { valid: false, reason: 'restricted Google API route class required' }
  if (!Array.isArray(proof.resolved_addresses) || proof.resolved_addresses.length === 0) return { valid: false, reason: 'restricted VIP DNS evidence missing' }
  if (proof.resolved_addresses.some((address) => !RESTRICTED_VIP.has(address))) return { valid: false, reason: 'network proof includes non-restricted IP' }
  if (!proof.hostname?.endsWith('.googleapis.com')) return { valid: false, reason: 'Google API hostname required for restricted profile' }
  return { valid: true }
}

export function evaluateNetworkEgress({ endpoint, provider, use_case, region, network_probe, key_store, now = new Date() }) {
  const url = safeHttpsEndpoint(endpoint)
  if (!url) return { allowed: false, reason: 'HTTPS hostname endpoint required' }
  const policy = provider?.use_cases?.[use_case]
  const allowed = policy?.endpoints?.[region]
  if (!Array.isArray(allowed) || !allowed.includes(url.origin)) return { allowed: false, reason: 'endpoint not bound to signed provider policy' }
  if (typeof network_probe !== 'function') return { allowed: false, reason: 'signed network attestation required' }
  const envelope = network_probe({ endpoint: url.origin, hostname: url.hostname, region, now })
  const attested = verifyEnvelope({ envelope, key_store, purpose: 'network_attestation', now })
  if (!attested.valid) return { allowed: false, reason: 'network attestation invalid or signer untrusted' }
  const proof = attested.body
  if (proof.schema !== 'trustready-network-attestation-v1' || proof.tls !== true || proof.certificate_valid !== true || proof.redirected !== false || proof.hostname !== url.hostname || proof.region !== region || proof.endpoint !== url.origin) {
    return { allowed: false, reason: 'network path evidence invalid' }
  }
  const profile = validateNetworkProfile(policy, proof)
  if (!profile.valid) return { allowed: false, reason: profile.reason }
  const observed = parseTime(proof.observed_at)
  const expires = parseTime(proof.expires_at)
  if (observed > now.getTime() + 5000 || expires <= now.getTime() || expires - observed > 60000) return { allowed: false, reason: 'network attestation freshness invalid' }
  return {
    allowed: true,
    endpoint: url.origin,
    network_proof: {
      hostname: proof.hostname, region: proof.region, tls: true, certificate_valid: true,
      route_class: proof.route_class || null, resolved_addresses: proof.resolved_addresses || [],
      peer_fingerprint: proof.peer_fingerprint || null, attestor_key_id: attested.signer_key_id,
    },
  }
}

export function verifyEgressEnforcement({ attestation, key_store, tenant_id, policy_version, now = new Date() }) {
  const verified = verifyEnvelope({ envelope: attestation, key_store, purpose: 'egress_enforcement', now })
  if (!verified.valid) return { valid: false, reason: 'egress enforcement attestation invalid' }
  const body = verified.body
  if (body.schema !== 'trustready-egress-enforcement-v1' || body.tenant_id !== tenant_id || body.policy_version !== policy_version || body.deny_by_default !== true || body.only_gateway !== true) {
    return { valid: false, reason: 'egress enforcement posture invalid' }
  }
  const observed = parseTime(body.observed_at)
  const expires = parseTime(body.expires_at)
  if (observed > now.getTime() + 5000 || expires <= now.getTime() || expires - observed > 5 * 60 * 1000) return { valid: false, reason: 'egress enforcement attestation stale' }
  return { valid: true, signer_key_id: verified.signer_key_id, release: body.release || null }
}
