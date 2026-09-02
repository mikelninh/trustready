import net from 'node:net'
import tls from 'node:tls'
import dns from 'node:dns/promises'
import { signEnvelopeWithSigner } from './legal-key-identity.mjs'

const RESTRICTED_VIP = new Set(['199.36.153.4', '199.36.153.5', '199.36.153.6', '199.36.153.7'])

function parseGoogleApiEndpoint(endpoint) {
  let url
  try { url = new URL(endpoint) } catch { return null }
  if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443')) return null
  if (!url.hostname.endsWith('.googleapis.com') || net.isIP(url.hostname)) return null
  return url
}

export function evaluateRestrictedGoogleDns({ endpoint, addresses }) {
  const url = parseGoogleApiEndpoint(endpoint)
  if (!url) return { ready: false, reason: 'Google API HTTPS hostname required' }
  if (!Array.isArray(addresses) || addresses.length === 0) return { ready: false, reason: 'DNS returned no IPv4 addresses' }
  const unique = [...new Set(addresses)]
  if (unique.some((address) => net.isIP(address) !== 4 || !RESTRICTED_VIP.has(address))) {
    return { ready: false, reason: 'Google API hostname did not resolve exclusively to restricted VIP' }
  }
  return { ready: true, hostname: url.hostname, endpoint: url.origin, addresses: unique.sort() }
}

function connectTls({ hostname, address, tls_connect = tls.connect, timeout_ms = 5000 }) {
  return new Promise((resolve) => {
    let settled = false
    let socket
    const finish = (result) => {
      if (settled) return
      settled = true
      try { socket?.destroy() } catch {}
      resolve(result)
    }
    try {
      socket = tls_connect({ host: address, port: 443, servername: hostname, rejectUnauthorized: true, ALPNProtocols: ['h2', 'http/1.1'] }, () => {
        const cert = socket.getPeerCertificate?.(true)
        const remote = socket.remoteAddress
        const authorised = socket.authorized === true
        const authorizationError = socket.authorizationError || null
        const fingerprint = cert?.raw ? `sha256:${awaitHash(cert.raw)}` : null
        finish({ ok: authorised && RESTRICTED_VIP.has(remote), remote_address: remote, certificate_valid: authorised, authorization_error: authorizationError, peer_fingerprint: fingerprint, alpn: socket.alpnProtocol || null })
      })
      socket.setTimeout?.(timeout_ms, () => finish({ ok: false, reason: 'TLS timeout' }))
      socket.on?.('error', () => finish({ ok: false, reason: 'TLS connection failed' }))
    } catch {
      finish({ ok: false, reason: 'TLS connection failed' })
    }
  })
}

function awaitHash(bytes) {
  const crypto = globalThis.__trustreadyCrypto
  if (crypto?.createHash) return crypto.createHash('sha256').update(bytes).digest('hex')
  return null
}

export function createRestrictedGoogleApiProbe({ signer, resolve4 = dns.resolve4, tls_connect = tls.connect, timeout_ms = 5000 }) {
  if (!signer || typeof signer.sign !== 'function') throw new TypeError('separate network attestation signer required')
  return async function networkProbe({ endpoint, hostname, region, now = new Date() }) {
    const parsed = parseGoogleApiEndpoint(endpoint)
    if (!parsed || parsed.hostname !== hostname) return null
    let addresses
    try { addresses = await resolve4(hostname) } catch { return null }
    const dnsProof = evaluateRestrictedGoogleDns({ endpoint, addresses })
    if (!dnsProof.ready) return null

    const tlsResults = []
    for (const address of dnsProof.addresses) {
      const result = await connectTls({ hostname, address, tls_connect, timeout_ms })
      tlsResults.push(result)
      if (!result.ok) return null
    }
    const peers = [...new Set(tlsResults.map((result) => result.remote_address))]
    if (peers.length !== dnsProof.addresses.length || peers.some((peer) => !RESTRICTED_VIP.has(peer))) return null

    const body = {
      schema: 'trustready-network-attestation-v1',
      endpoint: parsed.origin,
      hostname,
      region,
      tls: true,
      certificate_valid: true,
      redirected: false,
      route_class: 'restricted-googleapis',
      resolved_addresses: dnsProof.addresses,
      peer_fingerprint: tlsResults[0]?.peer_fingerprint || null,
      observed_at: now.toISOString(),
      expires_at: new Date(now.getTime() + 30_000).toISOString(),
    }
    return signEnvelopeWithSigner({ body, signer, purpose: 'network_attestation' })
  }
}
