import crypto from 'node:crypto'
import dns from 'node:dns/promises'
import https from 'node:https'
import net from 'node:net'
import tls from 'node:tls'
import { sha256, signEnvelopeWithSigner } from './legal-key-identity.mjs'

const RESTRICTED_VIP = new Set(['199.36.153.4', '199.36.153.5', '199.36.153.6', '199.36.153.7'])
const TRANSPORT_BRAND = Symbol('trustready.restricted-google-api-transport')
const PREPARED_BRAND = Symbol('trustready.prepared-restricted-request')

function endpointUrl(endpoint) {
  let url
  try { url = new URL(endpoint) } catch { return null }
  if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443')) return null
  if (!url.hostname.endsWith('.googleapis.com') || net.isIP(url.hostname)) return null
  return url
}
function normalizeRemote(address) { return typeof address === 'string' && address.startsWith('::ffff:') ? address.slice(7) : address }
function requestBytes(value) {
  if (Buffer.isBuffer(value)) return value
  if (value instanceof Uint8Array) return Buffer.from(value)
  if (typeof value === 'string') return Buffer.from(value, 'utf8')
  return Buffer.from(JSON.stringify(value), 'utf8')
}
function safeHeader(name, value) {
  return /^[A-Za-z0-9-]{1,64}$/.test(name) && !['host','content-length','connection'].includes(name.toLowerCase()) && typeof value === 'string' && !/[\r\n]/.test(value) && value.length <= 8192
}
function closeSocket(socket) { try { socket?.destroy() } catch {} }

function openTls({ address, hostname, tls_connect, timeout_ms }) {
  return new Promise((resolve, reject) => {
    let settled = false
    let socket
    const fail = (error) => {
      if (settled) return
      settled = true
      closeSocket(socket)
      reject(error instanceof Error ? error : new Error(String(error)))
    }
    try {
      socket = tls_connect({ host: address, port: 443, servername: hostname, rejectUnauthorized: true, ALPNProtocols: ['http/1.1'] })
      socket.setTimeout?.(timeout_ms, () => fail(new Error('restricted TLS timeout')))
      socket.once?.('error', () => fail(new Error('restricted TLS connection failed')))
      socket.once?.('secureConnect', () => {
        if (settled) return
        const remote = normalizeRemote(socket.remoteAddress)
        const cert = socket.getPeerCertificate?.(true)
        const peerFingerprint = cert?.raw ? `sha256:${crypto.createHash('sha256').update(cert.raw).digest('hex')}` : null
        if (socket.authorized !== true || remote !== address || !RESTRICTED_VIP.has(remote) || !peerFingerprint || socket.alpnProtocol !== 'http/1.1') return fail(new Error('restricted TLS peer validation failed'))
        settled = true
        resolve({ socket, remote_address: remote, peer_fingerprint: peerFingerprint })
      })
    } catch (error) { fail(error) }
  })
}

export function createRestrictedGoogleApiTransport({ signer, resolve4 = dns.resolve4, tls_connect = tls.connect, https_request = https.request, timeout_ms = 5000, max_request_bytes = 1024 * 1024, max_response_bytes = 2 * 1024 * 1024 }) {
  if (!signer || signer.hardware_backed !== true || typeof signer.sign !== 'function' || typeof signer.posture !== 'function') throw new TypeError('hardware-backed network signer required')
  if (typeof resolve4 !== 'function' || typeof tls_connect !== 'function' || typeof https_request !== 'function') throw new TypeError('restricted transport dependencies required')
  return Object.freeze({ [TRANSPORT_BRAND]: true, signer, resolve4, tls_connect, https_request, timeout_ms, max_request_bytes, max_response_bytes })
}

export async function restrictedTransportPosture(transport) {
  if (transport?.[TRANSPORT_BRAND] !== true) return { ready: false, reason: 'untrusted restricted transport' }
  const posture = await transport.signer.posture()
  if (!posture?.ready || posture.protection_level !== 'HSM' || posture.algorithm !== 'EC_SIGN_P256_SHA256' || !posture.key_version_name) return { ready: false, reason: 'network transport signer HSM posture invalid' }
  return posture
}

export async function prepareRestrictedGoogleApiRequest({ transport, endpoint, body, region, now = new Date() }) {
  if (transport?.[TRANSPORT_BRAND] !== true) return { ready: false, reason: 'untrusted restricted transport' }
  const url = endpointUrl(endpoint)
  if (!url || !region) return { ready: false, reason: 'restricted Google API endpoint/region required' }
  const bytes = requestBytes(body)
  if (!bytes.length || bytes.length > transport.max_request_bytes) return { ready: false, reason: 'outbound request size denied' }
  let addresses
  try { addresses = [...new Set(await transport.resolve4(url.hostname))].sort() } catch { return { ready: false, reason: 'restricted DNS resolution failed' } }
  if (!addresses.length || addresses.some((address) => net.isIP(address) !== 4 || !RESTRICTED_VIP.has(address))) return { ready: false, reason: 'hostname did not resolve exclusively to restricted Google VIP' }
  const address = addresses[0]
  let tlsProof
  try { tlsProof = await openTls({ address, hostname: url.hostname, tls_connect: transport.tls_connect, timeout_ms: transport.timeout_ms }) } catch (error) { return { ready: false, reason: error.message } }
  const requestFingerprint = `sha256:${sha256(bytes)}`
  const bodyAttestation = {
    schema: 'trustready-network-attestation-v1', endpoint: url.origin, hostname: url.hostname, region,
    tls: true, certificate_valid: true, redirected: false, route_class: 'restricted-googleapis',
    resolved_addresses: addresses, connected_address: tlsProof.remote_address, peer_fingerprint: tlsProof.peer_fingerprint,
    request_fingerprint: requestFingerprint, observed_at: now.toISOString(), expires_at: new Date(now.getTime() + 30_000).toISOString(),
  }
  let attestation
  try { attestation = await signEnvelopeWithSigner({ body: bodyAttestation, signer: transport.signer, purpose: 'network_attestation' }) } catch (error) { closeSocket(tlsProof.socket); return { ready: false, reason: `network attestation signing failed: ${error.message}` } }
  return {
    ready: true,
    request_fingerprint: requestFingerprint,
    network_attestation: attestation,
    prepared: { [PREPARED_BRAND]: true, transport, socket: tlsProof.socket, url, bytes, request_fingerprint: requestFingerprint, peer_fingerprint: tlsProof.peer_fingerprint, connected_address: tlsProof.remote_address, used: false },
  }
}

export function cancelPreparedGoogleApiRequest(prepared) {
  if (prepared?.[PREPARED_BRAND] !== true) return false
  closeSocket(prepared.socket)
  prepared.used = true
  return true
}

export function sendPreparedGoogleApiRequest({ transport, prepared, headers = {} }) {
  return new Promise((resolve) => {
    if (transport?.[TRANSPORT_BRAND] !== true || prepared?.[PREPARED_BRAND] !== true || prepared.transport !== transport || prepared.used === true) return resolve({ ok: false, reason: 'prepared restricted request invalid or already consumed' })
    for (const [name, value] of Object.entries(headers)) if (!safeHeader(name, value)) { cancelPreparedGoogleApiRequest(prepared); return resolve({ ok: false, reason: 'unsafe outbound header denied' }) }
    prepared.used = true
    const requestHeaders = { 'content-type': 'application/json', accept: 'application/json', 'content-length': String(prepared.bytes.length), connection: 'close', ...headers }
    let req
    let responseBytes = 0
    try {
      req = transport.https_request(prepared.url, {
        method: 'POST', agent: false, headers: requestHeaders,
        createConnection: () => prepared.socket,
      }, (res) => {
        if (res.socket !== prepared.socket || normalizeRemote(res.socket?.remoteAddress) !== prepared.connected_address) {
          closeSocket(prepared.socket)
          return resolve({ ok: false, reason: 'HTTP request did not use attested TLS socket' })
        }
        if (res.statusCode >= 300 && res.statusCode < 400) { closeSocket(prepared.socket); return resolve({ ok: false, reason: 'provider redirect denied', status: res.statusCode }) }
        const chunks = []
        res.on('data', (chunk) => {
          responseBytes += chunk.length
          if (responseBytes > transport.max_response_bytes) { closeSocket(prepared.socket); return }
          chunks.push(Buffer.from(chunk))
        })
        res.on('end', () => {
          if (responseBytes > transport.max_response_bytes) return resolve({ ok: false, reason: 'provider response exceeds limit' })
          const response = Buffer.concat(chunks)
          resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, body: response, response_fingerprint: `sha256:${sha256(response)}`, request_fingerprint: prepared.request_fingerprint, peer_fingerprint: prepared.peer_fingerprint })
        })
      })
      req.setTimeout?.(transport.timeout_ms, () => { req.destroy?.(); closeSocket(prepared.socket); resolve({ ok: false, reason: 'provider request timeout' }) })
      req.once?.('error', () => { closeSocket(prepared.socket); resolve({ ok: false, reason: 'provider request failed' }) })
      req.end(prepared.bytes)
    } catch { closeSocket(prepared.socket); resolve({ ok: false, reason: 'provider request failed' }) }
  })
}
