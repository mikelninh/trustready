import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { EventEmitter } from 'node:events'
import { canonicalize, createKeyTrustStore, verifyEnvelope } from './legal-key-identity.mjs'
import { cancelPreparedGoogleApiRequest, createRestrictedGoogleApiTransport, prepareRestrictedGoogleApiRequest, restrictedTransportPosture, sendPreparedGoogleApiRequest } from './legal-gcp-bound-transport.mjs'
import { buildVertexProposalRequest, parseVertexProposalResponse } from './legal-vertex-proposal.mjs'

const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const keyId = 'projects/p/locations/europe-west3/keyRings/legal/cryptoKeys/network/cryptoKeyVersions/1'
const signer = {
  hardware_backed: true,
  async posture() { return { ready: true, provider: 'gcp-cloud-hsm', protection_level: 'HSM', algorithm: 'EC_SIGN_P256_SHA256', key_version_name: keyId, location: 'europe-west3' } },
  async sign({ body }) { return { algorithm: 'ECDSA_P256_SHA256', key_id: keyId, value: crypto.sign('sha256', Buffer.from(canonicalize(body)), ec.privateKey).toString('base64') } },
}
function tlsFactory({ remote = '199.36.153.4', authorised = true, alpn = 'http/1.1' } = {}) {
  return () => {
    const socket = new EventEmitter()
    socket.authorized = authorised
    socket.remoteAddress = remote
    socket.alpnProtocol = alpn
    socket.getPeerCertificate = () => ({ raw: Buffer.from('bound-transport-cert') })
    socket.setTimeout = () => socket
    socket.destroyed = false
    socket.destroy = () => { socket.destroyed = true }
    queueMicrotask(() => socket.emit('secureConnect'))
    return socket
  }
}
function httpsFactory({ responseBody, status = 200, swapSocket = false } = {}) {
  return (_url, options, callback) => {
    const req = new EventEmitter()
    req.setTimeout = () => req
    req.destroy = () => {}
    req.end = (bytes) => {
      req.sent = Buffer.from(bytes)
      const socket = options.createConnection()
      const res = new EventEmitter()
      res.statusCode = status
      res.socket = swapSocket ? { remoteAddress: '199.36.153.4' } : socket
      queueMicrotask(() => {
        callback(res)
        queueMicrotask(() => {
          if (responseBody) res.emit('data', Buffer.from(responseBody))
          res.emit('end')
        })
      })
    }
    return req
  }
}
const endpoint = 'https://europe-west3-aiplatform.googleapis.com/v1/projects/p/locations/europe-west3/publishers/google/models/gemini:generateContent'
const payload = { subject_hash: `sha256:${'a'.repeat(64)}`, body_excerpt: 'Pseudonymised correspondence.' }
const vertex = buildVertexProposalRequest({ payload, use_case: 'summarise_mail' })
const vertexResponse = JSON.stringify({ candidates: [{ content: { parts: [{ text: JSON.stringify({ type: 'summary', text: 'Short neutral summary', source_refs: ['doc-1'] }) }] } }] })

function transport(overrides = {}) { return createRestrictedGoogleApiTransport({ signer, resolve4: async () => ['199.36.153.4'], tls_connect: tlsFactory(), https_request: httpsFactory({ responseBody: vertexResponse }), ...overrides }) }

test('bound transport attests exact request bytes and sends them over the same TLS socket once', async () => {
  const t = transport()
  assert.equal((await restrictedTransportPosture(t)).ready, true)
  const prepared = await prepareRestrictedGoogleApiRequest({ transport: t, endpoint, body: vertex.bytes, region: 'europe-west3', now: new Date('2026-09-02T12:00:00Z') })
  assert.equal(prepared.ready, true)
  assert.equal(prepared.request_fingerprint, vertex.request_fingerprint)
  assert.equal(prepared.network_attestation.body.request_fingerprint, vertex.request_fingerprint)
  const ks = createKeyTrustStore([{ key_id: keyId, purpose: 'network_attestation', public_key: ec.publicKey }])
  assert.equal(verifyEnvelope({ envelope: prepared.network_attestation, key_store: ks, purpose: 'network_attestation', now: new Date('2026-09-02T12:00:00Z') }).valid, true)
  const sent = await sendPreparedGoogleApiRequest({ transport: t, prepared: prepared.prepared, headers: { authorization: 'Bearer synthetic-token-123456' } })
  assert.equal(sent.ok, true)
  assert.equal(sent.request_fingerprint, vertex.request_fingerprint)
  assert.equal(parseVertexProposalResponse(sent.body).valid, true)
  const replay = await sendPreparedGoogleApiRequest({ transport: t, prepared: prepared.prepared })
  assert.equal(replay.ok, false)
  assert.match(replay.reason, /consumed/)
})

test('bound transport fails closed on DNS poison, invalid TLS peer or non-http1 session', async () => {
  for (const t of [
    transport({ resolve4: async () => ['8.8.8.8'] }),
    transport({ tls_connect: tlsFactory({ remote: '8.8.8.8' }) }),
    transport({ tls_connect: tlsFactory({ authorised: false }) }),
    transport({ tls_connect: tlsFactory({ alpn: 'h2' }) }),
  ]) assert.equal((await prepareRestrictedGoogleApiRequest({ transport: t, endpoint, body: vertex.bytes, region: 'europe-west3' })).ready, false)
})

test('bound transport rejects socket substitution and redirects', async () => {
  for (const cfg of [
    { https_request: httpsFactory({ responseBody: vertexResponse, swapSocket: true }) },
    { https_request: httpsFactory({ responseBody: '', status: 302 }) },
  ]) {
    const t = transport(cfg)
    const prepared = await prepareRestrictedGoogleApiRequest({ transport: t, endpoint, body: vertex.bytes, region: 'europe-west3' })
    assert.equal(prepared.ready, true)
    const result = await sendPreparedGoogleApiRequest({ transport: t, prepared: prepared.prepared })
    assert.equal(result.ok, false)
  }
})

test('prepared request can be cancelled without sending payload', async () => {
  const t = transport()
  const prepared = await prepareRestrictedGoogleApiRequest({ transport: t, endpoint, body: vertex.bytes, region: 'europe-west3' })
  assert.equal(cancelPreparedGoogleApiRequest(prepared.prepared), true)
  assert.equal((await sendPreparedGoogleApiRequest({ transport: t, prepared: prepared.prepared })).ok, false)
})

test('Vertex proposal adapter never emits tools and rejects tool/function-shaped output', () => {
  assert.equal('tools' in vertex.provider_body, false)
  assert.deepEqual(vertex.proposal_request.security.tools, [])
  assert.equal(parseVertexProposalResponse(Buffer.from(vertexResponse)).valid, true)
  const functionResponse = Buffer.from(JSON.stringify({ candidates: [{ content: { parts: [{ functionCall: { name: 'sendEmail' }, text: '{}' }] } }] }))
  assert.equal(parseVertexProposalResponse(functionResponse).valid, false)
  const badProposal = Buffer.from(JSON.stringify({ candidates: [{ content: { parts: [{ text: JSON.stringify({ type: 'summary', text: 'x', recipient: 'victim' }) }] } }] }))
  assert.equal(parseVertexProposalResponse(badProposal).valid, false)
})
