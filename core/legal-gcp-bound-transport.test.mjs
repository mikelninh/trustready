import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import https from 'node:https'
import net from 'node:net'
import { EventEmitter } from 'node:events'
import { canonicalize, createKeyTrustStore, verifyEnvelope } from './legal-key-identity.mjs'
import { cancelPreparedGoogleApiRequest, createRestrictedGoogleApiTransport, createRestrictedGoogleApiTransportForTest, isProductionRestrictedGoogleApiTransport, isTestRestrictedGoogleApiTransport, prepareRestrictedGoogleApiRequest, restrictedTransportPosture, sendPreparedGoogleApiRequest } from './legal-gcp-bound-transport.mjs'
import { buildVertexProposalRequest, parseVertexProposalResponse } from './legal-vertex-proposal.mjs'

const NOW = new Date('2026-09-02T12:00:00Z')
const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const keyId = 'projects/p/locations/europe-west3/keyRings/legal/cryptoKeys/network/cryptoKeyVersions/1'
const signer = { hardware_backed: true, async posture() { return { ready: true, provider: 'gcp-cloud-hsm', protection_level: 'HSM', algorithm: 'EC_SIGN_P256_SHA256', key_version_name: keyId, location: 'europe-west3' } }, async sign({ body }) { return { algorithm: 'ECDSA_P256_SHA256', key_id: keyId, value: crypto.sign('sha256', Buffer.from(canonicalize(body)), ec.privateKey).toString('base64') } } }
function tlsFactory({ remote = '199.36.153.4', authorised = true, alpn = 'http/1.1' } = {}) { return () => { const socket = new EventEmitter(); socket.authorized = authorised; socket.remoteAddress = remote; socket.alpnProtocol = alpn; socket.getPeerCertificate = () => ({ raw: Buffer.from('bound-transport-cert') }); socket.setTimeout = () => socket; socket.destroyed = false; socket.destroy = () => { socket.destroyed = true }; queueMicrotask(() => socket.emit('secureConnect')); return socket } }
function httpsFactory({ responseBody, status = 200, swapSocket = false, onRequest = null } = {}) { return (_url, options, callback) => { const req = new EventEmitter(); req.setTimeout = () => req; req.destroy = () => {}; req.end = (bytes) => { req.sent = Buffer.from(bytes); onRequest?.({ options, bytes: req.sent }); const socket = options.agent.createConnection({}); const res = new EventEmitter(); res.statusCode = status; res.socket = swapSocket ? { remoteAddress: '199.36.153.4' } : socket; queueMicrotask(() => { callback(res); queueMicrotask(() => { if (responseBody) res.emit('data', Buffer.from(responseBody)); res.emit('end') }) }) }; return req } }
const endpoint = 'https://europe-west3-aiplatform.googleapis.com/v1/projects/p/locations/europe-west3/publishers/google/models/gemini:generateContent'
const payload = { subject_hash: `sha256:${'a'.repeat(64)}`, body_excerpt: 'Pseudonymised correspondence.' }
const vertex = buildVertexProposalRequest({ payload, use_case: 'summarise_mail' })
const vertexResponse = JSON.stringify({ candidates: [{ content: { parts: [{ text: JSON.stringify({ type: 'summary', text: 'Short neutral summary', source_refs: ['doc-1'] }) }] } }] })
function transport(overrides = {}) { return createRestrictedGoogleApiTransportForTest({ signer, resolve4: async () => ['199.36.153.4'], tls_connect: tlsFactory(), https_request: httpsFactory({ responseBody: vertexResponse }), ...overrides }) }

test('production transport rejects self-asserted HSM signers while test transport remains explicitly test-branded', () => {
  assert.throws(() => createRestrictedGoogleApiTransport({ signer }), /production Google Cloud HSM signer/)
  const t = transport()
  assert.equal(isTestRestrictedGoogleApiTransport(t), true)
  assert.equal(isProductionRestrictedGoogleApiTransport(t), false)
})

test('bound transport attests full target plus exact body and sends over same TLS socket once', async () => { const t=transport();assert.equal((await restrictedTransportPosture(t)).ready,true);const prepared=await prepareRestrictedGoogleApiRequest({transport:t,endpoint,body:vertex.bytes,region:'europe-west3',now:NOW});assert.equal(prepared.ready,true);assert.equal(prepared.body_fingerprint,vertex.request_fingerprint);assert.notEqual(prepared.request_fingerprint,vertex.request_fingerprint);assert.equal(prepared.network_attestation.body.target_url,endpoint);assert.equal(prepared.network_attestation.body.body_fingerprint,vertex.request_fingerprint);assert.equal(prepared.network_attestation.body.request_fingerprint,prepared.request_fingerprint);const ks=createKeyTrustStore([{key_id:keyId,purpose:'network_attestation',public_key:ec.publicKey}]);assert.equal(verifyEnvelope({envelope:prepared.network_attestation,key_store:ks,purpose:'network_attestation',now:NOW}).valid,true);assert.equal(Object.isFrozen(prepared.prepared),true);assert.deepEqual(Object.keys(prepared.prepared),[]);const sent=await sendPreparedGoogleApiRequest({transport:t,prepared:prepared.prepared,headers:{authorization:'Bearer synthetic-token-123456'},clock:()=>NOW});assert.equal(sent.ok,true);assert.equal(sent.request_fingerprint,prepared.request_fingerprint);assert.equal(sent.body_fingerprint,vertex.request_fingerprint);assert.equal(parseVertexProposalResponse(sent.body).valid,true);const replay=await sendPreparedGoogleApiRequest({transport:t,prepared:prepared.prepared,clock:()=>NOW});assert.equal(replay.ok,false);assert.match(replay.reason,/consumed/) })
test('same body on a different target path gets a different signed transport fingerprint',async()=>{const t=transport();const a=await prepareRestrictedGoogleApiRequest({transport:t,endpoint,body:vertex.bytes,region:'europe-west3',now:NOW});const b=await prepareRestrictedGoogleApiRequest({transport:transport(),endpoint:endpoint.replace(':generateContent',':countTokens'),body:vertex.bytes,region:'europe-west3',now:NOW});assert.equal(a.body_fingerprint,b.body_fingerprint);assert.notEqual(a.request_fingerprint,b.request_fingerprint);cancelPreparedGoogleApiRequest(a.prepared);cancelPreparedGoogleApiRequest(b.prepared)})
test('bound transport fails closed on DNS poison invalid TLS peer or non-http1 session',async()=>{for(const t of[transport({resolve4:async()=>['8.8.8.8']}),transport({tls_connect:tlsFactory({remote:'8.8.8.8'})}),transport({tls_connect:tlsFactory({authorised:false})}),transport({tls_connect:tlsFactory({alpn:'h2'})})])assert.equal((await prepareRestrictedGoogleApiRequest({transport:t,endpoint,body:vertex.bytes,region:'europe-west3',now:NOW})).ready,false)})
test('bound transport rejects socket substitution and redirects',async()=>{for(const cfg of[{https_request:httpsFactory({responseBody:vertexResponse,swapSocket:true})},{https_request:httpsFactory({responseBody:'',status:302})}]){const t=transport(cfg),prepared=await prepareRestrictedGoogleApiRequest({transport:t,endpoint,body:vertex.bytes,region:'europe-west3',now:NOW});assert.equal(prepared.ready,true);assert.equal((await sendPreparedGoogleApiRequest({transport:t,prepared:prepared.prepared,clock:()=>NOW})).ok,false)}})
test('prepared request can be cancelled without sending payload',async()=>{const t=transport(),prepared=await prepareRestrictedGoogleApiRequest({transport:t,endpoint,body:vertex.bytes,region:'europe-west3',now:NOW});assert.equal(cancelPreparedGoogleApiRequest(prepared.prepared),true);assert.equal((await sendPreparedGoogleApiRequest({transport:t,prepared:prepared.prepared,clock:()=>NOW})).ok,false)})
test('expired preparation and failed fresh authorization block before https request',async()=>{let calls=0;const t=transport({https_request:httpsFactory({responseBody:vertexResponse,onRequest:()=>calls++})});const expired=await prepareRestrictedGoogleApiRequest({transport:t,endpoint,body:vertex.bytes,region:'europe-west3',now:NOW});const r1=await sendPreparedGoogleApiRequest({transport:t,prepared:expired.prepared,clock:()=>new Date(NOW.getTime()+30_001)});assert.equal(r1.ok,false);assert.match(r1.reason,/expired/);assert.equal(calls,0);const denied=await prepareRestrictedGoogleApiRequest({transport:t,endpoint,body:vertex.bytes,region:'europe-west3',now:NOW});const r2=await sendPreparedGoogleApiRequest({transport:t,prepared:denied.prepared,clock:()=>NOW,before_send:()=>({allowed:false,reason:'kill switch active'})});assert.equal(r2.ok,false);assert.match(r2.reason,/kill switch/);assert.equal(calls,0)})
test('real node https.request uses only the prepared one-shot agent socket', async () => {
  let captured = Buffer.alloc(0)
  const server = net.createServer((socket) => {
    let incoming = Buffer.alloc(0)
    socket.on('data', (chunk) => {
      incoming = Buffer.concat([incoming, chunk])
      const headerEnd = incoming.indexOf('\r\n\r\n')
      if (headerEnd < 0) return
      const head = incoming.subarray(0, headerEnd).toString('utf8')
      const match = head.match(/content-length:\s*(\d+)/i)
      const length = match ? Number(match[1]) : 0
      if (incoming.length < headerEnd + 4 + length) return
      captured = incoming.subarray(headerEnd + 4, headerEnd + 4 + length)
      const body = Buffer.from(vertexResponse)
      socket.end(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`)
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port
  const tls_connect = () => {
    const socket = net.connect({ host: '127.0.0.1', port })
    socket.authorized = true
    socket.alpnProtocol = 'http/1.1'
    socket.getPeerCertificate = () => ({ raw: Buffer.from('real-node-agent-cert') })
    socket.once('connect', () => { Object.defineProperty(socket, 'remoteAddress', { value: '199.36.153.4', configurable: true }); socket.emit('secureConnect') })
    return socket
  }
  try {
    const t=createRestrictedGoogleApiTransportForTest({signer,resolve4:async()=>['199.36.153.4'],tls_connect,https_request:https.request,timeout_ms:2000})
    const prepared=await prepareRestrictedGoogleApiRequest({transport:t,endpoint,body:vertex.bytes,region:'europe-west3',now:NOW})
    assert.equal(prepared.ready,true)
    const sent=await sendPreparedGoogleApiRequest({transport:t,prepared:prepared.prepared,headers:{authorization:'Bearer synthetic-token-123456'},clock:()=>NOW})
    assert.equal(sent.ok,true)
    assert.deepEqual(captured,vertex.bytes)
  } finally { await new Promise((resolve) => server.close(resolve)) }
})
test('Vertex proposal adapter never emits tools and rejects tool/function-shaped output',()=>{assert.equal('tools'in vertex.provider_body,false);assert.deepEqual(vertex.proposal_request.security.tools,[]);assert.equal(parseVertexProposalResponse(Buffer.from(vertexResponse)).valid,true);const functionResponse=Buffer.from(JSON.stringify({candidates:[{content:{parts:[{functionCall:{name:'sendEmail'},text:'{}'}]}}]}));assert.equal(parseVertexProposalResponse(functionResponse).valid,false);const badProposal=Buffer.from(JSON.stringify({candidates:[{content:{parts:[{text:JSON.stringify({type:'summary',text:'x',recipient:'victim'})}]}}]}));assert.equal(parseVertexProposalResponse(badProposal).valid,false)})
