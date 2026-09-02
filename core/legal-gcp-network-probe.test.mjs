import test from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import crypto from 'node:crypto'
import { canonicalize, createKeyTrustStore, verifyEnvelope } from './legal-key-identity.mjs'
import { createRestrictedGoogleApiProbe, evaluateRestrictedGoogleDns } from './legal-gcp-network-probe.mjs'

const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const keyId = 'projects/p/locations/europe-west3/keyRings/legal/cryptoKeys/network/cryptoKeyVersions/1'
const signer = {
  hardware_backed: true,
  async sign({ body }) {
    const bytes = Buffer.from(canonicalize(body))
    return { algorithm: 'ECDSA_P256_SHA256', key_id: keyId, value: crypto.sign('sha256', bytes, ec.privateKey).toString('base64') }
  },
}

function tlsFactory({ authorised = true, remote = '199.36.153.4', error = false } = {}) {
  return (_options, callback) => {
    const socket = new EventEmitter()
    socket.authorized = authorised
    socket.authorizationError = authorised ? null : 'CERT_REJECTED'
    socket.remoteAddress = remote
    socket.alpnProtocol = 'h2'
    socket.getPeerCertificate = () => ({ raw: Buffer.from('synthetic-cert') })
    socket.setTimeout = () => socket
    socket.destroy = () => {}
    queueMicrotask(() => error ? socket.emit('error', new Error('tls')) : callback())
    return socket
  }
}

test('DNS proof accepts only restricted.googleapis.com VIP addresses', () => {
  assert.equal(evaluateRestrictedGoogleDns({ endpoint: 'https://europe-west3-aiplatform.googleapis.com', addresses: ['199.36.153.4', '199.36.153.7'] }).ready, true)
  for (const addresses of [[], ['8.8.8.8'], ['199.36.153.4', '1.2.3.4'], ['::1']]) {
    assert.equal(evaluateRestrictedGoogleDns({ endpoint: 'https://europe-west3-aiplatform.googleapis.com', addresses }).ready, false)
  }
  assert.equal(evaluateRestrictedGoogleDns({ endpoint: 'https://evil.example', addresses: ['199.36.153.4'] }).ready, false)
})

test('runtime probe signs only after all restricted VIP TLS checks succeed', async () => {
  const probe = createRestrictedGoogleApiProbe({ signer, resolve4: async () => ['199.36.153.4'], tls_connect: tlsFactory() })
  const envelope = await probe({ endpoint: 'https://europe-west3-aiplatform.googleapis.com', hostname: 'europe-west3-aiplatform.googleapis.com', region: 'europe-west3', now: new Date('2026-09-02T12:00:00Z') })
  assert.equal(envelope.body.route_class, 'restricted-googleapis')
  assert.deepEqual(envelope.body.resolved_addresses, ['199.36.153.4'])
  const store = createKeyTrustStore([{ key_id: keyId, purpose: 'network_attestation', public_key: ec.publicKey }])
  assert.equal(verifyEnvelope({ envelope, key_store: store, purpose: 'network_attestation', now: new Date('2026-09-02T12:00:00Z') }).valid, true)
})

test('runtime probe returns no attestation on DNS poisoning, invalid certificate, wrong peer or TLS error', async () => {
  const cases = [
    { resolve4: async () => ['8.8.8.8'], tls_connect: tlsFactory() },
    { resolve4: async () => ['199.36.153.4'], tls_connect: tlsFactory({ authorised: false }) },
    { resolve4: async () => ['199.36.153.4'], tls_connect: tlsFactory({ remote: '1.2.3.4' }) },
    { resolve4: async () => ['199.36.153.4'], tls_connect: tlsFactory({ error: true }) },
  ]
  for (const config of cases) {
    const probe = createRestrictedGoogleApiProbe({ signer, ...config })
    assert.equal(await probe({ endpoint: 'https://europe-west3-aiplatform.googleapis.com', hostname: 'europe-west3-aiplatform.googleapis.com', region: 'europe-west3' }), null)
  }
})
