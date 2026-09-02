import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import {
  appendEvidenceEvent, consumeApprovalCapability, evaluateEgress, issueApprovalCapability,
  signEvidenceCheckpoint, signEvidenceManifest, signProviderPassport, verifyApprovalCapability,
  verifyEvidenceChain, verifyEvidenceCheckpoint, verifyEvidenceManifest,
} from './legal-gateway.mjs'

const NOW = new Date('2026-09-02T12:00:00Z')
const reviewer = crypto.generateKeyPairSync('ed25519')
const approval = crypto.generateKeyPairSync('ed25519')
const evidence = crypto.generateKeyPairSync('ed25519')
const trustedPassportKeys = { 'legal-review-1': reviewer.publicKey }
const trustedApprovalKeys = { 'approval-1': approval.publicKey }
const trustedEvidenceKeys = { 'evidence-1': evidence.publicKey }

function passport(overrides = {}) {
  const body = {
    provider_id: 'eu-ai-1', status: 'approved', valid_until: '2026-12-31T00:00:00Z',
    training_on_customer_data: false, avv_status: 'approved', brao_43e_status: 'approved',
    subprocessor_status: 'approved', third_country: false,
    use_cases: {
      summarise_mail: {
        allowed_zones: ['MANDATE'], regions: ['eu-central'], max_retention_minutes: 0,
        allowed_fields: ['subject_hash', 'body_excerpt'], max_payload_bytes: 2048, allow_direct_identifiers: false,
      },
    }, ...overrides,
  }
  return signProviderPassport({ body, private_key: reviewer.privateKey, key_id: 'legal-review-1' })
}

function request(overrides = {}) {
  return {
    tenant_id: 'tenant-a', matter_id: 'matter-1', provider_id: 'eu-ai-1', zone: 'MANDATE',
    purpose: 'triage incoming correspondence', use_case: 'summarise_mail', region: 'eu-central', retention_minutes: 0,
    payload: { subject_hash: 'sha256:abc', body_excerpt: 'Pseudonymised short excerpt' }, policy_version: 'legal-v1', ...overrides,
  }
}

test('egress allows only signed approved provider policy and computes payload proof itself', () => {
  const result = evaluateEgress({ request: request(), passport: passport(), trusted_keys: trustedPassportKeys, now: NOW })
  assert.equal(result.allowed, true)
  assert.match(result.payload_fingerprint, /^sha256:[0-9a-f]{64}$/)
  assert.ok(result.payload_bytes > 0)
})

test('provider passport tampering fails closed', () => {
  const signed = passport()
  signed.body.provider_id = 'attacker-provider'
  assert.equal(evaluateEgress({ request: request({ provider_id: 'attacker-provider' }), passport: signed, trusted_keys: trustedPassportKeys, now: NOW }).code, 'PROVIDER_NOT_APPROVED')
})

test('mandate egress denies missing region, unknown fields, direct identifiers and oversized payloads', () => {
  assert.equal(evaluateEgress({ request: request({ region: undefined }), passport: passport(), trusted_keys: trustedPassportKeys, now: NOW }).code, 'REGION_REQUIRED')
  assert.equal(evaluateEgress({ request: request({ payload: { subject_hash: 'x', full_mailbox: 'no' } }), passport: passport(), trusted_keys: trustedPassportKeys, now: NOW }).code, 'FIELD_DENIED')
  const withName = passport({ use_cases: { summarise_mail: { allowed_zones: ['MANDATE'], regions: ['eu-central'], max_retention_minutes: 0, allowed_fields: ['client_name'], max_payload_bytes: 2048, allow_direct_identifiers: false } } })
  assert.equal(evaluateEgress({ request: request({ payload: { client_name: 'Alice' } }), passport: withName, trusted_keys: trustedPassportKeys, now: NOW }).code, 'DIRECT_IDENTIFIER_DENIED')
  assert.equal(evaluateEgress({ request: request({ payload: { subject_hash: 'x', body_excerpt: 'A'.repeat(3000) } }), passport: passport(), trusted_keys: trustedPassportKeys, now: NOW }).code, 'PAYLOAD_TOO_LARGE')
})

test('mandate egress denies legal/provider governance gaps', () => {
  const cases = [
    [{ training_on_customer_data: true }, 'PROVIDER_NOT_APPROVED'],
    [{ avv_status: 'missing' }, 'AVV_REQUIRED'],
    [{ brao_43e_status: 'missing' }, 'BRAO43E_REQUIRED'],
    [{ subprocessor_status: 'missing' }, 'SUBPROCESSOR_REQUIRED'],
    [{ third_country: true, transfer_safeguards_status: 'missing' }, 'TRANSFER_SAFEGUARDS_REQUIRED'],
  ]
  for (const [change, code] of cases) assert.equal(evaluateEgress({ request: request(), passport: passport(change), trusted_keys: trustedPassportKeys, now: NOW }).code, code)
})

test('approval requires MFA and is bound to actor session, matter, action and exact payload', () => {
  const payload = { recipient_id: 'party-1', subject_hash: 'a', body_hash: 'b' }
  assert.throws(() => issueApprovalCapability({ actor_id: 'bao', actor_session_id: 's1', tenant_id: 'tenant-a', matter_id: 'matter-1', action: 'send_email', payload, auth_context: { mfa: false }, expires_at: '2026-09-02T12:03:00Z', private_key: approval.privateKey, key_id: 'approval-1', now: NOW }), /MFA/)
  const cap = issueApprovalCapability({ actor_id: 'bao', actor_session_id: 's1', tenant_id: 'tenant-a', matter_id: 'matter-1', action: 'send_email', payload, auth_context: { mfa: true, method: 'webauthn' }, expires_at: '2026-09-02T12:03:00Z', private_key: approval.privateKey, key_id: 'approval-1', now: NOW })
  const expected = { actor_id: 'bao', actor_session_id: 's1', tenant_id: 'tenant-a', matter_id: 'matter-1', action: 'send_email', payload }
  assert.equal(verifyApprovalCapability({ capability: cap, expected, trusted_keys: trustedApprovalKeys, now: NOW }).valid, true)
  assert.equal(verifyApprovalCapability({ capability: cap, expected: { ...expected, payload: { ...payload, body_hash: 'changed' } }, trusted_keys: trustedApprovalKeys, now: NOW }).valid, false)
  assert.equal(verifyApprovalCapability({ capability: cap, expected: { ...expected, actor_session_id: 'other-session' }, trusted_keys: trustedApprovalKeys, now: NOW }).valid, false)
})

test('approval signature tamper, expiry and excessive lifetime fail closed', () => {
  const payload = { mutation: 'write-note', value_hash: 'v1' }
  const cap = issueApprovalCapability({ actor_id: 'bao', actor_session_id: 's1', tenant_id: 'tenant-a', matter_id: 'matter-1', action: 'case_write', payload, auth_context: { mfa: true }, expires_at: '2026-09-02T12:03:00Z', private_key: approval.privateKey, key_id: 'approval-1', now: NOW })
  const tampered = structuredClone(cap); tampered.body.action = 'delete_matter'
  assert.equal(verifyApprovalCapability({ capability: tampered, expected: { actor_id: 'bao', actor_session_id: 's1', tenant_id: 'tenant-a', matter_id: 'matter-1', action: 'delete_matter', payload }, trusted_keys: trustedApprovalKeys, now: NOW }).valid, false)
  assert.equal(verifyApprovalCapability({ capability: cap, expected: { actor_id: 'bao', actor_session_id: 's1', tenant_id: 'tenant-a', matter_id: 'matter-1', action: 'case_write', payload }, trusted_keys: trustedApprovalKeys, now: new Date('2026-09-02T12:04:00Z') }).valid, false)
  assert.throws(() => issueApprovalCapability({ actor_id: 'bao', actor_session_id: 's1', tenant_id: 'tenant-a', action: 'x', payload: {}, auth_context: { mfa: true }, expires_at: '2026-09-02T12:10:00Z', private_key: approval.privateKey, key_id: 'approval-1', now: NOW }), /5 minutes/)
})

test('approval consumption fails without durable replay protection and rejects replay atomically', async () => {
  const payload = { task_id: 't1', mutation: 'complete' }
  const cap = issueApprovalCapability({ actor_id: 'bao', actor_session_id: 's1', tenant_id: 'tenant-a', matter_id: 'matter-1', action: 'complete_task', payload, auth_context: { mfa: true }, expires_at: '2026-09-02T12:03:00Z', private_key: approval.privateKey, key_id: 'approval-1', now: NOW })
  const expected = { actor_id: 'bao', actor_session_id: 's1', tenant_id: 'tenant-a', matter_id: 'matter-1', action: 'complete_task', payload }
  assert.equal((await consumeApprovalCapability({ capability: cap, expected, trusted_keys: trustedApprovalKeys, now: NOW })).valid, false)
  const used = new Set()
  const consume_nonce = async ({ nonce }) => { if (used.has(nonce)) return false; used.add(nonce); return true }
  assert.equal((await consumeApprovalCapability({ capability: cap, expected, trusted_keys: trustedApprovalKeys, consume_nonce, now: NOW })).valid, true)
  assert.equal((await consumeApprovalCapability({ capability: cap, expected, trusted_keys: trustedApprovalKeys, consume_nonce, now: NOW })).valid, false)
})

test('evidence chain detects delete/reorder/mutation and signed checkpoint prevents silent chain rewrite', () => {
  const e1 = appendEvidenceEvent({ sequence: 1, event: { event_type: 'egress.denied', occurred_at: NOW.toISOString(), tenant_id: 'tenant-a', metadata: { code: 'ZONE_DENIED', provider_id: 'x' } } })
  const e2 = appendEvidenceEvent({ previous_hash: e1.event_hash, sequence: 2, event: { event_type: 'approval.consumed', occurred_at: '2026-09-02T12:01:00Z', tenant_id: 'tenant-a', actor_id: 'bao', metadata: { capability_id: 'cap-1' } } })
  assert.equal(verifyEvidenceChain([e1, e2]).valid, true)
  assert.equal(verifyEvidenceChain([e2, e1]).valid, false)
  assert.equal(verifyEvidenceChain([{ ...e1, actor_id: 'attacker' }, e2]).valid, false)
  const cp = signEvidenceCheckpoint({ tenant_id: 'tenant-a', head_hash: e2.event_hash, sequence: 2, generated_at: '2026-09-02T12:02:00Z', private_key: evidence.privateKey, key_id: 'evidence-1' })
  assert.equal(verifyEvidenceCheckpoint({ checkpoint: cp, trusted_keys: trustedEvidenceKeys }).valid, true)
  const changed = structuredClone(cp); changed.body.head_hash = e1.event_hash
  assert.equal(verifyEvidenceCheckpoint({ checkpoint: changed, trusted_keys: trustedEvidenceKeys }).valid, false)
})

test('evidence metadata rejects obvious raw content, credentials, email addresses and private keys', () => {
  const bad = [
    { prompt: 'ignore rules' }, { auth_token: 'abc' }, { note: 'person@example.com' },
    { safe: '-----BEGIN PRIVATE KEY-----x' },
  ]
  for (const metadata of bad) assert.throws(() => appendEvidenceEvent({ sequence: 1, event: { event_type: 'bad', occurred_at: NOW.toISOString(), tenant_id: 'tenant-a', metadata } }))
})

test('detached evidence manifest signature detects manifest mutation and requires artifact digests', () => {
  const manifest = { schema: 'trustready-legal-evidence-manifest-v1', tenant: 'tenant-a', artifacts: [{ path: 'controls.json', sha256: `sha256:${'a'.repeat(64)}` }] }
  const sig = signEvidenceManifest({ manifest, private_key: evidence.privateKey, key_id: 'evidence-1' })
  assert.equal(verifyEvidenceManifest({ manifest, signature: sig, trusted_keys: trustedEvidenceKeys }).valid, true)
  assert.equal(verifyEvidenceManifest({ manifest: { ...manifest, tenant: 'attacker' }, signature: sig, trusted_keys: trustedEvidenceKeys }).valid, false)
  const bad = { ...manifest, artifacts: [{ path: 'controls.json', sha256: 'nope' }] }
  const badSig = signEvidenceManifest({ manifest: bad, private_key: evidence.privateKey, key_id: 'evidence-1' })
  assert.equal(verifyEvidenceManifest({ manifest: bad, signature: badSig, trusted_keys: trustedEvidenceKeys }).valid, false)
})
