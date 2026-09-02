import test from 'node:test'
import assert from 'node:assert/strict'
import {
  createClientInvite,
  verifyClientInvite,
  redeemClientInvite,
  authorizePortalOperation,
  createStaffSession,
  createUploadCapability,
  verifyUploadCapability,
  promoteQuarantinedUpload,
  advanceMatterReview,
} from './legal-client-portal.mjs'

const base = {
  tenant_id: 'firm_bao_demo',
  matter_id: 'matter_demo_014',
  client_ref_hash: 'c'.repeat(64),
  second_factor_target_hash: 's'.repeat(64),
  now_ms: 1_800_000_000_000,
}

function clientSession() {
  const { token, record } = createClientInvite(base)
  return redeemClientInvite({ record, token, second_factor_verified: true, now_ms: base.now_ms + 1_000 }).session
}

test('invite token is opaque and stored only as hash', () => {
  const { token, record } = createClientInvite(base)
  assert.ok(token.length >= 40)
  assert.equal(record.token_hash.length, 64)
  assert.equal(JSON.stringify(record).includes(token), false)
  assert.equal(token.includes(base.matter_id), false)
})

test('invite is short lived, single use and requires second factor', () => {
  const { token, record } = createClientInvite({ ...base, ttl_ms: 60_000 })
  assert.equal(verifyClientInvite({ record, token, now_ms: base.now_ms + 59_000 }).ok, true)
  assert.equal(verifyClientInvite({ record, token, now_ms: base.now_ms + 61_000 }).reason, 'INVITE_EXPIRED')
  assert.throws(() => redeemClientInvite({ record, token, second_factor_verified: false, now_ms: base.now_ms + 10_000 }), /SECOND_FACTOR_REQUIRED/)
  const redeemed = redeemClientInvite({ record, token, second_factor_verified: true, now_ms: base.now_ms + 10_000 })
  assert.equal(verifyClientInvite({ record: redeemed.consumed_invite, token, now_ms: base.now_ms + 11_000 }).reason, 'INVITE_ALREADY_USED')
})

test('wrong invitation token fails closed', () => {
  const { record } = createClientInvite(base)
  assert.equal(verifyClientInvite({ record, token: 'x'.repeat(48), now_ms: base.now_ms + 1_000 }).reason, 'INVITE_TOKEN_INVALID')
})

test('client session is bound to exact tenant and matter', () => {
  const session = clientSession()
  assert.equal(authorizePortalOperation({ session, tenant_id: base.tenant_id, matter_id: base.matter_id, operation: 'matter.read', now_ms: base.now_ms + 2_000 }).allow, true)
  assert.equal(authorizePortalOperation({ session, tenant_id: 'other_firm', matter_id: base.matter_id, operation: 'matter.read', now_ms: base.now_ms + 2_000 }).reason, 'TENANT_MISMATCH')
  assert.equal(authorizePortalOperation({ session, tenant_id: base.tenant_id, matter_id: 'other_matter', operation: 'matter.read', now_ms: base.now_ms + 2_000 }).reason, 'MATTER_MISMATCH')
})

test('client cannot perform staff or lawyer operations', () => {
  const session = clientSession()
  assert.equal(authorizePortalOperation({ session, tenant_id: base.tenant_id, matter_id: base.matter_id, operation: 'matter.approve', now_ms: base.now_ms + 2_000 }).reason, 'OPERATION_DENIED')
  assert.equal(authorizePortalOperation({ session, tenant_id: base.tenant_id, matter_id: base.matter_id, operation: 'document.review', now_ms: base.now_ms + 2_000 }).reason, 'OPERATION_DENIED')
})

test('staff session requires MFA and lawyer role is distinct', () => {
  assert.throws(() => createStaffSession({ tenant_id: base.tenant_id, staff_ref_hash: 'a'.repeat(64), role: 'lawyer', mfa_verified: false, now_ms: base.now_ms }), /MFA_REQUIRED/)
  const intake = createStaffSession({ tenant_id: base.tenant_id, staff_ref_hash: 'a'.repeat(64), role: 'intake_staff', now_ms: base.now_ms }).session
  const lawyer = createStaffSession({ tenant_id: base.tenant_id, staff_ref_hash: 'b'.repeat(64), role: 'lawyer', now_ms: base.now_ms }).session
  assert.equal(authorizePortalOperation({ session: intake, tenant_id: base.tenant_id, matter_id: base.matter_id, operation: 'matter.approve', now_ms: base.now_ms + 1 }).allow, false)
  assert.equal(authorizePortalOperation({ session: lawyer, tenant_id: base.tenant_id, matter_id: base.matter_id, operation: 'matter.approve', now_ms: base.now_ms + 1 }).allow, true)
})

test('upload capability is scoped to one matter and one document slot', () => {
  const session = clientSession()
  const { capability, record } = createUploadCapability({ session, tenant_id: base.tenant_id, matter_id: base.matter_id, document_slot: 'signed_power_of_attorney', filename: 'vollmacht.pdf', mime_type: 'application/pdf', size_bytes: 1234, now_ms: base.now_ms + 2_000 })
  assert.equal(verifyUploadCapability({ record, capability, tenant_id: base.tenant_id, matter_id: base.matter_id, document_slot: 'signed_power_of_attorney', now_ms: base.now_ms + 3_000 }).ok, true)
  assert.equal(verifyUploadCapability({ record, capability, tenant_id: base.tenant_id, matter_id: 'other', document_slot: 'signed_power_of_attorney', now_ms: base.now_ms + 3_000 }).reason, 'UPLOAD_SCOPE_MISMATCH')
  assert.equal(verifyUploadCapability({ record, capability, tenant_id: base.tenant_id, matter_id: base.matter_id, document_slot: 'identity_document', now_ms: base.now_ms + 3_000 }).reason, 'UPLOAD_SCOPE_MISMATCH')
})

test('upload rejects unsafe filename, MIME and size', () => {
  const session = clientSession()
  const args = { session, tenant_id: base.tenant_id, matter_id: base.matter_id, document_slot: 'signed_power_of_attorney', now_ms: base.now_ms + 2_000 }
  assert.throws(() => createUploadCapability({ ...args, filename: '../secret.pdf', mime_type: 'application/pdf', size_bytes: 10 }), /FILENAME_UNSAFE/)
  assert.throws(() => createUploadCapability({ ...args, filename: 'payload.html', mime_type: 'text/html', size_bytes: 10 }), /MIME_TYPE_DENIED/)
  assert.throws(() => createUploadCapability({ ...args, filename: 'huge.pdf', mime_type: 'application/pdf', size_bytes: 26 * 1024 * 1024 }), /UPLOAD_SIZE_DENIED/)
})

test('upload capability expires', () => {
  const session = clientSession()
  const { capability, record } = createUploadCapability({ session, tenant_id: base.tenant_id, matter_id: base.matter_id, document_slot: 'supporting_document', filename: 'a.pdf', mime_type: 'application/pdf', size_bytes: 100, now_ms: base.now_ms + 2_000, ttl_ms: 30_000 })
  assert.equal(verifyUploadCapability({ record, capability, tenant_id: base.tenant_id, matter_id: base.matter_id, document_slot: 'supporting_document', now_ms: base.now_ms + 33_000 }).reason, 'UPLOAD_CAP_EXPIRED')
})

test('quarantined upload cannot be promoted before clean malware result', () => {
  const session = clientSession()
  const { record } = createUploadCapability({ session, tenant_id: base.tenant_id, matter_id: base.matter_id, document_slot: 'supporting_document', filename: 'a.pdf', mime_type: 'application/pdf', size_bytes: 100, now_ms: base.now_ms + 2_000 })
  assert.throws(() => promoteQuarantinedUpload({ record, malware_status: 'PENDING', content_sha256: 'a'.repeat(64), observed_mime_type: 'application/pdf', observed_size_bytes: 100, now_ms: base.now_ms + 4_000 }), /MALWARE_SCAN_NOT_CLEAN/)
  assert.throws(() => promoteQuarantinedUpload({ record, malware_status: 'INFECTED', content_sha256: 'a'.repeat(64), observed_mime_type: 'application/pdf', observed_size_bytes: 100, now_ms: base.now_ms + 4_000 }), /MALWARE_SCAN_NOT_CLEAN/)
})

test('promotion verifies observed MIME and size against upload intent', () => {
  const session = clientSession()
  const { record } = createUploadCapability({ session, tenant_id: base.tenant_id, matter_id: base.matter_id, document_slot: 'supporting_document', filename: 'a.pdf', mime_type: 'application/pdf', size_bytes: 100, now_ms: base.now_ms + 2_000 })
  assert.throws(() => promoteQuarantinedUpload({ record, malware_status: 'CLEAN', content_sha256: 'a'.repeat(64), observed_mime_type: 'image/png', observed_size_bytes: 100, now_ms: base.now_ms + 4_000 }), /MIME_MISMATCH/)
  assert.throws(() => promoteQuarantinedUpload({ record, malware_status: 'CLEAN', content_sha256: 'a'.repeat(64), observed_mime_type: 'application/pdf', observed_size_bytes: 101, now_ms: base.now_ms + 4_000 }), /SIZE_MISMATCH/)
})

test('clean scanned upload promotes to protected matter store with provenance hash', () => {
  const session = clientSession()
  const { record } = createUploadCapability({ session, tenant_id: base.tenant_id, matter_id: base.matter_id, document_slot: 'supporting_document', filename: 'a.pdf', mime_type: 'application/pdf', size_bytes: 100, now_ms: base.now_ms + 2_000 })
  const doc = promoteQuarantinedUpload({ record, malware_status: 'CLEAN', content_sha256: 'a'.repeat(64), observed_mime_type: 'application/pdf', observed_size_bytes: 100, now_ms: base.now_ms + 4_000 })
  assert.equal(doc.storage_state, 'PROTECTED_MATTER_STORE')
  assert.equal(doc.content_sha256, 'a'.repeat(64))
  assert.equal(doc.matter_id, base.matter_id)
})

test('intake team can prepare complete matter but cannot lawyer-approve it', () => {
  const intake = createStaffSession({ tenant_id: base.tenant_id, staff_ref_hash: 'a'.repeat(64), role: 'intake_staff', now_ms: base.now_ms }).session
  assert.equal(advanceMatterReview({ actor_session: intake, tenant_id: base.tenant_id, matter_id: base.matter_id, current_state: 'COMPLETE', action: 'prepare_for_lawyer', now_ms: base.now_ms + 1_000 }), 'READY_FOR_LAWYER')
  assert.throws(() => advanceMatterReview({ actor_session: intake, tenant_id: base.tenant_id, matter_id: base.matter_id, current_state: 'READY_FOR_LAWYER', action: 'lawyer_approve', now_ms: base.now_ms + 1_000 }), /OPERATION_DENIED/)
})

test('lawyer approval is shadow-only and cannot become send execution', () => {
  const lawyer = createStaffSession({ tenant_id: base.tenant_id, staff_ref_hash: 'b'.repeat(64), role: 'lawyer', now_ms: base.now_ms }).session
  const state = advanceMatterReview({ actor_session: lawyer, tenant_id: base.tenant_id, matter_id: base.matter_id, current_state: 'READY_FOR_LAWYER', action: 'lawyer_approve', now_ms: base.now_ms + 1_000 })
  assert.equal(state, 'LAWYER_APPROVED_SHADOW_ONLY')
})