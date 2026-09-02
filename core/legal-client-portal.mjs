import crypto from 'node:crypto'

const MAX_INVITE_TTL_MS = 30 * 60 * 1000
const MAX_SESSION_TTL_MS = 8 * 60 * 60 * 1000
const MAX_UPLOAD_CAP_TTL_MS = 10 * 60 * 1000
const MAX_UPLOAD_BYTES = 25 * 1024 * 1024

const CLIENT_OPS = new Set(['matter.read', 'requirements.read', 'upload.prepare', 'help.request'])
const INTAKE_OPS = new Set(['matter.read', 'requirements.read', 'document.review', 'matter.prepare_for_lawyer'])
const LAWYER_OPS = new Set([...INTAKE_OPS, 'matter.approve'])
const ALLOWED_MIME = new Set(['application/pdf', 'image/jpeg', 'image/png'])
const ALLOWED_SLOTS = new Set([
  'identity_document',
  'signed_power_of_attorney',
  'lease_contract',
  'cost_statement_missing_page',
  'supporting_document',
])

function requireString(value, name, max = 256) {
  if (typeof value !== 'string' || value.length < 1 || value.length > max) throw new Error(`${name}_INVALID`)
  return value
}

function requireEpoch(value, name) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${name}_INVALID`)
  return value
}

function b64url(bytes) {
  return Buffer.from(bytes).toString('base64url')
}

export function sha256Text(value) {
  return crypto.createHash('sha256').update(requireString(value, 'TOKEN', 4096), 'utf8').digest('hex')
}

function safeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || !/^[a-f0-9]{64}$/.test(a) || !/^[a-f0-9]{64}$/.test(b)) return false
  return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'))
}

export function createClientInvite({ tenant_id, matter_id, client_ref_hash, second_factor_target_hash, now_ms = Date.now(), ttl_ms = 15 * 60 * 1000 }) {
  requireString(tenant_id, 'TENANT_ID', 128)
  requireString(matter_id, 'MATTER_ID', 128)
  requireString(client_ref_hash, 'CLIENT_REF_HASH', 128)
  requireString(second_factor_target_hash, 'SECOND_FACTOR_TARGET_HASH', 128)
  requireEpoch(now_ms, 'NOW_MS')
  if (!Number.isSafeInteger(ttl_ms) || ttl_ms < 60_000 || ttl_ms > MAX_INVITE_TTL_MS) throw new Error('INVITE_TTL_INVALID')

  const token = b64url(crypto.randomBytes(32))
  const invite_id = `inv_${b64url(crypto.randomBytes(18))}`
  const record = Object.freeze({
    schema: 'trustready-client-invite-v1',
    invite_id,
    token_hash: sha256Text(token),
    tenant_id,
    matter_id,
    client_ref_hash,
    second_factor_target_hash,
    created_at_ms: now_ms,
    expires_at_ms: now_ms + ttl_ms,
    consumed_at_ms: null,
  })
  return { token, record }
}

export function verifyClientInvite({ record, token, now_ms = Date.now() }) {
  if (!record || record.schema !== 'trustready-client-invite-v1') return { ok: false, reason: 'INVITE_SCHEMA_INVALID' }
  requireEpoch(now_ms, 'NOW_MS')
  if (record.consumed_at_ms !== null) return { ok: false, reason: 'INVITE_ALREADY_USED' }
  if (now_ms > record.expires_at_ms) return { ok: false, reason: 'INVITE_EXPIRED' }
  const presented = sha256Text(token)
  if (!safeEqualHex(presented, record.token_hash)) return { ok: false, reason: 'INVITE_TOKEN_INVALID' }
  return { ok: true }
}

export function redeemClientInvite({ record, token, second_factor_verified, now_ms = Date.now(), session_ttl_ms = 60 * 60 * 1000 }) {
  const verified = verifyClientInvite({ record, token, now_ms })
  if (!verified.ok) throw new Error(verified.reason)
  if (second_factor_verified !== true) throw new Error('SECOND_FACTOR_REQUIRED')
  if (!Number.isSafeInteger(session_ttl_ms) || session_ttl_ms < 5 * 60 * 1000 || session_ttl_ms > MAX_SESSION_TTL_MS) throw new Error('SESSION_TTL_INVALID')

  const session_id = `ses_${b64url(crypto.randomBytes(24))}`
  const consumed_invite = Object.freeze({ ...record, consumed_at_ms: now_ms })
  const session = Object.freeze({
    schema: 'trustready-client-session-v1',
    session_id_hash: sha256Text(session_id),
    role: 'client',
    tenant_id: record.tenant_id,
    matter_id: record.matter_id,
    client_ref_hash: record.client_ref_hash,
    authenticated_at_ms: now_ms,
    expires_at_ms: now_ms + session_ttl_ms,
    revoked_at_ms: null,
  })
  return { session_id, session, consumed_invite }
}

export function authorizePortalOperation({ session, tenant_id, matter_id, operation, now_ms = Date.now() }) {
  if (!session || !['trustready-client-session-v1', 'trustready-staff-session-v1'].includes(session.schema)) return { allow: false, reason: 'SESSION_INVALID' }
  requireEpoch(now_ms, 'NOW_MS')
  if (session.revoked_at_ms !== null) return { allow: false, reason: 'SESSION_REVOKED' }
  if (now_ms > session.expires_at_ms) return { allow: false, reason: 'SESSION_EXPIRED' }
  if (tenant_id !== session.tenant_id) return { allow: false, reason: 'TENANT_MISMATCH' }
  if (matter_id !== session.matter_id && session.role === 'client') return { allow: false, reason: 'MATTER_MISMATCH' }

  const allowed = session.role === 'client' ? CLIENT_OPS : session.role === 'intake_staff' ? INTAKE_OPS : session.role === 'lawyer' ? LAWYER_OPS : new Set()
  if (!allowed.has(operation)) return { allow: false, reason: 'OPERATION_DENIED' }
  return { allow: true, reason: 'ALLOW' }
}

export function createStaffSession({ tenant_id, staff_ref_hash, role, matter_id = '*', now_ms = Date.now(), ttl_ms = 60 * 60 * 1000, mfa_verified = true }) {
  requireString(tenant_id, 'TENANT_ID', 128)
  requireString(staff_ref_hash, 'STAFF_REF_HASH', 128)
  if (!['intake_staff', 'lawyer'].includes(role)) throw new Error('STAFF_ROLE_INVALID')
  if (mfa_verified !== true) throw new Error('MFA_REQUIRED')
  requireEpoch(now_ms, 'NOW_MS')
  if (!Number.isSafeInteger(ttl_ms) || ttl_ms < 5 * 60 * 1000 || ttl_ms > MAX_SESSION_TTL_MS) throw new Error('SESSION_TTL_INVALID')
  const session_id = `ses_${b64url(crypto.randomBytes(24))}`
  return {
    session_id,
    session: Object.freeze({
      schema: 'trustready-staff-session-v1',
      session_id_hash: sha256Text(session_id),
      tenant_id,
      matter_id,
      staff_ref_hash,
      role,
      mfa_verified: true,
      authenticated_at_ms: now_ms,
      expires_at_ms: now_ms + ttl_ms,
      revoked_at_ms: null,
    }),
  }
}

function validateFilename(name) {
  requireString(name, 'FILENAME', 180)
  if (/[\\/\0]/.test(name) || name.includes('..')) throw new Error('FILENAME_UNSAFE')
  return name
}

export function createUploadCapability({ session, tenant_id, matter_id, document_slot, filename, mime_type, size_bytes, now_ms = Date.now(), ttl_ms = 5 * 60 * 1000 }) {
  const auth = authorizePortalOperation({ session, tenant_id, matter_id, operation: 'upload.prepare', now_ms })
  if (!auth.allow) throw new Error(auth.reason)
  if (!ALLOWED_SLOTS.has(document_slot)) throw new Error('DOCUMENT_SLOT_DENIED')
  validateFilename(filename)
  if (!ALLOWED_MIME.has(mime_type)) throw new Error('MIME_TYPE_DENIED')
  if (!Number.isSafeInteger(size_bytes) || size_bytes < 1 || size_bytes > MAX_UPLOAD_BYTES) throw new Error('UPLOAD_SIZE_DENIED')
  if (!Number.isSafeInteger(ttl_ms) || ttl_ms < 30_000 || ttl_ms > MAX_UPLOAD_CAP_TTL_MS) throw new Error('UPLOAD_CAP_TTL_INVALID')

  const capability = b64url(crypto.randomBytes(32))
  const object_id = `upl_${b64url(crypto.randomBytes(18))}`
  return {
    capability,
    record: Object.freeze({
      schema: 'trustready-upload-capability-v1',
      capability_hash: sha256Text(capability),
      object_id,
      tenant_id,
      matter_id,
      document_slot,
      filename,
      mime_type,
      size_bytes,
      storage_state: 'QUARANTINE_REQUIRED',
      created_at_ms: now_ms,
      expires_at_ms: now_ms + ttl_ms,
      consumed_at_ms: null,
    }),
  }
}

export function verifyUploadCapability({ record, capability, tenant_id, matter_id, document_slot, now_ms = Date.now() }) {
  if (!record || record.schema !== 'trustready-upload-capability-v1') return { ok: false, reason: 'UPLOAD_CAP_SCHEMA_INVALID' }
  if (record.consumed_at_ms !== null) return { ok: false, reason: 'UPLOAD_CAP_ALREADY_USED' }
  if (now_ms > record.expires_at_ms) return { ok: false, reason: 'UPLOAD_CAP_EXPIRED' }
  if (tenant_id !== record.tenant_id || matter_id !== record.matter_id || document_slot !== record.document_slot) return { ok: false, reason: 'UPLOAD_SCOPE_MISMATCH' }
  if (!safeEqualHex(sha256Text(capability), record.capability_hash)) return { ok: false, reason: 'UPLOAD_CAP_INVALID' }
  return { ok: true }
}

export function promoteQuarantinedUpload({ record, malware_status, content_sha256, observed_mime_type, observed_size_bytes, now_ms = Date.now() }) {
  if (!record || record.schema !== 'trustready-upload-capability-v1') throw new Error('UPLOAD_CAP_SCHEMA_INVALID')
  if (record.storage_state !== 'QUARANTINE_REQUIRED') throw new Error('UPLOAD_STATE_INVALID')
  if (malware_status !== 'CLEAN') throw new Error('MALWARE_SCAN_NOT_CLEAN')
  if (!/^[a-f0-9]{64}$/.test(content_sha256 || '')) throw new Error('CONTENT_HASH_INVALID')
  if (observed_mime_type !== record.mime_type) throw new Error('MIME_MISMATCH')
  if (observed_size_bytes !== record.size_bytes) throw new Error('SIZE_MISMATCH')
  requireEpoch(now_ms, 'NOW_MS')
  return Object.freeze({
    schema: 'trustready-client-document-v1',
    object_id: record.object_id,
    tenant_id: record.tenant_id,
    matter_id: record.matter_id,
    document_slot: record.document_slot,
    content_sha256,
    mime_type: observed_mime_type,
    size_bytes: observed_size_bytes,
    malware_status: 'CLEAN',
    storage_state: 'PROTECTED_MATTER_STORE',
    promoted_at_ms: now_ms,
  })
}

export function advanceMatterReview({ actor_session, tenant_id, matter_id, current_state, action, now_ms = Date.now() }) {
  const operation = action === 'prepare_for_lawyer' ? 'matter.prepare_for_lawyer' : action === 'lawyer_approve' ? 'matter.approve' : null
  if (!operation) throw new Error('REVIEW_ACTION_INVALID')
  const auth = authorizePortalOperation({ session: actor_session, tenant_id, matter_id, operation, now_ms })
  if (!auth.allow) throw new Error(auth.reason)
  if (action === 'prepare_for_lawyer' && current_state !== 'COMPLETE') throw new Error('MATTER_NOT_COMPLETE')
  if (action === 'lawyer_approve' && current_state !== 'READY_FOR_LAWYER') throw new Error('MATTER_NOT_READY_FOR_LAWYER')
  return action === 'prepare_for_lawyer' ? 'READY_FOR_LAWYER' : 'LAWYER_APPROVED_SHADOW_ONLY'
}

export const clientPortalLimits = Object.freeze({
  max_invite_ttl_ms: MAX_INVITE_TTL_MS,
  max_session_ttl_ms: MAX_SESSION_TTL_MS,
  max_upload_cap_ttl_ms: MAX_UPLOAD_CAP_TTL_MS,
  max_upload_bytes: MAX_UPLOAD_BYTES,
  allowed_mime_types: Object.freeze([...ALLOWED_MIME]),
  allowed_document_slots: Object.freeze([...ALLOWED_SLOTS]),
})