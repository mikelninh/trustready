import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'

const schema = fs.readFileSync(new URL('../infra/gcp-legal-shadow/pilot_schema.sql', import.meta.url), 'utf8')
const architecture = fs.readFileSync(new URL('../docs/CLIENT_PORTAL_SECURITY_ARCHITECTURE.md', import.meta.url), 'utf8')
const plan = fs.readFileSync(new URL('../docs/BAO_PRODUCTION_PILOT_PLAN.md', import.meta.url), 'utf8')
const env = fs.readFileSync(new URL('../.env.example', import.meta.url), 'utf8')

test('production data remains disabled by default', () => {
  assert.match(env, /TRUSTREADY_REAL_MANDATE_DATA_ENABLED=false/)
  assert.match(env, /TRUSTREADY_HUMAN_APPROVED_SEND_ENABLED=false/)
  assert.match(env, /TRUSTREADY_LEGAL_PILOT_MODE=synthetic/)
})

test('client portal architecture requires link plus second verification rather than bearer-link access', () => {
  assert.match(architecture, /Link\/QR is \*\*not authentication by itself\*\*/)
  assert.match(architecture, /second verification step/i)
  assert.match(architecture, /short-lived, single-use/i)
  assert.match(architecture, /tenant \+ client \+ matter/i)
})

test('production upload architecture requires quarantine malware scan and hash before promotion', () => {
  assert.match(architecture, /private quarantine/i)
  assert.match(architecture, /Malware scan/i)
  assert.match(architecture, /SHA-256/i)
  assert.match(architecture, /Only clean files are promoted/i)
})

test('pilot database schema carries firm and matter scope and enables RLS', () => {
  for (const table of ['matters','matter_access','requirements','documents','translations','audit_events']) {
    assert.match(schema, new RegExp(`alter table ${table} enable row level security`, 'i'))
  }
  assert.match(schema, /firm_id uuid not null/i)
  assert.match(schema, /matter_id uuid not null/i)
  assert.match(schema, /current_setting\('trustready\.tenant_id'/)
})

test('database records quarantine and clean promotion states without raw document bodies', () => {
  assert.match(schema, /storage_state text not null check \(storage_state in \('QUARANTINE','REJECTED','PROTECTED_MATTER_STORE','DELETED'\)\)/)
  assert.match(schema, /malware_status text not null check \(malware_status in \('PENDING','CLEAN','INFECTED','ERROR'\)\)/)
  assert.match(schema, /content_sha256 char\(64\)/)
  assert.doesNotMatch(schema, /document_body|raw_document|file_bytes|bytea/i)
})

test('translation is stored separately from authoritative source evidence', () => {
  assert.match(schema, /create table if not exists translations/i)
  assert.match(schema, /source_content_hash char\(64\)/)
  assert.match(schema, /requires_review boolean not null default true/)
  assert.match(architecture, /Never overwrite the Vietnamese source with the German translation/i)
})

test('Bao production plan keeps lawyer approval shadow-only until separate execution release', () => {
  assert.match(plan, /LAWYER_APPROVED_SHADOW_ONLY/)
  assert.match(plan, /human-approved execution/i)
  assert.match(plan, /separate release/i)
  assert.match(plan, /no autonomous outbound communication/i)
})