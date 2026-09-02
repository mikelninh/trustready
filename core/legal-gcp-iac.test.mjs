import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'

const main = fs.readFileSync(new URL('../infra/gcp-legal-shadow/main.tf', import.meta.url), 'utf8')
const vars = fs.readFileSync(new URL('../infra/gcp-legal-shadow/variables.tf', import.meta.url), 'utf8')
const outputs = fs.readFileSync(new URL('../infra/gcp-legal-shadow/outputs.tf', import.meta.url), 'utf8')
const readme = fs.readFileSync(new URL('../infra/gcp-legal-shadow/README.md', import.meta.url), 'utf8')

test('IaC encodes network-wide deny-all with only restricted Google API VIP allow', () => {
  assert.match(main, /destination_ranges\s*=\s*\["199\.36\.153\.4\/30"\]/)
  assert.match(main, /destination_ranges\s*=\s*\["0\.0\.0\.0\/0"\]/)
  assert.match(main, /deny\s*\{\s*protocol\s*=\s*"all"/s)
  assert.doesNotMatch(main, /target_tags\s*=/)
  assert.doesNotMatch(main, /target_service_accounts\s*=/)
  assert.match(main, /private_ip_google_access\s*=\s*true/)
  assert.match(main, /\*\.googleapis\.com\./)
  assert.match(main, /restricted\.googleapis\.com\./)
})

test('IaC provisions four purpose-separated asymmetric HSM keys using P-256 SHA-256', () => {
  for (const name of ['dlp-attestation', 'egress-enforcement', 'network-attestation', 'evidence-manifest']) assert.match(main, new RegExp(`"${name}"`))
  assert.match(main, /purpose\s*=\s*"ASYMMETRIC_SIGN"/)
  assert.match(main, /algorithm\s*=\s*"EC_SIGN_P256_SHA256"/)
  assert.match(main, /protection_level\s*=\s*"HSM"/)
  assert.match(main, /prevent_destroy\s*=\s*true/)
})

test('VPC Service Controls project identity is derived from project_id rather than caller-supplied number', () => {
  assert.match(main, /data\s+"google_project"\s+"current"/)
  assert.match(main, /resources\s*=\s*\["projects\/\$\{data\.google_project\.current\.number\}"\]/)
  assert.doesNotMatch(vars, /variable\s+"project_number"/)
  assert.match(outputs, /project_number\s*=\s*data\.google_project\.current\.number/)
  assert.match(outputs, /protected_resource\s*=\s*"projects\/\$\{data\.google_project\.current\.number\}"/)
})

test('VPC Service Controls restricts all services used by the mandate shadow path without escape-policy blocks', () => {
  for (const service of ['aiplatform.googleapis.com', 'cloudkms.googleapis.com', 'dlp.googleapis.com', 'storage.googleapis.com']) assert.match(main, new RegExp(service.replaceAll('.', '\\.')))
  assert.match(main, /enable_restriction\s*=\s*true/)
  assert.match(main, /allowed_services\s*=\s*\["RESTRICTED-SERVICES"\]/)
  assert.doesNotMatch(main, /egress_policies?\s*\{/)
  assert.doesNotMatch(main, /ingress_policies?\s*\{/)
})

test('evidence bucket safety defaults make irreversible lock an explicit second step', () => {
  assert.match(main, /uniform_bucket_level_access\s*=\s*true/)
  assert.match(main, /public_access_prevention\s*=\s*"enforced"/)
  assert.match(main, /force_destroy\s*=\s*false/)
  assert.match(main, /is_locked\s*=\s*var\.lock_evidence_bucket/)
  assert.match(vars, /variable "lock_evidence_bucket"[\s\S]*default\s*=\s*false/)
  assert.match(vars, /evidence_retention_seconds[\s\S]*>= 2592000/)
  assert.match(readme, /irreversible/i)
  assert.match(readme, /does \*\*not\*\* prove/i)
})
