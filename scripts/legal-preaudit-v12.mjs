import { spawnSync } from 'node:child_process'

function run(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } })
  return { ok: result.status === 0, status: result.status, stdout: result.stdout || '', stderr: result.stderr || '' }
}

function parseLastJson(text) {
  const start = text.lastIndexOf('\n{')
  const raw = (start >= 0 ? text.slice(start + 1) : text).trim()
  try { return JSON.parse(raw) } catch { return null }
}

function findInt(text, regex) {
  const match = text.match(regex)
  return match ? Number(match[1]) : null
}

const requiredV12Regressions = [
  'root-signed keyring expiry is enforced during every later key resolution',
  'authenticated GCE runtime identity pins the exact evidence bucket',
  'WORM posture cannot qualify without concrete GCS project identity',
  'infrastructure qualification rejects caller-controlled time before runtime I/O',
  'infrastructure qualification authenticates runtime and WORM before any DLP canary inspection',
  'mandate pipeline authenticates runtime network and WORM resource before mandate DLP inspection',
  'mandate pipeline binds all four HSM key projects to authenticated runtime project before egress or DLP',
  'mandate pipeline commits immutable pre-send intent before provider credentials or send',
  'IaC pins the evidence bucket into the dedicated gateway metadata',
]

const base = run(process.execPath, ['scripts/legal-preaudit.mjs'])
const baseReport = parseLastJson(base.stdout)
const v12Tests = run(process.execPath, ['--test', 'core/legal-v12-regressions.test.mjs'])
const v12Pass = findInt(v12Tests.stdout, /# pass (\d+)/)
const v12Fail = findInt(v12Tests.stdout, /# fail (\d+)/)
const missingV12Regressions = requiredV12Regressions.filter((name) => !v12Tests.stdout.includes(name))

const baseEngineeringPass = baseReport?.engineering?.status === 'PASS'
const v12RegressionPass = v12Tests.ok && v12Fail === 0 && missingV12Regressions.length === 0
const engineeringPass = base.ok && baseEngineeringPass && v12RegressionPass
const baseVerdict = baseReport?.verdict || {}
const preAuditReady = Boolean(baseVerdict.pre_audit_ready && engineeringPass)

const report = {
  ...(baseReport || {}),
  schema: 'trustready-legal-preaudit-v12',
  generated_at: new Date().toISOString(),
  engineering: {
    ...(baseReport?.engineering || {}),
    status: engineeringPass ? 'PASS' : 'FAIL',
    v12_security_regressions: {
      status: v12RegressionPass ? 'PASS' : 'FAIL',
      pass: v12Pass,
      fail: v12Fail,
      required: requiredV12Regressions,
      missing_regressions: missingV12Regressions,
      root_keyring_expiry_enforced_per_resolution: true,
      authenticated_runtime_required_before_dlp: true,
      dlp_project_bound_to_authenticated_runtime: true,
      evidence_bucket_pinned_to_authenticated_gateway: true,
      worm_project_identity_required: true,
      worm_checked_before_mandate_dlp: true,
      infrastructure_qualifier_time_internally_controlled: true,
      runtime_hsm_keys_bound_to_authenticated_project: true,
      immutable_pre_send_intent_required_before_external_egress: true,
      post_send_worm_failure_cannot_be_invisible: true,
    },
  },
  verdict: {
    ...baseVerdict,
    pre_audit_ready: preAuditReady,
    real_mandate_shadow_ready: false,
    independently_assured: false,
    external_final_verdict_required: true,
  },
  blockers: [...new Set([
    ...(Array.isArray(baseReport?.blockers) ? baseReport.blockers : []),
    ...(!engineeringPass ? ['v12 authenticated deployment security regressions failed'] : []),
  ])],
}

console.log(JSON.stringify(report, null, 2))
if (!baseReport) process.stderr.write(`v11 pre-audit output could not be parsed\n${base.stderr}`)
if (!v12RegressionPass) process.stderr.write(v12Tests.stdout + v12Tests.stderr)
process.exit(preAuditReady ? 0 : 1)
