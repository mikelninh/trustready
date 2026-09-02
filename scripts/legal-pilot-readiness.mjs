import { spawnSync } from 'node:child_process'

function runAudit() {
  const result = spawnSync(process.execPath, ['scripts/legal-preaudit-v12.mjs'], {
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
  })
  const text = result.stdout || ''
  const start = text.lastIndexOf('\n{')
  const raw = (start >= 0 ? text.slice(start + 1) : text).trim()
  let report = null
  try { report = JSON.parse(raw) } catch {}
  return { ok: result.status === 0, report, stderr: result.stderr || '' }
}

export function evaluatePilotReadiness({ audit_report, env = process.env }) {
  const engineering = audit_report?.engineering?.status === 'PASS'
  const preAudit = audit_report?.verdict?.pre_audit_ready === true
  const realRequested = String(env.TRUSTREADY_REAL_MANDATE_DATA_ENABLED || 'false').toLowerCase() === 'true'
  const sendRequested = String(env.TRUSTREADY_HUMAN_APPROVED_SEND_ENABLED || 'false').toLowerCase() === 'true'
  const liveReady = audit_report?.verdict?.real_mandate_shadow_ready === true
  const independentlyAssured = audit_report?.verdict?.independently_assured === true

  const syntheticPilotReady = engineering && preAudit && !realRequested && !sendRequested
  const realMandatePilotReady = engineering && preAudit && realRequested && liveReady && independentlyAssured && !sendRequested
  const humanApprovedSendReady = realMandatePilotReady && sendRequested && audit_report?.verdict?.human_approved_send_ready === true

  const blockers = []
  if (!engineering) blockers.push('ENGINEERING_AUDIT_NOT_PASS')
  if (!preAudit) blockers.push('PRE_AUDIT_NOT_READY')
  if (realRequested && !liveReady) blockers.push('REAL_MANDATE_LIVE_EVIDENCE_MISSING')
  if (realRequested && !independentlyAssured) blockers.push('INDEPENDENT_ASSURANCE_MISSING')
  if (sendRequested && !audit_report?.verdict?.human_approved_send_ready) blockers.push('HUMAN_APPROVED_SEND_NOT_SEPARATELY_RELEASED')
  if (!realRequested && sendRequested) blockers.push('SEND_CANNOT_PRECEDE_REAL_MANDATE_APPROVAL')

  return {
    schema: 'trustready-bao-pilot-readiness-v1',
    synthetic_pilot_ready: syntheticPilotReady,
    real_mandate_pilot_ready: realMandatePilotReady,
    human_approved_send_ready: humanApprovedSendReady,
    requested: {
      real_mandate_data: realRequested,
      human_approved_send: sendRequested,
    },
    blockers,
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const audit = runAudit()
  if (!audit.report) {
    console.error(JSON.stringify({ schema: 'trustready-bao-pilot-readiness-v1', synthetic_pilot_ready: false, real_mandate_pilot_ready: false, blockers: ['AUDIT_REPORT_UNAVAILABLE'] }, null, 2))
    process.exit(1)
  }
  const result = evaluatePilotReadiness({ audit_report: audit.report })
  console.log(JSON.stringify(result, null, 2))
  process.exit(result.synthetic_pilot_ready || result.real_mandate_pilot_ready ? 0 : 1)
}