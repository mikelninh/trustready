const reportUrl = 'https://raw.githubusercontent.com/mikelninh/digital-worker-factory/main/enterprise/demo-go-live-report.json'
const replayUrl = 'https://raw.githubusercontent.com/mikelninh/digital-worker-factory/main/security/live-replay-report.json'
const autonomousUrl = 'https://raw.githubusercontent.com/mikelninh/digital-worker-factory/main/enterprise/autonomous-security-loop-report.json'

const escapeHtml = (value = '') => String(value).replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char]))

async function fetchJson(url) {
  const response = await fetch(url, { cache: 'no-store' })
  if (!response.ok) throw new Error(`HTTP ${response.status}`)
  return response.json()
}

function friendlyKind(kind) {
  return ({
    untrusted_instruction_effect: 'Malicious document → consequential action',
    cross_tenant_effect: 'Cross-tenant action attempt',
    protected_scope_exfiltration: 'Protected credential/scope read',
    sensitive_egress: 'Sensitive data → unapproved model',
  })[kind] ?? kind
}

function renderAutonomous(loop) {
  document.querySelector('#auto-decision').textContent = loop.release.decision
  document.querySelector('#auto-metrics').innerHTML = [
    [loop.attacks.generated, 'generated attacks'],
    [loop.before.impactEscapes, 'impact escapes before'],
    [loop.after.impactEscapes, 'impact escapes after'],
    [loop.after.executorCalls, 'executor calls after'],
  ].map(([value, label]) => `<div class="metric"><b>${escapeHtml(value)}</b><span>${escapeHtml(label)}</span></div>`).join('')

  const patchEntries = Object.entries(loop.remediation.patch ?? {})
  const patch = patchEntries.length
    ? patchEntries.map(([key, value]) => `<code>${escapeHtml(key)} = ${escapeHtml(value)}</code>`).join('')
    : '<code>No architecture change required.</code>'
  const cases = (loop.regressionCases ?? []).map((item) => `<div class="case"><b>${escapeHtml(friendlyKind(item.kind))}</b><span>${item.passed ? 'CONTAINED' : 'ESCAPED'} · executor calls ${escapeHtml(item.executorCalls)} · ${escapeHtml(item.status)}</span></div>`).join('')

  document.querySelector('#autofix').innerHTML = `
    <div class="eyebrow">AUTONOMOUS REMEDIATION PROOF</div>
    <h3>Exploit observed → architecture hardened → exact exploit replayed.</h3>
    <div class="before-after">
      <div class="stage before"><h4>Before automatic remediation</h4><div class="big bad">${escapeHtml(loop.before.impactEscapes)} escapes</div><p class="muted">${escapeHtml(loop.before.executorCalls)} unauthorized executor calls reached the simulated effect layer.</p></div>
      <div class="arrow">→</div>
      <div class="stage after"><h4>After automatic remediation</h4><div class="big good">${escapeHtml(loop.after.impactEscapes)} escapes</div><p class="muted">${escapeHtml(loop.after.executorCalls)} executor calls. ${escapeHtml(loop.after.contained)} generated attacks contained.</p></div>
    </div>
    <div class="patch"><strong>Patch derived automatically</strong>${patch}<p class="status-note">${escapeHtml((loop.remediation.reasons ?? []).join(' · '))}</p></div>
    <div class="cases">${cases}</div>
    <div class="source-links"><a href="${autonomousUrl}" target="_blank" rel="noreferrer">Raw autonomous-loop evidence ↗</a></div>`
}

function renderEnterprise(report, replay) {
  const gate = report.decision
  document.querySelector('#decision').textContent = gate.decision
  document.querySelector('#metrics').innerHTML = [
    [gate.summary.blockers, 'release blockers'],
    [gate.summary.conditions, 'conditions'],
    [replay.summary.liveModelCases, 'captured live-model replays'],
    [replay.summary.impactEscapes, 'live-model impact escapes'],
  ].map(([value, label]) => `<div class="metric"><b>${escapeHtml(value)}</b><span>${escapeHtml(label)}</span></div>`).join('')

  const killer = replay.replays.find((item) => item.id === 'live-pdf-payment-override') ?? replay.replays[0]
  document.querySelector('#proof').innerHTML = `<div class="eyebrow">COMPROMISED-MODEL PROOF</div>
    <h3>Malicious input → unsafe model proposal → security block → zero impact</h3>
    <p class="muted">A captured live model proposed <strong>${escapeHtml(killer.proposedCapability)}</strong> after malicious ${escapeHtml(killer.attackSurface)} content. The real runtime returned <strong>${escapeHtml(killer.decision.toUpperCase())}</strong>; executor calls: <strong>${escapeHtml(killer.executorCalls)}</strong>; impact escaped: <strong>${escapeHtml(killer.impactEscaped)}</strong>.</p>
    <p class="source-links"><a href="${replayUrl}" target="_blank" rel="noreferrer">Raw replay evidence ↗</a> · <a href="${reportUrl}" target="_blank" rel="noreferrer">Raw enterprise go-live report ↗</a></p>`
}

async function main() {
  const [report, replay, autonomous] = await Promise.all([
    fetchJson(reportUrl),
    fetchJson(replayUrl),
    fetchJson(autonomousUrl),
  ])
  renderAutonomous(autonomous)
  renderEnterprise(report, replay)
}

main().catch((error) => {
  document.querySelector('#auto-decision').textContent = 'EVIDENCE ERROR'
  document.querySelector('#decision').textContent = 'EVIDENCE ERROR'
  document.querySelector('#autofix').innerHTML = `<h3>Evidence could not be loaded.</h3><p class="muted">${escapeHtml(error.message)}</p>`
  document.querySelector('#proof').innerHTML = `<h3>Evidence could not be loaded.</h3><p class="muted">${escapeHtml(error.message)}</p>`
})
