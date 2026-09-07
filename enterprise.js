const reportUrl = 'https://raw.githubusercontent.com/mikelninh/digital-worker-factory/main/enterprise/demo-go-live-report.json'
const replayUrl = 'https://raw.githubusercontent.com/mikelninh/digital-worker-factory/main/security/live-replay-report.json'

const escapeHtml = (value = '') => String(value).replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char]))

async function fetchJson(url) {
  const response = await fetch(url, { cache: 'no-store' })
  if (!response.ok) throw new Error(`HTTP ${response.status}`)
  return response.json()
}

async function main() {
  const [report, replay] = await Promise.all([fetchJson(reportUrl), fetchJson(replayUrl)])
  const gate = report.decision
  document.querySelector('#decision').textContent = gate.decision
  document.querySelector('#metrics').innerHTML = [
    [gate.summary.blockers, 'release blockers'],
    [gate.summary.conditions, 'conditions'],
    [replay.summary.liveModelCases, 'live-model replays'],
    [replay.summary.impactEscapes, 'impact escapes'],
  ].map(([value, label]) => `<div class="metric"><b>${escapeHtml(value)}</b><span>${escapeHtml(label)}</span></div>`).join('')

  const killer = replay.replays.find((item) => item.id === 'live-pdf-payment-override') ?? replay.replays[0]
  document.querySelector('#proof').innerHTML = `<div class="eyebrow">COMPROMISED-MODEL PROOF</div>
    <h3>Malicious input → unsafe model proposal → security block → zero impact</h3>
    <p class="muted">A captured live model proposed <strong>${escapeHtml(killer.proposedCapability)}</strong> after malicious ${escapeHtml(killer.attackSurface)} content. The real runtime returned <strong>${escapeHtml(killer.decision.toUpperCase())}</strong>; executor calls: <strong>${escapeHtml(killer.executorCalls)}</strong>; impact escaped: <strong>${escapeHtml(killer.impactEscaped)}</strong>.</p>
    <p><a href="${replayUrl}" target="_blank" rel="noreferrer">Raw replay evidence ↗</a> · <a href="${reportUrl}" target="_blank" rel="noreferrer">Raw go-live report ↗</a></p>`
}

main().catch((error) => {
  document.querySelector('#decision').textContent = 'EVIDENCE ERROR'
  document.querySelector('#proof').innerHTML = `<h3>Evidence could not be loaded.</h3><p class="muted">${escapeHtml(error.message)}</p>`
})
