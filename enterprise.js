const reportUrl = 'https://raw.githubusercontent.com/mikelninh/digital-worker-factory/main/enterprise/demo-go-live-report.json'
const replayUrl = 'https://raw.githubusercontent.com/mikelninh/digital-worker-factory/main/security/live-replay-report.json'
const autonomousUrl = 'https://raw.githubusercontent.com/mikelninh/digital-worker-factory/main/enterprise/autonomous-security-loop-report.json'
const reachabilityUrl = 'https://raw.githubusercontent.com/mikelninh/digital-worker-factory/main/enterprise/safevoice-reachability-proof.json'
const safevoiceNativeUrl = 'https://raw.githubusercontent.com/mikelninh/safevoice/main/security/agent-boundary-report.json'

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

function renderReachability(proof, native) {
  document.querySelector('#reach-decision').textContent = proof.release.decision
  document.querySelector('#reach-metrics').innerHTML = [
    [proof.chain.reachableTools.length, 'reachable Court-Prep tools'],
    [proof.nativeRuntimeEvidence.adversarialCases, 'native adversarial cases'],
    [proof.nativeRuntimeEvidence.criticalEscapesAfterBoundary, 'critical escapes after'],
    [proof.chain.isolatedSurfaces.length, 'isolated MCP surfaces'],
  ].map(([value, label]) => `<div class="metric"><b>${escapeHtml(value)}</b><span>${escapeHtml(label)}</span></div>`).join('')

  const context = proof.chain.contextInputs.map((item) => `<code>${escapeHtml(item)}</code>`).join(' ')
  const tools = proof.chain.reachableTools.map((item) => `<span class="pill">${escapeHtml(item)}</span>`).join('')
  const effect = proof.chain.effectPaths[0]
  const nativeCases = (native.adversarial ?? []).map((item) => {
    const before = item.before?.networkCalls != null
      ? `network calls ${item.before.networkCalls}`
      : item.before?.rawHandlerAcceptedForeignCase
        ? 'foreign case reachable'
        : 'impact observed'
    const after = item.after?.networkCalls != null
      ? `network calls ${item.after.networkCalls}`
      : item.after?.handlerCalls != null
        ? `handler calls ${item.after.handlerCalls}`
        : 'impact blocked'
    return `<div class="case"><b>${escapeHtml(item.id)}</b><span>${escapeHtml(before)} → ${escapeHtml(after)}</span></div>`
  }).join('')

  document.querySelector('#reachability-proof').innerHTML = `
    <div class="eyebrow">REAL REPOSITORY · SAFEVOICE</div>
    <h3>Request authority → agent → shared loop → reachable tools → real effect sink.</h3>
    <p class="muted">TrustReady no longer joins every agent and MCP surface simply because they live in the same repository. It resolves the actual Court-Prep execution path and keeps the separate SafeVoice MCP server outside this security claim.</p>
    <div class="chain">
      <div><strong>Request authority</strong><span>${context}</span></div>
      <div>→</div>
      <div><strong>Agent entrypoint</strong><span>${escapeHtml(proof.chain.entrypoint)}</span></div>
      <div>→</div>
      <div><strong>Shared loop</strong><span>${escapeHtml(proof.chain.frameworks[0])}</span></div>
      <div>→</div>
      <div><strong>Effect path</strong><span>${escapeHtml(effect.tool)} → ${escapeHtml(effect.sink.path)} → ${escapeHtml(effect.sink.kind)}</span></div>
    </div>
    <div class="patch"><strong>Reachable tool surface</strong><div class="pills">${tools}</div><p class="status-note">Deterministic boundary: ${escapeHtml(proof.chain.deterministicBoundaries[0])} · isolated surface: ${escapeHtml(proof.chain.isolatedSurfaces[0])}</p></div>
    <div class="cases">${nativeCases}</div>
    <p class="status-note"><strong>Scoped release:</strong> ${escapeHtml(proof.release.decision)} · ${escapeHtml(proof.release.reason)}. The isolated MCP surface is explicitly excluded.</p>
    <div class="source-links"><a href="${reachabilityUrl}" target="_blank" rel="noreferrer">Raw CI-drift-checked reachability proof ↗</a> · <a href="${safevoiceNativeUrl}" target="_blank" rel="noreferrer">Raw SafeVoice exploit evidence ↗</a></div>`
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
  const [report, replay, autonomous, reachability, safevoiceNative] = await Promise.all([
    fetchJson(reportUrl),
    fetchJson(replayUrl),
    fetchJson(autonomousUrl),
    fetchJson(reachabilityUrl),
    fetchJson(safevoiceNativeUrl),
  ])
  renderAutonomous(autonomous)
  renderReachability(reachability, safevoiceNative)
  renderEnterprise(report, replay)
}

main().catch((error) => {
  document.querySelector('#auto-decision').textContent = 'EVIDENCE ERROR'
  document.querySelector('#reach-decision').textContent = 'EVIDENCE ERROR'
  document.querySelector('#decision').textContent = 'EVIDENCE ERROR'
  document.querySelector('#autofix').innerHTML = `<h3>Evidence could not be loaded.</h3><p class="muted">${escapeHtml(error.message)}</p>`
  document.querySelector('#reachability-proof').innerHTML = `<h3>Evidence could not be loaded.</h3><p class="muted">${escapeHtml(error.message)}</p>`
  document.querySelector('#proof').innerHTML = `<h3>Evidence could not be loaded.</h3><p class="muted">${escapeHtml(error.message)}</p>`
})
