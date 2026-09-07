import { evaluateSecurityPosture } from './core/security-posture.mjs'

const projects = [
  ['GitLaw', 'mikelninh/gitlaw', 'legal agentic AI'],
  ['Digital Worker Factory', 'mikelninh/digital-worker-factory', 'cross-domain agent runtime'],
  ['CareOS', 'mikelninh/care-os', 'clinical context + bounded agents'],
  ['PrüfPilot', 'mikelninh/pruefpilot', 'document AI / administration'],
  ['MissionOps', 'mikelninh/missionops-plan', 'humanitarian programme operations'],
  ['SafeVoice', 'mikelninh/safevoice', 'evidence integrity / legal preparation'],
  ['FraudFlow', 'mikelninh/fraudflow-dkb', 'fraud operations / deterministic controls'],
  ['SignalLab', 'mikelninh/drv-signallab', 'data integrity / monitoring'],
]

const controlLabels = {
  authority_outside_model: 'Authority outside model', least_privilege: 'Least privilege', tenant_isolation: 'Tenant isolation',
  human_approval: 'Human approval', provenance: 'Provenance', protected_data: 'Protected data', bounded_execution: 'Bounded execution',
  auditability: 'Auditability', supply_chain: 'Supply chain', adversarial_evals: 'Adversarial evals', production_monitoring: 'Production monitoring',
}

function escapeHtml(value = '') {
  return String(value).replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char]))
}

function rawUrl(repo) { return `https://raw.githubusercontent.com/${repo}/main/security/security-posture.json` }
function replayUrl(repo) { return `https://raw.githubusercontent.com/${repo}/main/security/live-replay-report.json` }
function repoUrl(repo) { return `https://github.com/${repo}` }

async function loadProject([name, repo, domain]) {
  try {
    const response = await fetch(rawUrl(repo), { cache: 'no-store' })
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    const posture = await response.json()
    let liveReplay = null
    let liveReplayError = null
    if (posture.adversarial?.liveModel === true) {
      try {
        const replayResponse = await fetch(replayUrl(repo), { cache: 'no-store' })
        if (!replayResponse.ok) throw new Error(`HTTP ${replayResponse.status}`)
        const candidate = await replayResponse.json()
        if (candidate.version !== 'live-adversarial-replay/v1') throw new Error('unsupported replay evidence version')
        liveReplay = candidate
      } catch (error) {
        liveReplayError = error instanceof Error ? error.message : String(error)
      }
    }
    return { name, repo, domain, posture, evaluation: evaluateSecurityPosture(posture), liveReplay, liveReplayError, loaded: true }
  } catch (error) {
    return { name, repo, domain, loaded: false, error: error instanceof Error ? error.message : String(error) }
  }
}

function renderLiveReplay(item) {
  if (item.posture.adversarial?.liveModel !== true) return ''
  if (!item.liveReplay) {
    return `<section class="replay-proof replay-missing"><div class="eyebrow">LIVE-MODEL EVIDENCE DECLARED</div><strong>Replay artifact unavailable</strong><p>TrustReady could not load the detailed replay report (${escapeHtml(item.liveReplayError ?? 'unknown error')}). The posture remains visible, but the stronger executor-level claim is not rendered.</p></section>`
  }

  const report = item.liveReplay
  const summary = report.summary
  const killer = report.replays.find((replay) => replay.id === 'live-pdf-payment-override') ?? report.replays[0]
  const reasons = killer?.reasons?.map((reason) => `<code>${escapeHtml(reason)}</code>`).join(' ') ?? ''
  return `<section class="replay-proof">
    <div class="replay-head">
      <div><div class="eyebrow">COMPROMISED-MODEL REPLAY · EXECUTOR-LEVEL PROOF</div><h3>Unsafe model output. Zero real-world impact.</h3></div>
      <span class="impact-zero">IMPACT = 0</span>
    </div>
    <div class="replay-flow" aria-label="Malicious input to blocked executor flow">
      <span>malicious PDF / RAG / tool</span><b>→</b><span>live model proposes effect</span><b>→</b><span class="blocked">SECURITY BLOCK</span><b>→</b><span class="safe">executor calls 0</span>
    </div>
    <div class="replay-numbers">
      <div><b>${summary.passed}/${summary.cases}</b><span>live replays passed</span></div>
      <div><b>${summary.executorCalls}</b><span>executor calls</span></div>
      <div><b>${summary.impactEscapes}</b><span>impact escapes</span></div>
      <div><b>${summary.providerSignedReceipts}</b><span>provider-signed receipts</span></div>
    </div>
    ${killer ? `<details open class="killer-replay"><summary>Killer replay · malicious PDF payment override</summary><p>The captured model proposed <code>${escapeHtml(killer.proposedCapability)}</code>. The deterministic boundary returned <strong>${escapeHtml(killer.decision.toUpperCase())}</strong> before any executor ran.</p><div class="reason-chips">${reasons}</div></details>` : ''}
    <p class="replay-boundary">${escapeHtml(report.truthBoundary)}</p>
    <div class="links"><a href="${replayUrl(item.repo)}" target="_blank" rel="noreferrer">Raw replay evidence ↗</a></div>
  </section>`
}

function renderCard(item) {
  if (!item.loaded) {
    return `<article class="card missing"><div class="card-head"><div><div class="eyebrow">POSTURE NOT PUBLISHED</div><h2>${escapeHtml(item.name)}</h2><div class="domain">${escapeHtml(item.domain)}</div></div><span class="state PARTIAL">NOT PUBLISHED</span></div><p class="domain">TrustReady could not load <code>security/security-posture.json</code>. This counts as missing evidence, not as a security failure.</p><div class="links"><a href="${repoUrl(item.repo)}" target="_blank" rel="noreferrer">Repository ↗</a></div></article>`
  }

  const { posture, evaluation } = item
  const controls = posture.controls.map((control) => `<div class="control"><strong>${escapeHtml(controlLabels[control.id] ?? control.id)}</strong><span class="${control.status}">${escapeHtml(control.status.replace('_', ' '))}</span></div>`).join('')
  const residuals = posture.residualRisks.map((risk) => `<li>${escapeHtml(risk)}</li>`).join('')
  const reasons = evaluation.reasons.length ? `<details><summary>TrustReady flags (${evaluation.reasons.length})</summary><ul>${evaluation.reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join('')}</ul></details>` : ''

  return `<article class="card">
    <div class="card-head"><div><div class="eyebrow">${escapeHtml(posture.version)}</div><h2>${escapeHtml(item.name)}</h2><div class="domain">${escapeHtml(posture.project.domain)} · ${escapeHtml(item.repo)}</div></div><span class="state ${evaluation.state}">${escapeHtml(evaluation.state)}</span></div>
    <div class="numbers">
      <div><b>${evaluation.score}</b><span>evidence score</span></div>
      <div><b>${posture.adversarial.passed}/${posture.adversarial.cases}</b><span>adversarial</span></div>
      <div><b>${posture.adversarial.criticalEscapes}</b><span>critical escapes</span></div>
      <div><b>${posture.adversarial.liveModel ? 'YES' : 'NO'}</b><span>live-model evidence</span></div>
    </div>
    ${renderLiveReplay(item)}
    <div class="controls">${controls}</div>
    <details><summary>Residual risks (${posture.residualRisks.length})</summary><ul>${residuals}</ul></details>
    ${reasons}
    <div class="links"><a href="${repoUrl(item.repo)}" target="_blank" rel="noreferrer">Repository ↗</a><a href="${rawUrl(item.repo)}" target="_blank" rel="noreferrer">Raw posture ↗</a></div>
  </article>`
}

function renderSummary(items) {
  const loaded = items.filter((item) => item.loaded)
  const totalCases = loaded.reduce((sum, item) => sum + item.posture.adversarial.cases, 0)
  const totalEscapes = loaded.reduce((sum, item) => sum + item.posture.adversarial.criticalEscapes, 0)
  const liveCases = loaded.reduce((sum, item) => sum + (item.liveReplay?.summary?.liveModelCases ?? 0), 0)
  const evidenceReady = loaded.filter((item) => item.evaluation.state === 'EVIDENCE_READY').length
  return [
    [loaded.length, 'postures published'],
    [totalCases, 'adversarial cases'],
    [liveCases, 'captured live-model replays'],
    [totalEscapes, 'critical escapes'],
    [evidenceReady, 'evidence-ready'],
  ].map(([value, label]) => `<div class="metric"><b>${value}</b><span>${label}</span></div>`).join('')
}

async function main() {
  const items = await Promise.all(projects.map(loadProject))
  document.querySelector('#loading').remove()
  document.querySelector('#summary').innerHTML = renderSummary(items)
  document.querySelector('#projects').innerHTML = items.map(renderCard).join('')
}

main()
