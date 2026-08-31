import { scanPublicGitHubInBrowser } from './browser-scan.mjs'

const $ = (sel) => document.querySelector(sel)
const $$ = (sel) => [...document.querySelectorAll(sel)]

const form = $('#scan-form')
const repoInput = $('#repo')
const loading = $('#loading')
const errorCard = $('#error')
const result = $('#result')
let currentData = null
let currentFilter = 'all'

function statusLabel(status) {
  return String(status || '').replaceAll('_', ' ')
}

function esc(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;')
}

function setBusy(busy) {
  loading.classList.toggle('hidden', !busy)
  $('#scan-button').disabled = busy
  $('#scan-button').textContent = busy ? 'Scanning…' : 'Scan repository'
}

function showError(message) {
  errorCard.textContent = message
  errorCard.classList.remove('hidden')
  result.classList.add('hidden')
}

function metric(value, label) {
  return `<div class="metric"><strong>${esc(value)}</strong><span>${esc(label)}</span></div>`
}

function renderMetrics(data) {
  const verified = data.controls.filter((c) => ['verified','attested'].includes(c.status)).length
  const unresolved = data.controls.length - verified
  $('#metrics').innerHTML = [
    metric(`${verified}/${data.controls.length}`, 'controls satisfied'),
    metric(`${Math.round(data.coverage_pct)}%`, 'evidence coverage'),
    metric(unresolved, 'controls unresolved'),
    metric(data.provenance_complete ? 'Complete' : 'Check', 'verified-evidence provenance'),
  ].join('')
}

function renderRoadmap(data) {
  $('#roadmap').innerHTML = data.path_to_100.map((phase, i) => {
    const noWork = phase.controls.length === 0
    return `<article class="roadmap-step">
      <div class="step-num">${i + 1}</div>
      <div class="step-range">${phase.from} → ${phase.to}</div>
      <div class="step-title">${esc(phase.title)}</div>
      <div class="step-desc">${esc(noWork ? 'Already complete for this scan.' : phase.description)}</div>
      <div class="step-gain">${noWork ? 'No unresolved controls' : `+${phase.gain} points · ${phase.controls.length} control${phase.controls.length === 1 ? '' : 's'}`}</div>
    </article>`
  }).join('')
}

function evidenceHtml(control) {
  if (!control.evidence?.length) return '<p class="small-muted">No accepted or candidate evidence linked to this result.</p>'
  return `<ul class="evidence-list">${control.evidence.slice(0, 5).map((e) => `<li>${esc(e.strength)} · <a href="${esc(e.source)}" target="_blank" rel="noreferrer">source</a> · valid until ${esc((e.valid_until || '').slice(0,10))}</li>`).join('')}</ul>`
}

function renderControls() {
  if (!currentData) return
  const controls = currentData.controls.filter((c) => {
    if (currentFilter === 'verified') return ['verified','attested'].includes(c.status)
    if (currentFilter === 'unresolved') return !['verified','attested','not_applicable'].includes(c.status)
    return true
  })

  $('#controls').innerHTML = controls.map((c) => {
    const resolved = ['verified','attested','not_applicable'].includes(c.status)
    return `<article class="control" data-status="${esc(c.status)}">
      <button class="control-toggle" type="button" aria-expanded="false">
        <div class="control-head">
          <div class="control-id">${esc(c.id)}${c.blocking ? ' · BLOCKING' : ''}</div>
          <div class="control-title">${esc(c.title)}</div>
          <div class="status ${esc(c.status)}">${esc(statusLabel(c.status))}</div>
          <div class="points">${resolved ? '+5' : '0'}/5</div>
        </div>
      </button>
      <div class="control-body hidden">
        <div>
          <span class="lane-chip">${esc(c.lane)}</span>
          <h4>Why this status</h4>
          <p>${esc(c.reason)}</p>
        </div>
        <div>
          <h4>Exact next proof</h4>
          <p>${esc(c.next_proof || 'No remediation required. Keep evidence current and monitor for regression.')}</p>
        </div>
        <div>
          <h4>Evidence inspected</h4>
          ${evidenceHtml(c)}
        </div>
        <div>
          <h4>Remediation lane</h4>
          <p>${esc(c.remediation_lane)}</p>
        </div>
      </div>
    </article>`
  }).join('')

  $$('.control-toggle').forEach((button) => {
    button.addEventListener('click', () => {
      const body = button.parentElement.querySelector('.control-body')
      const opening = body.classList.contains('hidden')
      body.classList.toggle('hidden')
      button.setAttribute('aria-expanded', String(opening))
    })
  })
}

function render(data) {
  currentData = data
  errorCard.classList.add('hidden')
  result.classList.remove('hidden')
  $('#subject-name').textContent = data.subject?.name || 'Repository'
  $('#subject-source').textContent = `${data.profile.title} · ${data.profile.version}`
  $('#revision').textContent = `Pinned revision ${data.source_revision}`
  $('#score').textContent = Math.round(data.score)
  $('#score-ring').style.setProperty('--score-angle', `${Math.max(0, Math.min(100, data.score)) * 3.6}deg`)
  $('#boundary').textContent = data.boundary
  renderMetrics(data)
  renderRoadmap(data)
  renderControls()
  result.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

async function runScan(repo) {
  setBusy(true)
  errorCard.classList.add('hidden')
  try {
    render(await scanPublicGitHubInBrowser(repo))
  } catch (error) {
    showError(error.message || 'Scan failed')
  } finally {
    setBusy(false)
  }
}

form.addEventListener('submit', (event) => {
  event.preventDefault()
  runScan(repoInput.value.trim())
})

$$('.filter').forEach((button) => {
  button.addEventListener('click', () => {
    currentFilter = button.dataset.filter
    $$('.filter').forEach((b) => b.classList.toggle('active', b === button))
    renderControls()
  })
})

$('#copy-plan').addEventListener('click', async () => {
  if (!currentData) return
  const lines = [`TrustReady remediation plan — ${currentData.subject.name}`, `Current score: ${currentData.score}/100`, '']
  currentData.path_to_100.forEach((phase, i) => {
    lines.push(`${i + 1}. ${phase.title}: ${phase.from} → ${phase.to}`)
    phase.controls.forEach((c) => lines.push(`- ${c.id}: ${c.title} — ${c.next_proof}`))
    lines.push('')
  })
  await navigator.clipboard.writeText(lines.join('\n'))
  const button = $('#copy-plan')
  const old = button.textContent
  button.textContent = 'Copied'
  setTimeout(() => { button.textContent = old }, 1200)
})

runScan(repoInput.value.trim())
