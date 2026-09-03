import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { GOLDEN_CASES, GOLDEN_CASE_STATES } from '../golden-cases.js'
import { allowedRehearsalActions, applyRehearsalAction, simulateGoldenCaseToDecision } from '../rehearsal-flow.js'

const html = fs.readFileSync(new URL('../bao-cockpit.html', import.meta.url), 'utf8')
const js = fs.readFileSync(new URL('../bao-cockpit.js', import.meta.url), 'utf8')

test('Golden Pilot rehearsal contains at least 12 fully synthetic realistic cases', () => {
  assert.ok(GOLDEN_CASES.length >= 12)
  const ids = new Set()
  for (const row of GOLDEN_CASES) {
    assert.match(row.id, /^TR-GOLD-\d{3}$/)
    assert.equal(ids.has(row.id), false)
    ids.add(row.id)
    assert.match(row.client_label, /synthetisch/i)
    assert.ok(row.vn_original.length >= 20)
    assert.ok(row.de_translation.length >= 20)
    assert.ok(row.summary.length >= 20)
    assert.ok(row.next_action.length >= 10)
    assert.ok(Array.isArray(row.timeline) && row.timeline.length >= 3)
    assert.ok(GOLDEN_CASE_STATES.includes(row.state))
    assert.ok(Number.isFinite(row.baseline_seconds) && row.baseline_seconds > 0)
    assert.ok(Number.isFinite(row.review_seconds) && row.review_seconds >= 0)
    assert.ok(row.baseline_seconds >= row.review_seconds)
  }
})

test('Golden cases cover Bao critical intake workflow classes', () => {
  const text = GOLDEN_CASES.map(row => `${row.title} ${row.summary} ${row.next_action}`).join('\n')
  assert.match(text, /Unterschrift/i)
  assert.match(text, /Seite 3/i)
  assert.match(text, /Datum/i)
  assert.match(text, /Frist/i)
  assert.match(text, /Namens/i)
  assert.match(text, /lesbar/i)
  assert.match(text, /falsche|falscher|Slot/i)
  assert.match(text, /Version/i)
  assert.match(text, /Eskalation|eskalieren/i)
  assert.match(text, /Freigabe/i)
})

test('every Golden Case can be simulated through a clear decision path without send', () => {
  for (const row of GOLDEN_CASES) {
    const result = simulateGoldenCaseToDecision(row.state)
    if (row.state === 'DONE') assert.equal(result.snapshot.state, 'DONE')
    else assert.equal(result.snapshot.state, 'DONE', `${row.id} must reach a lawyer decision`)
    assert.notEqual(result.snapshot.outcome, null, `${row.id} must record a decision outcome`)
    assert.equal(result.trace.includes('send'), false)
  }
})

test('incomplete cases cannot jump directly to Bao before request and review', () => {
  let snapshot = { state: 'INCOMPLETE', request_prepared: false, review_completed: false, outcome: null }
  assert.deepEqual(allowedRehearsalActions(snapshot), ['request_missing'])
  snapshot = applyRehearsalAction(snapshot, 'request_missing')
  assert.deepEqual(allowedRehearsalActions(snapshot), ['simulate_client_completion'])
  snapshot = applyRehearsalAction(snapshot, 'simulate_client_completion')
  assert.deepEqual(allowedRehearsalActions(snapshot), ['review_sources'])
  assert.throws(() => applyRehearsalAction(snapshot, 'submit_for_approval'), /denied/)
})

test('review must happen before submit to Bao and then Bao gets explicit choices', () => {
  let snapshot = { state: 'REVIEW', request_prepared: false, review_completed: false, outcome: null }
  assert.deepEqual(allowedRehearsalActions(snapshot), ['review_sources'])
  snapshot = applyRehearsalAction(snapshot, 'review_sources')
  assert.deepEqual(allowedRehearsalActions(snapshot), ['submit_for_approval', 'mark_correction_needed'])
  snapshot = applyRehearsalAction(snapshot, 'submit_for_approval')
  assert.deepEqual(allowedRehearsalActions(snapshot), ['lawyer_approve', 'mark_correction_needed', 'lawyer_reject'])
})

test('Bao cockpit stays synthetic and has no browser network egress primitive', () => {
  assert.match(html, /Synthetische Probe/i)
  assert.match(html, /kein Produktivbetrieb/i)
  assert.match(html, /connect-src 'none'/)
  assert.match(html + js, /Freigeben & senden — späterer Release/i)
  assert.doesNotMatch(html + js, /\bfetch\s*\(/)
  assert.doesNotMatch(html + js, /XMLHttpRequest/)
  assert.doesNotMatch(html + js, /navigator\.sendBeacon/)
  assert.doesNotMatch(html + js, /new\s+WebSocket\s*\(/)
  assert.doesNotMatch(html, /<form\b/i)
})

test('Bao cockpit reduces information density with collapsible queue and details', () => {
  assert.match(html, /id="queueToggle"/)
  assert.match(html, /Einklappen/)
  assert.match(js, /queueCollapsed/)
  assert.match(html, /Unterlagen, offene Punkte & Nachweise anzeigen/i)
  assert.match(html, /Pilot-Messung anzeigen/i)
})

test('Bao cockpit labels recommendation as a proposal and makes manual review outcome explicit', () => {
  assert.match(html, /TrustReady schlägt vor · Team entscheidet/i)
  assert.match(js, /Schreiben & Aktennotiz vergleichen/i)
  assert.match(js, /Pass & Vertrag vergleichen/i)
  assert.match(js, /Vertrag v1 & v2 vergleichen/i)
  assert.match(js, /Prüfung abgeschlossen → Bao vorlegen/i)
  assert.match(js, /Erst nach dieser Prüfung/i)
  assert.doesNotMatch(html + js, /Quellen manuell prüfen/i)
})

test('Bao rehearsal stores workflow feedback locally and exports a bounded iteration package', () => {
  assert.match(html, /Feedback für die nächste Iteration notieren/i)
  assert.match(html, /Keine echten Mandatsdaten eintragen/i)
  assert.match(js, /localStorage\.setItem\(NOTE_KEY/)
  assert.match(js, /trustready-bao-rehearsal-feedback-v1/)
  assert.match(js, /trustready-bao-feedback\.json/)
  assert.match(js, /Workflow\/Product feedback only\. No real mandate data\./)
})

test('Bao cockpit exposes bilingual evidence, explicit actions, timeline, metrics and meeting mode', () => {
  assert.match(html, /Heutige Vorgänge/i)
  assert.match(html, /Original · Vietnamesisch/i)
  assert.match(html, /Arbeitsübersetzung/i)
  assert.match(html, /Was ist passiert\?/i)
  assert.match(html, /modellierte Zeitersparnis/i)
  assert.match(html, /modellierte Rückfragen vermieden/i)
  assert.match(html, /autonome Aktionen/i)
  assert.match(html, /Bao Pilot starten/i)
  assert.match(js, /Fehlende Unterlagen \/ Angaben anfordern/i)
  assert.match(js, /Vorgang fachlich freigeben/i)
})

test('rehearsal KPI model cannot claim autonomous external execution', () => {
  assert.match(js, /metricActions'\)\.textContent = '0'/)
  assert.match(js, /Shadow Pilot endet hier/i)
  assert.match(js, /Im Rehearsal wird nichts versendet/i)
})
