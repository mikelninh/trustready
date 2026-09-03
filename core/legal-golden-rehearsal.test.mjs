import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { GOLDEN_CASES, GOLDEN_CASE_STATES } from '../golden-cases.js'

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

test('Bao cockpit stays synthetic and has no browser egress primitive', () => {
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

test('Bao cockpit exposes queue, bilingual evidence, explicit actions, timeline, metrics and meeting mode', () => {
  assert.match(html, /Heutige Vorgänge/i)
  assert.match(html, /Original Vietnamesisch/i)
  assert.match(html, /Arbeitsübersetzung/i)
  assert.match(html, /Was ist passiert\?/i)
  assert.match(html, /synthetisch modellierte Zeitersparnis/i)
  assert.match(html, /modellierte Rückfragen vermieden/i)
  assert.match(html, /autonome externe Aktionen/i)
  assert.match(html, /Bao Pilot starten/i)
  assert.match(js, /Fehlende Unterlagen \/ Angaben anfordern/i)
  assert.match(js, /Vorgang nach Prüfung zur Freigabe vorlegen/i)
  assert.match(js, /Vorgang fachlich freigeben/i)
})

test('rehearsal KPI model cannot claim autonomous external execution', () => {
  assert.match(js, /metricActions'\)\.textContent = '0'/)
  assert.match(js, /Rehearsal beendet hier — kein Versand/i)
  assert.match(js, /Im Rehearsal wird nichts versendet/i)
})
