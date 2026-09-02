import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'

const html = fs.readFileSync(new URL('../legal.html', import.meta.url), 'utf8')

test('public Legal demo is explicitly synthetic and not production readiness', () => {
  assert.match(html, /Öffentliche synthetische Demo/i)
  assert.match(html, /keine echten Mandatsdaten/i)
  assert.match(html, /kein Produktivbetrieb/i)
  assert.match(html, /Noch real zu beweisen/i)
})

test('public Legal demo contains no browser network egress primitive', () => {
  assert.doesNotMatch(html, /\bfetch\s*\(/)
  assert.doesNotMatch(html, /XMLHttpRequest/)
  assert.doesNotMatch(html, /navigator\.sendBeacon/)
  assert.doesNotMatch(html, /new\s+WebSocket\s*\(/)
  assert.doesNotMatch(html, /<form\b/i)
})

test('public Legal demo cannot send from its interactive workflow', () => {
  assert.match(html, /<button disabled>Jetzt senden<\/button>/)
  assert.match(html, /Nichts wird in dieser Demo autonom versendet/i)
  assert.match(html, /keine E-Mail autonom versenden/i)
  assert.match(html, /keine beA-Nachricht autonom senden/i)
})

test('public Legal demo makes evidence inspectable instead of self-certifying', () => {
  assert.match(html, /actions\/runs\/33690913923/)
  assert.match(html, /legal-pilot-metrics\.mjs/)
  assert.match(html, /issues\/17/)
  assert.match(html, /keine Zertifizierungsstelle/i)
})
