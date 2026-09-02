import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'

const html = fs.readFileSync(new URL('../bao.html', import.meta.url), 'utf8')

test('Bao pilot is explicitly synthetic shadow mode rather than production readiness', () => {
  assert.match(html, /Shadow Pilot · synthetische Demo/i)
  assert.match(html, /Nur synthetische Beispieldaten/i)
  assert.match(html, /keine Aussage über eine produktiv eingesetzte Kanzleiumgebung/i)
})

test('Bao pilot keeps real send control physically disabled in the demo', () => {
  assert.match(html, /<button class="btn" disabled>Jetzt senden<\/button>/)
  assert.match(html, /nichts autonom versendet/i)
  assert.match(html, /keine autonomen Aktenänderungen/i)
})

test('Bao pilot contains no browser network egress primitive', () => {
  assert.doesNotMatch(html, /\bfetch\s*\(/)
  assert.doesNotMatch(html, /XMLHttpRequest/)
  assert.doesNotMatch(html, /navigator\.sendBeacon/)
  assert.doesNotMatch(html, /new\s+WebSocket\s*\(/)
})

test('Bao pilot exposes measurable utility and control success criteria', () => {
  assert.match(html, /≥20 echte Vorgänge/i)
  assert.match(html, /30<span[^>]*>\+<\/span><small> min \/ Tag<\/small>/is)
  assert.match(html, /0 nicht autorisierte externe Aktionen/i)
  assert.match(html, /Bao möchte es weiter benutzen/i)
})
