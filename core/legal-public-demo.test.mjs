import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'

const html = fs.readFileSync(new URL('../legal.html', import.meta.url), 'utf8')
const client = fs.readFileSync(new URL('../client-portal.html', import.meta.url), 'utf8')

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
  assert.match(html, /connect-src 'none'/)
})

test('public Legal demo cannot send from its interactive workflow', () => {
  assert.match(html, /Freigeben &amp; senden — erst nach Pilotfreigabe/i)
  assert.match(html, /Nichts wird in dieser Demo autonom versendet/i)
  assert.match(html, /keine E-Mail autonom versenden/i)
  assert.match(html, /keine beA-Nachricht autonom senden/i)
})

test('public Legal demo uses explicit workflow actions rather than ambiguous confirmation buttons', () => {
  assert.match(html, /Fehlende Unterlagen beim Mandanten anfordern/i)
  assert.match(html, /Quellen vergleichen/i)
  assert.match(html, /03\.09\. als korrekt übernehmen/i)
  assert.match(html, /Vorgang zur Freigabe an Bao vorlegen/i)
  assert.match(html, /Entwurf fachlich freigeben/i)
  assert.doesNotMatch(html, /<button[^>]*>\s*Korrekturbedarf bestätigen\s*<\/button>/i)
  assert.doesNotMatch(html, /<button[^>]*>\s*Prüfliste bestätigen\s*<\/button>/i)
})

test('public Legal demo makes evidence inspectable instead of self-certifying', () => {
  assert.match(html, /legal-pilot-metrics\.mjs/)
  assert.match(html, /issues\/17/)
  assert.match(html, /keine Zertifizierungsstelle/i)
})

test('client portal is Vietnamese-first with a German switch', () => {
  assert.match(client, /<html lang="vi">/)
  assert.match(client, /Cổng thông tin khách hàng/)
  assert.match(client, /Hồ sơ của bạn gần hoàn tất/)
  assert.match(client, /Còn thiếu chữ ký/)
  assert.match(client, /id="deBtn"/)
  assert.match(client, /Vietnamesisch zuerst/i)
})

test('client portal demo supports local-only file selection without reading or exfiltrating file contents', () => {
  assert.match(client, /type="file"/i)
  assert.match(client, /Dateien werden nicht übertragen/i)
  assert.match(client, /Dateiinhalt wird weder gelesen noch übertragen/i)
  assert.match(client, /connect-src 'none'/)
  assert.doesNotMatch(client, /\bfetch\s*\(/)
  assert.doesNotMatch(client, /XMLHttpRequest/)
  assert.doesNotMatch(client, /navigator\.sendBeacon/)
  assert.doesNotMatch(client, /new\s+WebSocket\s*\(/)
  assert.doesNotMatch(client, /<form\b/i)
  assert.doesNotMatch(client, /FileReader/)
  assert.doesNotMatch(client, /\.arrayBuffer\s*\(/)
  assert.doesNotMatch(client, /\.stream\s*\(/)
  assert.doesNotMatch(client, /URL\.createObjectURL/)
})