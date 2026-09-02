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
  assert.match(html, /<button disabled>Jetzt senden<\/button>/)
  assert.match(html, /keine autonomen externen Aktionen/i)
  assert.match(html, /keine E-Mail autonom versenden/i)
  assert.match(html, /keine beA-Nachricht autonom senden/i)
})

test('public Legal demo focuses on client intake, completeness and reduced back-and-forth', () => {
  assert.match(html, /Mandantenportal \+ Vollständigkeit/i)
  assert.match(html, /Vollmacht formal unvollständig/i)
  assert.match(html, /Seite 3 fehlt/i)
  assert.match(html, /Weniger Ping-Pong/i)
})

test('public Legal demo makes evidence inspectable instead of self-certifying', () => {
  assert.match(html, /actions\/runs\/33692345321/)
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

test('client portal demo cannot upload or exfiltrate real data', () => {
  assert.match(client, /không tải dữ liệu thật lên đây/i)
  assert.match(client, /connect-src 'none'/)
  assert.doesNotMatch(client, /\bfetch\s*\(/)
  assert.doesNotMatch(client, /XMLHttpRequest/)
  assert.doesNotMatch(client, /navigator\.sendBeacon/)
  assert.doesNotMatch(client, /new\s+WebSocket\s*\(/)
  assert.doesNotMatch(client, /<form\b/i)
  assert.doesNotMatch(client, /type=["']file["']/i)
  assert.match(client, /<button class="btn" disabled>/)
})
