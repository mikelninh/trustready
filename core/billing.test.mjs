import test from 'node:test'
import assert from 'node:assert/strict'
import { createEntitlementToken, verifyEntitlementToken } from './billing.mjs'

const secret = 'test-secret-123'

test('signed entitlement token verifies and carries plan', () => {
  const token = createEntitlementToken({ customer_id:'cus_123', subscription_id:'sub_123', plan:'developer', email:'dev@example.com', expires_at:'2026-09-01T00:00:00Z' }, secret)
  const result = verifyEntitlementToken(token, secret, new Date('2026-08-31T18:00:00Z'))
  assert.equal(result.valid, true)
  assert.equal(result.payload.plan, 'developer')
  assert.equal(result.plan.api_units, 500)
})

test('tampering fails closed', () => {
  const token = createEntitlementToken({ customer_id:'cus_123', subscription_id:'sub_123', plan:'developer', expires_at:'2026-09-01T00:00:00Z' }, secret)
  const tampered = token.replace('tr_live_', 'tr_live_x')
  assert.equal(verifyEntitlementToken(tampered, secret, new Date('2026-08-31T18:00:00Z')).valid, false)
})

test('expired entitlement fails closed', () => {
  const token = createEntitlementToken({ customer_id:'cus_123', subscription_id:'sub_123', plan:'team', expires_at:'2026-08-31T17:00:00Z' }, secret)
  const result = verifyEntitlementToken(token, secret, new Date('2026-08-31T18:00:00Z'))
  assert.equal(result.valid, false)
  assert.equal(result.reason, 'Token expired')
})
