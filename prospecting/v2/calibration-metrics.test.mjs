import assert from 'node:assert/strict'
import test from 'node:test'
import { calibrationMetrics } from './calibration-metrics.mjs'

test('computes proof-gap precision and review-queue recall separately', () => {
  const items = [
    {repository:'a', signal:{classification:'PROOF_GAP'}, humanLabel:'TRUE_SIGNAL'},
    {repository:'b', signal:{classification:'PROOF_GAP'}, humanLabel:'FALSE_POSITIVE'},
    {repository:'c', signal:{classification:'REVIEW_SIGNAL'}, humanLabel:'TRUE_SIGNAL'},
    {repository:'d', signal:{classification:'ARCHITECTURE_UNCERTAIN'}, humanLabel:'TRUE_SIGNAL'},
    {repository:'e', signal:{classification:'NO_ACTIONABLE_SIGNAL'}, humanLabel:'UNCERTAIN'},
  ]
  const m = calibrationMetrics(items)
  assert.equal(m.reviewed, 5)
  assert.equal(m.binaryReviewed, 4)
  assert.equal(m.proofGap.precision, 0.5)
  assert.equal(m.proofGap.recall, 1/3)
  assert.equal(m.reviewQueue.precision, 2/3)
  assert.equal(m.reviewQueue.recall, 2/3)
  assert.deepEqual(m.falseNegatives.map(x=>x.repository), ['d'])
})
