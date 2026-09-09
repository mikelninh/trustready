export function calibrationMetrics(items) {
  const reviewed = items.filter((x) => ['TRUE_SIGNAL', 'FALSE_POSITIVE', 'UNCERTAIN'].includes(x.humanLabel))
  const binary = reviewed.filter((x) => ['TRUE_SIGNAL', 'FALSE_POSITIVE'].includes(x.humanLabel))
  const trueSignals = binary.filter((x) => x.humanLabel === 'TRUE_SIGNAL')

  const proofGapPredicted = binary.filter((x) => x.signal?.classification === 'PROOF_GAP')
  const proofGapTp = proofGapPredicted.filter((x) => x.humanLabel === 'TRUE_SIGNAL').length
  const proofGapFp = proofGapPredicted.filter((x) => x.humanLabel === 'FALSE_POSITIVE').length

  const reviewQueuePredicted = binary.filter((x) => ['PROOF_GAP', 'REVIEW_SIGNAL'].includes(x.signal?.classification))
  const reviewQueueTp = reviewQueuePredicted.filter((x) => x.humanLabel === 'TRUE_SIGNAL').length
  const reviewQueueFp = reviewQueuePredicted.filter((x) => x.humanLabel === 'FALSE_POSITIVE').length

  const proofGapCaught = trueSignals.filter((x) => x.signal?.classification === 'PROOF_GAP').length
  const reviewQueueCaught = trueSignals.filter((x) => ['PROOF_GAP', 'REVIEW_SIGNAL'].includes(x.signal?.classification)).length
  const falseNegatives = trueSignals.filter((x) => !['PROOF_GAP', 'REVIEW_SIGNAL'].includes(x.signal?.classification))

  return {
    reviewed: reviewed.length,
    binaryReviewed: binary.length,
    uncertainReviewed: reviewed.length - binary.length,
    trueSignals: trueSignals.length,
    falsePositiveLabels: binary.filter((x) => x.humanLabel === 'FALSE_POSITIVE').length,
    proofGap: {
      predicted: proofGapPredicted.length,
      truePositives: proofGapTp,
      falsePositives: proofGapFp,
      precision: proofGapTp + proofGapFp ? proofGapTp / (proofGapTp + proofGapFp) : null,
      recall: trueSignals.length ? proofGapCaught / trueSignals.length : null,
    },
    reviewQueue: {
      predicted: reviewQueuePredicted.length,
      truePositives: reviewQueueTp,
      falsePositives: reviewQueueFp,
      precision: reviewQueueTp + reviewQueueFp ? reviewQueueTp / (reviewQueueTp + reviewQueueFp) : null,
      recall: trueSignals.length ? reviewQueueCaught / trueSignals.length : null,
    },
    falseNegatives: falseNegatives.map((x) => ({
      repository: x.repository,
      classification: x.signal?.classification ?? null,
      humanNote: x.humanNote ?? null,
    })),
  }
}
