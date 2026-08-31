#!/usr/bin/env node

import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { scanRepositorySnapshot } from '../core/scanner.mjs'
import { SCANNER_GOLDEN_CASES } from './scanner-golden.mjs'

function round(value) {
  return Math.round(value * 10000) / 10000
}

function statusFor(scan, controlId) {
  return scan.evaluation.results.find((item) => item.control_id === controlId)?.status || 'not_observed'
}

export function runScannerBenchmark(cases, profile) {
  const rows = []
  for (const testCase of cases) {
    const scan = scanRepositorySnapshot(testCase.snapshot, profile)
    const actualStatus = statusFor(scan, testCase.control_id)
    const expectedVerified = testCase.expected_status === 'verified'
    const actualVerified = ['verified', 'attested'].includes(actualStatus)
    const detected = actualStatus !== 'not_observed'
    rows.push({
      id: testCase.id,
      control_id: testCase.control_id,
      expected_status: testCase.expected_status,
      actual_status: actualStatus,
      expected_verified: expectedVerified,
      actual_verified: actualVerified,
      detected,
      false_verified: actualVerified && !expectedVerified,
      missed_verified: expectedVerified && !actualVerified,
      exact_match: actualStatus === testCase.expected_status,
      provenance_complete: scan.provenance_complete,
      note: testCase.note,
    })
  }

  const verifiedPositives = rows.filter((row) => row.expected_verified)
  const verifiedNegatives = rows.filter((row) => !row.expected_verified)
  const truePositives = rows.filter((row) => row.expected_verified && row.actual_verified).length
  const falsePositives = rows.filter((row) => !row.expected_verified && row.actual_verified).length
  const falseNegatives = rows.filter((row) => row.expected_verified && !row.actual_verified).length
  const precision = truePositives + falsePositives === 0 ? 1 : truePositives / (truePositives + falsePositives)
  const recall = verifiedPositives.length === 0 ? 1 : truePositives / verifiedPositives.length
  const falseVerifiedRate = verifiedNegatives.length === 0 ? 0 : falsePositives / verifiedNegatives.length
  const exactAccuracy = rows.filter((row) => row.exact_match).length / rows.length

  const controls = [...new Set(rows.map((row) => row.control_id))].sort()
  const perControl = Object.fromEntries(controls.map((controlId) => {
    const subset = rows.filter((row) => row.control_id === controlId)
    const positives = subset.filter((row) => row.expected_verified)
    const negatives = subset.filter((row) => !row.expected_verified)
    const tp = subset.filter((row) => row.expected_verified && row.actual_verified).length
    const fp = subset.filter((row) => !row.expected_verified && row.actual_verified).length
    const fn = subset.filter((row) => row.expected_verified && !row.actual_verified).length
    return [controlId, {
      cases: subset.length,
      precision: round(tp + fp === 0 ? 1 : tp / (tp + fp)),
      recall: round(positives.length === 0 ? 1 : tp / positives.length),
      false_verified_rate: round(negatives.length === 0 ? 0 : fp / negatives.length),
      exact_accuracy: round(subset.filter((row) => row.exact_match).length / subset.length),
      false_positives: fp,
      false_negatives: fn,
    }]
  }))

  return {
    schema: 'trustready-scanner-benchmark-v1',
    cases: rows.length,
    verified_positive_cases: verifiedPositives.length,
    verified_negative_cases: verifiedNegatives.length,
    metrics: {
      verified_precision: round(precision),
      verified_recall: round(recall),
      false_verified_rate: round(falseVerifiedRate),
      exact_status_accuracy: round(exactAccuracy),
      provenance_complete_rate: round(rows.filter((row) => row.provenance_complete).length / rows.length),
      false_positives: falsePositives,
      false_negatives: falseNegatives,
    },
    per_control: perControl,
    failures: rows.filter((row) => row.false_verified || row.missed_verified || !row.exact_match || !row.provenance_complete),
    release_gate: {
      false_verified_zero: falsePositives === 0,
      verified_recall_complete: falseNegatives === 0,
      exact_status_complete: rows.every((row) => row.exact_match),
      provenance_complete: rows.every((row) => row.provenance_complete),
    },
    rows,
  }
}

async function main() {
  const profile = JSON.parse(await readFile(new URL('../profiles/core-ai-procurement-2026.08.json', import.meta.url), 'utf8'))
  const report = runScannerBenchmark(SCANNER_GOLDEN_CASES, profile)
  console.log(JSON.stringify(report, null, 2))
  const pass = Object.values(report.release_gate).every(Boolean)
  process.exit(pass ? 0 : 1)
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  await main()
}
