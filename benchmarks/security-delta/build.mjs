import { mkdir, readFile, writeFile, copyFile } from 'node:fs/promises'
import path from 'node:path'

function argsOf(argv) {
  const out = {}
  for (let i = 0; i < argv.length; i += 2) out[argv[i]?.replace(/^--/, '')] = argv[i + 1]
  return out
}

const args = argsOf(process.argv.slice(2))
const targetRoot = args.root ?? '_targets'
const metadataPath = args.metadata ?? path.join(targetRoot, 'metadata.json')
const outputDir = args.out ?? 'security-delta-dist'
const specPath = new URL('./targets.json', import.meta.url)

const spec = JSON.parse(await readFile(specPath, 'utf8'))
const metadata = JSON.parse(await readFile(metadataPath, 'utf8'))

function pct(value) {
  return `${Math.round(value * 100)}%`
}

function assertTarget(target, report) {
  const problems = []
  if (report.version !== 'security-delta-target-proof/v1') problems.push('wrong_schema')
  if (report.repository !== target.repository) problems.push('wrong_repository')
  if (!Number.isInteger(report.summary?.attackCases) || report.summary.attackCases < 2) problems.push('insufficient_attack_cases')
  if (report.summary?.before?.impactEscapes !== report.summary?.attackCases) problems.push('baseline_not_exposed_to_every_attack')
  if (report.summary?.after?.impactEscapes !== 0) problems.push('post_boundary_impact_escape')
  if (report.summary?.delta?.relativeImpactReduction !== 1) problems.push('impact_reduction_not_complete_for_named_cases')
  if (!Number.isInteger(report.summary?.benign?.cases) || report.summary.benign.cases < 1) problems.push('benign_controls_missing')
  if (report.summary?.benign?.retentionRate !== 1) problems.push('benign_retention_regression')
  if (report.summary?.holdout?.total > 0 && report.summary.holdout.contained !== report.summary.holdout.total) problems.push('holdout_escape')
  if (typeof report.mutation?.historicalVulnerabilityClaimed !== 'boolean') problems.push('historical_claim_flag_missing')
  if (target.id === 'safevoice' && report.mutation?.historicalVulnerabilityClaimed !== true) problems.push('safevoice_native_replay_truth_boundary_regression')
  if (target.id !== 'safevoice' && report.mutation?.historicalVulnerabilityClaimed !== false) problems.push('controlled_mutant_mislabeled_as_historical')
  return problems
}

const results = []
for (const target of spec.targets) {
  const evidenceFile = path.join(targetRoot, target.id, target.evidencePath)
  const report = JSON.parse(await readFile(evidenceFile, 'utf8'))
  const problems = assertTarget(target, report)
  results.push({
    id: target.id,
    repository: target.repository,
    architecture: target.architecture,
    proofType: target.proofType,
    commit: metadata.targets?.[target.id]?.commit,
    evidencePath: target.evidencePath,
    report,
    assertions: problems.length === 0 ? ['PASS'] : problems,
    pass: problems.length === 0,
  })
}

const totals = results.reduce((acc, item) => {
  const s = item.report.summary
  acc.attackCases += s.attackCases
  acc.beforeEscapes += s.before.impactEscapes
  acc.afterEscapes += s.after.impactEscapes
  acc.effectCallsBefore += s.before.effectCalls ?? 0
  acc.effectCallsAfter += s.after.effectCalls ?? 0
  acc.holdoutCases += s.holdout.total ?? 0
  acc.holdoutContained += s.holdout.contained ?? 0
  acc.benignCases += s.benign.cases ?? 0
  acc.benignRetained += s.benign.retained ?? 0
  acc.nativeReplayTargets += item.report.mutation.historicalVulnerabilityClaimed ? 1 : 0
  acc.controlledMutationTargets += item.report.mutation.historicalVulnerabilityClaimed ? 0 : 1
  return acc
}, {
  attackCases: 0,
  beforeEscapes: 0,
  afterEscapes: 0,
  effectCallsBefore: 0,
  effectCallsAfter: 0,
  holdoutCases: 0,
  holdoutContained: 0,
  benignCases: 0,
  benignRetained: 0,
  nativeReplayTargets: 0,
  controlledMutationTargets: 0,
})

const globalProblems = []
if (results.length !== 4) globalProblems.push('expected_four_real_repositories')
if (new Set(results.map((item) => item.architecture)).size !== 4) globalProblems.push('architecture_diversity_regression')
if (results.some((item) => !item.pass)) globalProblems.push('target_assertion_failed')
if (totals.attackCases < 14) globalProblems.push('attack_coverage_below_v1_floor')
if (totals.beforeEscapes !== totals.attackCases) globalProblems.push('not_all_controlled_baselines_exposed')
if (totals.afterEscapes !== 0) globalProblems.push('post_boundary_impact_escape_present')
if (totals.holdoutCases < 6 || totals.holdoutContained !== totals.holdoutCases) globalProblems.push('holdout_coverage_or_containment_regression')
if (totals.benignCases < 7 || totals.benignRetained !== totals.benignCases) globalProblems.push('benign_retention_regression')
if (totals.controlledMutationTargets !== 3 || totals.nativeReplayTargets !== 1) globalProblems.push('causal_evidence_mix_regression')

const verdict = globalProblems.length === 0 ? 'PASS' : 'FAIL'
const benchmark = {
  version: 'security-delta-benchmark/v1',
  thesis: spec.thesis,
  generatedAt: new Date().toISOString(),
  engine: metadata.engine,
  summary: {
    repositories: results.length,
    architectureFamilies: new Set(results.map((item) => item.architecture)).size,
    attackCases: totals.attackCases,
    beforeImpactEscapes: totals.beforeEscapes,
    afterImpactEscapes: totals.afterEscapes,
    impactEscapesPrevented: totals.beforeEscapes - totals.afterEscapes,
    namedCaseAttackSuccessBefore: totals.attackCases === 0 ? 0 : totals.beforeEscapes / totals.attackCases,
    namedCaseAttackSuccessAfter: totals.attackCases === 0 ? 0 : totals.afterEscapes / totals.attackCases,
    measuredAttackSuccessDeltaPercentagePoints: totals.attackCases === 0 ? 0 : ((totals.beforeEscapes - totals.afterEscapes) / totals.attackCases) * 100,
    holdoutCases: totals.holdoutCases,
    holdoutContained: totals.holdoutContained,
    benignCases: totals.benignCases,
    benignRetained: totals.benignRetained,
    controlledMutationTargets: totals.controlledMutationTargets,
    nativeReachableReplayTargets: totals.nativeReplayTargets,
    verdict,
  },
  methodology: {
    unitOfComparison: 'same target + same named input, security control removed/weakened vs real protected path',
    targetOwnedEvidence: true,
    aggregatorMayOverrideTargetResult: false,
    frozenHoldoutRule: 'Holdout cases are evaluation-only in this benchmark change. The factory remediation is derived from its known split only; GitLaw and PrüfPilot controls pre-exist the new holdout fixtures. SafeVoice is explicitly excluded from holdout claims because its native replay predates the split.',
    utilityRule: 'A target fails if legitimate benign controls no longer work after the security boundary is restored.',
    releaseRule: 'Any post-boundary impact escape, holdout escape, benign regression, schema mismatch, or truth-boundary mismatch fails the benchmark.',
  },
  targets: results.map(({ report, ...item }) => ({
    ...item,
    summary: report.summary,
    mutation: report.mutation,
    methodology: report.methodology ?? null,
    truthBoundary: report.truthBoundary,
  })),
  assertions: globalProblems.length === 0 ? ['PASS'] : globalProblems,
  truthBoundary: spec.truthBoundary,
}

await mkdir(outputDir, { recursive: true })
await mkdir(path.join(outputDir, 'evidence'), { recursive: true })
await writeFile(path.join(outputDir, 'benchmark.json'), `${JSON.stringify(benchmark, null, 2)}\n`)
for (const target of spec.targets) {
  await copyFile(path.join(targetRoot, target.id, target.evidencePath), path.join(outputDir, 'evidence', `${target.id}.json`))
}

const targetRows = benchmark.targets.map((target) => {
  const s = target.summary
  const commitShort = target.commit?.slice(0, 8) ?? 'unknown'
  return `| ${target.repository} | ${target.architecture} | ${s.attackCases} | ${s.before.impactEscapes} → ${s.after.impactEscapes} | ${s.holdout.contained}/${s.holdout.total} | ${s.benign.retained}/${s.benign.cases} | ${commitShort} |`
}).join('\n')

const summaryMd = `# TrustReady Security Delta Benchmark v1\n\n**Verdict: ${verdict}**\n\nControlled question: **Does restoring the security boundary reduce measured unauthorized impact for the same named inputs without breaking legitimate behavior?**\n\n- Repositories: **${benchmark.summary.repositories}**\n- Architectures: **${benchmark.summary.architectureFamilies}**\n- Named attack cases: **${benchmark.summary.attackCases}**\n- Impact escapes: **${benchmark.summary.beforeImpactEscapes} → ${benchmark.summary.afterImpactEscapes}**\n- Frozen holdouts contained: **${benchmark.summary.holdoutContained}/${benchmark.summary.holdoutCases}**\n- Benign controls retained: **${benchmark.summary.benignRetained}/${benchmark.summary.benignCases}**\n- Evidence mix: **${benchmark.summary.controlledMutationTargets} controlled mutants + ${benchmark.summary.nativeReachableReplayTargets} native reachable pre-boundary replay**\n\n| Repository | Architecture | Attacks | Impact | Holdout | Benign | Commit |\n|---|---|---:|---:|---:|---:|---|\n${targetRows}\n\n## Interpretation\n\nFor the named controlled scenarios, measured attack success moves from ${pct(benchmark.summary.namedCaseAttackSuccessBefore)} to ${pct(benchmark.summary.namedCaseAttackSuccessAfter)} after the relevant deterministic boundary is present. This is a **causal engineering delta**, not a claim that the repositories are “100% secure.” Three baselines are intentionally weakened test-only mutants/synthetic fixtures. SafeVoice contributes stronger scoped native reachable pre-boundary evidence.\n\n## Truth boundary\n\n${benchmark.truthBoundary}\n`
await writeFile(path.join(outputDir, 'summary.md'), summaryMd)

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[ch]))
}

const cards = benchmark.targets.map((target) => {
  const s = target.summary
  const label = target.id === 'safevoice' ? 'native reachable replay' : 'controlled mutation'
  return `<article class="target-card">
    <div class="target-top"><span class="target-name">${escapeHtml(target.repository.split('/')[1])}</span><span class="proof-badge">${escapeHtml(label)}</span></div>
    <p>${escapeHtml(target.architecture)}</p>
    <div class="delta-line"><strong>${s.before.impactEscapes}</strong><span>impact escapes</span><b>→</b><strong class="safe">${s.after.impactEscapes}</strong></div>
    <div class="mini-grid"><span><b>${s.attackCases}</b> attacks</span><span><b>${s.holdout.contained}/${s.holdout.total}</b> holdouts</span><span><b>${s.benign.retained}/${s.benign.cases}</b> benign retained</span></div>
    <a href="https://github.com/${escapeHtml(target.repository)}/commit/${escapeHtml(target.commit)}" target="_blank" rel="noreferrer">Exact target commit ↗</a>
  </article>`
}).join('\n')

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TrustReady Security Delta Benchmark v1</title>
<meta name="description" content="A causal A/B benchmark showing whether deterministic AI security boundaries reduce measured attack impact while preserving benign behavior across four real repositories.">
<style>
:root{color-scheme:dark;--bg:#07100f;--panel:#0d1917;--panel2:#101f1d;--text:#eef8f5;--muted:#91aaa3;--line:#20332f;--good:#72f1bd;--warn:#ffc76a;--accent:#8dd9ff}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 70% 0%,#12302a 0,transparent 38%),var(--bg);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--text);line-height:1.5}.wrap{max-width:1120px;margin:auto;padding:64px 24px 96px}.eyebrow{font-size:12px;letter-spacing:.16em;text-transform:uppercase;color:var(--good);font-weight:800}.hero{padding:36px 0 44px}.hero h1{font-size:clamp(42px,7vw,78px);line-height:.98;letter-spacing:-.055em;max-width:950px;margin:14px 0 24px}.hero p{font-size:clamp(18px,2.2vw,24px);max-width:780px;color:#b9cbc6}.question{display:inline-block;margin-top:18px;padding:12px 16px;border:1px solid var(--line);border-radius:999px;background:#0a1513;color:#d8e8e3}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:26px 0 48px}.metric{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:18px;padding:22px}.metric strong{display:block;font-size:34px;letter-spacing:-.04em}.metric span{color:var(--muted);font-size:13px}.impact{border-color:#285c4d}.impact strong{color:var(--good)}h2{font-size:30px;letter-spacing:-.03em;margin:52px 0 16px}.ab{display:grid;grid-template-columns:1fr auto 1fr;align-items:center;gap:16px;padding:22px;border:1px solid var(--line);border-radius:20px;background:#0a1513}.state{padding:20px;border-radius:14px;background:#111d1b}.state small{display:block;color:var(--muted);text-transform:uppercase;letter-spacing:.1em}.state b{font-size:28px}.state.after b{color:var(--good)}.arrow{font-size:28px;color:var(--muted)}.targets{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}.target-card{border:1px solid var(--line);background:linear-gradient(180deg,#0f1d1a,#0b1614);border-radius:20px;padding:22px}.target-top{display:flex;justify-content:space-between;gap:12px;align-items:center}.target-name{font-size:20px;font-weight:800}.proof-badge{font-size:11px;color:var(--accent);border:1px solid #274653;border-radius:999px;padding:5px 8px}.target-card p{color:var(--muted);min-height:48px}.delta-line{display:flex;gap:10px;align-items:baseline;margin:18px 0}.delta-line strong{font-size:28px}.delta-line span{color:var(--muted);font-size:13px}.safe{color:var(--good)}.mini-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:16px 0}.mini-grid span{background:#081210;border-radius:10px;padding:10px;color:var(--muted);font-size:12px}.mini-grid b{color:var(--text);display:block;font-size:16px}.target-card a,.links a{color:var(--accent);text-decoration:none;font-size:13px}.method{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.method div{border:1px solid var(--line);border-radius:16px;padding:18px}.method b{display:block;margin-bottom:6px}.method span{color:var(--muted);font-size:14px}.truth{margin-top:48px;border:1px solid #534529;background:#1b1810;border-radius:18px;padding:20px}.truth strong{color:var(--warn)}.truth p{color:#d7c9a8;margin-bottom:0}.links{display:flex;gap:18px;flex-wrap:wrap;margin-top:22px}.foot{margin-top:44px;color:#68827b;font-size:12px}@media(max-width:760px){.wrap{padding:40px 18px 72px}.metrics{grid-template-columns:1fr 1fr}.targets{grid-template-columns:1fr}.ab{grid-template-columns:1fr}.arrow{transform:rotate(90deg);text-align:center}.method{grid-template-columns:1fr}.mini-grid{grid-template-columns:1fr 1fr 1fr}.hero h1{font-size:48px}}@media(max-width:430px){.metrics{grid-template-columns:1fr}.mini-grid{grid-template-columns:1fr}.target-top{align-items:flex-start;flex-direction:column}}
</style>
</head>
<body><main class="wrap">
<section class="hero"><div class="eyebrow">TrustReady · Security Delta Benchmark v1 · ${verdict}</div><h1>Does the boundary actually make the system safer?</h1><p>We remove or bypass one security boundary in a controlled baseline, replay the same attacks, restore the real control, and measure what reaches the effect layer.</p><div class="question">Same input → guard off vs guard on → impact measured</div></section>
<section class="metrics"><div class="metric"><strong>${benchmark.summary.repositories}</strong><span>real repositories</span></div><div class="metric impact"><strong>${benchmark.summary.beforeImpactEscapes} → ${benchmark.summary.afterImpactEscapes}</strong><span>measured impact escapes</span></div><div class="metric"><strong>${benchmark.summary.holdoutContained}/${benchmark.summary.holdoutCases}</strong><span>frozen holdouts contained</span></div><div class="metric"><strong>${benchmark.summary.benignRetained}/${benchmark.summary.benignCases}</strong><span>benign controls retained</span></div></section>
<section><h2>The causal test</h2><div class="ab"><div class="state"><small>Controlled baseline</small><b>${benchmark.summary.beforeImpactEscapes}/${benchmark.summary.attackCases} attacks reach impact</b><p>Boundary intentionally removed, bypassed, or represented by scoped native pre-boundary evidence.</p></div><div class="arrow">→</div><div class="state after"><small>Protected path</small><b>${benchmark.summary.afterImpactEscapes}/${benchmark.summary.attackCases} reach impact</b><p>The real deterministic boundary is present. Legitimate controls must still work.</p></div></div></section>
<section><h2>Four different systems</h2><div class="targets">${cards}</div></section>
<section><h2>Why this is stronger than “our tests are green”</h2><div class="method"><div><b>1 · Counterfactual</b><span>We establish what happens when the relevant control is absent, not just that the final build passes.</span></div><div><b>2 · Holdout</b><span>${benchmark.summary.holdoutCases} frozen cases test whether the boundary generalizes beyond the development examples. SafeVoice is explicitly excluded from this claim.</span></div><div><b>3 · Utility</b><span>${benchmark.summary.benignRetained}/${benchmark.summary.benignCases} legitimate controls still work, so “block everything” cannot pass.</span></div></div></section>
<section class="truth"><strong>Truth boundary</strong><p>${escapeHtml(benchmark.truthBoundary)}</p></section>
<div class="links"><a href="./benchmark.json">Machine-readable benchmark ↗</a><a href="https://github.com/mikelninh/trustready/tree/main/benchmarks/security-delta" target="_blank" rel="noreferrer">Method + source ↗</a></div>
<div class="foot">Engine commit ${escapeHtml(metadata.engine?.commit ?? 'unknown')} · generated from exact target revisions · PASS means the named benchmark assertions passed, not that any repository is universally secure.</div>
</main></body></html>`
await writeFile(path.join(outputDir, 'index.html'), html)

console.log(JSON.stringify({
  verdict,
  repositories: benchmark.summary.repositories,
  attacks: benchmark.summary.attackCases,
  impactEscapes: `${benchmark.summary.beforeImpactEscapes}->${benchmark.summary.afterImpactEscapes}`,
  holdout: `${benchmark.summary.holdoutContained}/${benchmark.summary.holdoutCases}`,
  benign: `${benchmark.summary.benignRetained}/${benchmark.summary.benignCases}`,
}))

if (verdict !== 'PASS') process.exitCode = 1
