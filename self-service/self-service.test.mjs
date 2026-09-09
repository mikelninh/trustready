import assert from 'node:assert/strict'
import test from 'node:test'
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { buildSelfServiceAssessment, validateTargetProof } from './self-service.mjs'
import { runConnectedProof } from './connected-runner.mjs'

const goodProof = () => ({
  version: 'security-delta-target-proof/v1', repository: 'acme/agent',
  summary: { attackCases: 2, before: { impactEscapes: 2 }, after: { impactEscapes: 0 }, holdout: { total: 1, contained: 1 }, benign: { cases: 1, retained: 1 } },
  truthBoundary: 'Named controlled scenarios only.'
})

function snapshot() {
  return { repository_url: 'https://github.com/acme/agent', revision: 'abc', files: {
    'agent.mjs': `// security-boundary\nexport const maxToolCalls=8; export const tools=[{id:'send_email',name:'send_email',risk:'consequential',external:true}]; export async function runAgent(model){ const tool_calls=[model]; const tool=tools[0]; tool.handler=async()=>true; const args={}; return tool.handler(args) }`
  }}
}

test('source preflight alone never becomes TECHNICAL_GO', () => {
  const result = buildSelfServiceAssessment(snapshot())
  assert.equal(result.release.decision, 'SETUP_REQUIRED')
  assert.equal(result.sourcePreflight.release.runtimeProofRequired, true)
})

test('valid target-owned proof upgrades eligible source to TECHNICAL_GO', () => {
  const result = buildSelfServiceAssessment(snapshot(), { proof: goodProof() })
  assert.equal(result.release.decision, 'TECHNICAL_GO')
  assert.equal(result.proof.valid, true)
})

test('proof fails closed on an impact escape or benign regression', () => {
  const proof = goodProof(); proof.summary.after.impactEscapes = 1; proof.summary.benign.retained = 0
  const result = validateTargetProof(proof)
  assert.equal(result.valid, false)
  assert.ok(result.errors.includes('post_boundary_impact_escape'))
  assert.ok(result.errors.includes('benign_regression'))
})

test('connected runner executes fixed node recipe and validates emitted proof', async () => {
  const root = await mkdtemp(join(tmpdir(), 'trustready-self-service-'))
  await mkdir(join(root, 'security'), { recursive: true })
  await writeFile(join(root, 'security/security-delta.mjs'), `import {writeFileSync} from 'node:fs'; const p=${JSON.stringify(goodProof())}; writeFileSync('security/security-delta-proof.json',JSON.stringify(p));`)
  const result = await runConnectedProof(root)
  assert.equal(result.recipe, 'node-security-delta')
  assert.equal(result.status, 'TECHNICAL_GO')
  assert.equal(result.validation.valid, true)
})

test('connected runner refuses unknown arbitrary commands', async () => {
  const root = await mkdtemp(join(tmpdir(), 'trustready-self-service-'))
  await writeFile(join(root, 'trustready.config.json'), JSON.stringify({ proofCommand: ['bash','-c','echo nope'] }))
  const result = await runConnectedProof(root)
  assert.equal(result.status, 'SETUP_REQUIRED')
  assert.equal(result.reason, 'no_supported_target_owned_delta_harness')
})
