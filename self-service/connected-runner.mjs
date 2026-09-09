import { access, readFile } from 'node:fs/promises'
import { constants } from 'node:fs'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { validateTargetProof } from './self-service.mjs'

export const CONNECTED_RUNNER_VERSION = 'trustready-connected-runner/v1'

const RECIPES = [
  { id: 'npm-security-delta', detect: async root => exists(join(root, 'package.json')) && packageHas(root, 'security:delta'), command: ['npm', 'run', 'security:delta'] },
  { id: 'node-security-delta', detect: async root => exists(join(root, 'security/security-delta.mjs')), command: ['node', 'security/security-delta.mjs'] },
  { id: 'python-security-delta', detect: async root => exists(join(root, 'security/security_delta.py')), command: ['python', 'security/security_delta.py'] },
]

async function exists(path) { try { await access(path, constants.R_OK); return true } catch { return false } }
async function packageHas(root, script) { try { const p = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')); return Boolean(p.scripts?.[script]) } catch { return false } }

export async function detectRecipe(root) {
  for (const recipe of RECIPES) if (await recipe.detect(root)) return recipe
  return null
}

export async function runConnectedProof(root, { timeoutMs = 120000 } = {}) {
  const cwd = resolve(root)
  const recipe = await detectRecipe(cwd)
  if (!recipe) return { version: CONNECTED_RUNNER_VERSION, status: 'SETUP_REQUIRED', reason: 'no_supported_target_owned_delta_harness' }
  const result = spawnSync(recipe.command[0], recipe.command.slice(1), {
    cwd,
    encoding: 'utf8',
    shell: false,
    timeout: timeoutMs,
    env: { ...process.env, TRUSTREADY_CONNECTED_RUNNER: '1' },
  })
  if (result.error) return { version: CONNECTED_RUNNER_VERSION, status: 'TECHNICAL_NO_GO', recipe: recipe.id, reason: result.error.message }
  if (result.status !== 0) return { version: CONNECTED_RUNNER_VERSION, status: 'TECHNICAL_NO_GO', recipe: recipe.id, reason: 'target_harness_failed', exitCode: result.status, stdout: result.stdout?.slice(-4000), stderr: result.stderr?.slice(-4000) }
  const candidates = [
    join(cwd, 'security/security-delta-proof.json'),
    join(cwd, 'enterprise/security-delta-proof.json'),
  ]
  let proof = null
  let proofPath = null
  for (const path of candidates) {
    if (!await exists(path)) continue
    try { proof = JSON.parse(await readFile(path, 'utf8')); proofPath = path; break } catch {}
  }
  if (!proof) return { version: CONNECTED_RUNNER_VERSION, status: 'TECHNICAL_NO_GO', recipe: recipe.id, reason: 'target_harness_did_not_emit_supported_proof' }
  const validation = validateTargetProof(proof)
  return {
    version: CONNECTED_RUNNER_VERSION,
    status: validation.valid ? 'TECHNICAL_GO' : 'TECHNICAL_NO_GO',
    recipe: recipe.id,
    proofPath,
    validation,
    proof,
    truthBoundary: 'The connected runner executes only one of TrustReady v1\'s fixed target-owned Security Delta recipes with shell=false, then validates the emitted machine evidence. The target harness remains responsible for its own attack realism and effect instrumentation.',
  }
}

if (import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const result = await runConnectedProof(process.argv[2] || '.')
  console.log(JSON.stringify(result, null, 2))
  if (result.status !== 'TECHNICAL_GO') process.exitCode = 1
}
