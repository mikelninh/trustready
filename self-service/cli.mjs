import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { collectLocalRepository } from './local-collector.mjs'
import { buildSelfServiceAssessment, defaultConfig, githubWorkflowTemplate, validateTargetProof } from './self-service.mjs'
import { runConnectedProof } from './connected-runner.mjs'

const [command = 'help', arg = '.'] = process.argv.slice(2)

async function main() {
  if (command === 'scan') {
    const snapshot = await collectLocalRepository(resolve(arg))
    const assessment = buildSelfServiceAssessment(snapshot)
    console.log(JSON.stringify(assessment, null, 2))
    if (assessment.release.decision === 'TECHNICAL_NO_GO') process.exitCode = 1
    return
  }
  if (command === 'verify') {
    const proof = JSON.parse(await readFile(resolve(arg), 'utf8'))
    const result = validateTargetProof(proof)
    console.log(JSON.stringify(result, null, 2))
    if (!result.valid) process.exitCode = 1
    return
  }
  if (command === 'run') {
    const result = await runConnectedProof(resolve(arg))
    console.log(JSON.stringify(result, null, 2))
    if (result.status !== 'TECHNICAL_GO') process.exitCode = 1
    return
  }
  if (command === 'init') {
    const root = resolve(arg)
    await mkdir(resolve(root, '.github/workflows'), { recursive: true })
    await writeFile(resolve(root, 'trustready.config.json'), `${JSON.stringify(defaultConfig(), null, 2)}\n`, { flag: 'wx' })
    await writeFile(resolve(root, '.github/workflows/trustready-security-delta.yml'), githubWorkflowTemplate(), { flag: 'wx' })
    console.log('TrustReady Self-Service initialized. Add a supported target-owned Security Delta harness, then run the generated CI workflow or: node self-service/cli.mjs run .')
    return
  }
  console.log('TrustReady Self-Service v1\n\n  scan <repo>    Discover reachable agent/tool security surface\n  verify <json>  Validate security-delta-target-proof/v1 evidence\n  run <repo>     Run a supported target-owned Security Delta recipe + verify evidence\n  init <repo>    Write config + minimal CI workflow (fails if files already exist)')
}

await main()
