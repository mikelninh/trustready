import assert from 'node:assert/strict'
import test from 'node:test'
import { scanAgentRepositorySnapshot } from './agent-repo-scanner.mjs'

function snapshot(files) {
  return { repository_url: 'https://github.com/acme/agent', revision: 'abc123', files }
}

test('unbounded model-selected executor is TECHNICAL_NO_GO and autofix candidate', () => {
  const result = scanAgentRepositorySnapshot(snapshot({
    'agent.mjs': `export const tools=[{id:'send_payment',name:'send_payment',risk:'consequential',external:true}]; export async function runAgent(model){ const tool_calls=[model]; const tool=tools[0]; tool.handler=async()=>true; const args={}; return tool.handler(args) }`,
  }))
  assert.equal(result.release.decision, 'TECHNICAL_NO_GO')
  assert.ok(result.blockers.includes('model_selected_executor_has_no_deterministic_boundary'))
  assert.equal(result.remediation.automaticCandidate, true)
  assert.ok(result.attackPlan.generated >= 4)
})

test('observed deterministic boundary can pass source precheck but never claims runtime TECHNICAL_GO', () => {
  const result = scanAgentRepositorySnapshot(snapshot({
    'agent.mjs': `// security-boundary\nexport const maxToolCalls=8; export const tools=[{id:'send_payment',name:'send_payment',risk:'consequential',external:true}]; export async function runAgent(model){ const tool_calls=[model]; const tool=tools[0]; tool.handler=async()=>true; const args={}; return tool.handler(args) }`,
  }))
  assert.equal(result.release.decision, 'SOURCE_PRECHECK_GO')
  assert.equal(result.release.runtimeProofRequired, true)
  assert.match(result.truthBoundary, /not runtime proof/i)
})

test('Python import graph excludes unrelated MCP tools from reachable attack plan', () => {
  const result = scanAgentRepositorySnapshot(snapshot({
    'app/court_agent.py': `from app import tools\ndef run_agent():\n    tool_calls=[]\n    return tool_calls\n`,
    'app/tools.py': `class ToolDef: pass\nx=ToolDef(name="read_case",description="read",schema={},handler=handler)`,
    'mcp/server.py': `mcp=FastMCP("x")\n@mcp.tool()\ndef send_payment(): pass`,
  }))
  assert.equal(result.topology.entrypoints.length, 1)
  assert.equal(result.topology.reachableMcpServers.length, 0)
  assert.equal(result.topology.isolatedMcpServers.length, 1)
  assert.ok(result.tools.reachable.some((tool) => tool.name === 'read_case'))
  assert.ok(result.tools.isolated.some((tool) => tool.name === 'send_payment'))
  assert.equal(result.attackPlan.cases.some((item) => item.capabilityId.includes('send_payment')), false)
})

test('unknown reachable tool risk fails closed', () => {
  const result = scanAgentRepositorySnapshot(snapshot({
    'agent.py': `class ToolDef: pass\nx=ToolDef(name="mystery_orb",description="x",schema={},handler=handler)\ndef run_agent():\n    tool_calls=[]\n    return tool_calls`,
  }))
  assert.equal(result.release.decision, 'TECHNICAL_NO_GO')
  assert.ok(result.blockers.includes('unknown_reachable_tool_risk'))
})
