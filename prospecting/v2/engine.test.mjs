import assert from 'node:assert/strict'
import test from 'node:test'
import { buildProspectSecuritySignalV2, precisionMetrics } from './engine.mjs'

const snap=(files)=>({repository_url:'https://github.com/acme/app',revision:'abc123',files})

test('proves selector-controlled getattr dispatch',()=>{
  const s=buildProspectSecuritySignalV2(snap({'agent.py':`tool_name = tool_call.function.name\nfunc = getattr(handler, tool_name)\nresult = await func(**tool_call.function.arguments)`}),{segment:'application'})
  assert.equal(s.classification,'PROOF_GAP')
  assert.equal(s.evidence.selectorFlows.length,1)
})

test('recognizes loop-bound selector dispatch',()=>{
  const s=buildProspectSecuritySignalV2(snap({'engine.py':`async for tool in iter_to_aiter(message.tool_calls):\n    if tool.tool_type == 'function':\n        res = await session.call_tool(tool.name, arguments=tool.arguments or {})`}),{segment:'agent framework'})
  assert.equal(s.classification,'REVIEW_SIGNAL')
  assert.equal(s.evidence.selectorFlows[0].selectorKind,'loop_item')
})

test('local approval between selector and sink downgrades',()=>{
  const s=buildProspectSecuritySignalV2(snap({'agent.py':`tool_name = tool_call.function.name\nif not requiresApproval(tool_name): raise Exception()\nfunc = getattr(handler, tool_name)\nresult = await func()`}),{segment:'application'})
  assert.equal(s.classification,'REVIEW_SIGNAL')
})

test('provider adapter does not count as effect dispatch',()=>{
  const s=buildProspectSecuritySignalV2(snap({'modules/agent/backends.py':`tool_name = tool_call.function.name\nresp = requests.post('http://127.0.0.1:11434/v1/chat/completions',json={'tool':tool_name})`}),{segment:'application'})
  assert.notEqual(s.classification,'PROOF_GAP')
})

test('tests and integration tests excluded',()=>{
  const s=buildProspectSecuritySignalV2(snap({'integration_tests/test_agent.py':`tool_name = tool_call.function.name\nfunc = getattr(handler, tool_name)\nfunc()`}),{segment:'application'})
  assert.equal(s.classification,'NO_ACTIONABLE_SIGNAL')
})

test('framework direct dispatch is review signal, not sales proof gap',()=>{
  const s=buildProspectSecuritySignalV2(snap({'engine.py':`tool_name = tool_call.function.name\nfunc = getattr(handler, tool_name)\nfunc()`}),{segment:'agent framework'})
  assert.equal(s.classification,'REVIEW_SIGNAL')
})

test('proximity alone does not qualify',()=>{
  const s=buildProspectSecuritySignalV2(snap({'agent.py':`tool_calls = response.tool_calls\nrequests.post('https://telemetry.example',json={'ok':true})`}),{segment:'application'})
  assert.notEqual(s.classification,'PROOF_GAP')
})

test('precision metric only scores reviewed proof gaps',()=>{
  const m=precisionMetrics([
    {signal:{classification:'PROOF_GAP'},humanLabel:'TRUE_SIGNAL'},
    {signal:{classification:'PROOF_GAP'},humanLabel:'FALSE_POSITIVE'},
    {signal:{classification:'REVIEW_SIGNAL'},humanLabel:'TRUE_SIGNAL'},
  ])
  assert.equal(m.reviewed,3)
  assert.equal(m.precision,0.5)
})
