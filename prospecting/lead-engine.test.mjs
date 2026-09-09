import assert from 'node:assert/strict'
import test from 'node:test'
import { buildProspectSecuritySignal, draftSecuritySignalMessage } from './lead-engine.mjs'

const snap=(files)=>({repository_url:'https://github.com/acme/agent',revision:'abc',files})

test('classifies public source gap without vulnerability claim',()=>{
  const result=buildProspectSecuritySignal(snap({
    'src/agent.py':`from openai import OpenAI\ndef run_agent(x):\n  tool_calls=x\n  return requests.post('https://example.com',json={'x':x})`,
  }))
  assert.equal(result.classification,'PROOF_GAP')
  assert.ok(result.observed.effectClasses.includes('external_http'))
  assert.match(result.truthBoundary,/does not .*prove exploitability/i)
  assert.doesNotMatch(JSON.stringify(result),/definitely vulnerable/i)
})

test('control signals downgrade to review signal',()=>{
  const result=buildProspectSecuritySignal(snap({
    'src/agent.ts':`import OpenAI from 'openai'; const maxToolCalls=4; function authorize(x){return x.approved_by}; async function run_agent(){ const tool_calls=[]; if(authorize({approved_by:'human'})) return fetch('https://x.test',{method:'POST'}) }`,
  }))
  assert.equal(result.classification,'REVIEW_SIGNAL')
  assert.ok(result.observed.controlClasses.includes('authorization'))
})

test('tests and docs do not create sales signal',()=>{
  const result=buildProspectSecuritySignal(snap({
    'tests/fake_agent.py':`openai tool_calls requests.post('https://x')`,
    'docs/example.ts':`anthropic tool_calls fetch('https://x',{method:'POST'})`,
  }))
  assert.equal(result.classification,'NO_ACTIONABLE_SIGNAL')
})

test('message is conditional and non-coercive',()=>{
  const result=buildProspectSecuritySignal(snap({'agent.js':`openai tool_calls fetch('https://x',{method:'POST'})`}))
  const msg=draftSecuritySignalMessage(result,{name:'Alex'})
  assert.match(msg,/not a claim that the system is exploitable/i)
  assert.match(msg,/Would a 20-minute technical check be useful\?/)
  assert.doesNotMatch(msg,/pay|or else|unless you pay|consequences if you refuse/i)
})
