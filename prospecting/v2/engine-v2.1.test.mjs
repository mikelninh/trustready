import assert from 'node:assert/strict'
import test from 'node:test'
import { buildProspectSecuritySignalV21 } from './engine-v2.1.mjs'

const snap=(files)=>({repository_url:'https://github.com/acme/app',revision:'abc123',files})

test('read-only search dispatch is not a proof gap',()=>{
  const s=buildProspectSecuritySignalV21(snap({'agent.py':`def search_web(query): return tavily.search(query=query)\navailable_functions={'search_web':search_web}\nfor tool_call in message.tool_calls:\n    func=available_functions[tool_call.function.name]\n    result=func(**args)`}),{segment:'application'})
  assert.notEqual(s.classification,'PROOF_GAP')
})

test('demo plotting dispatch is not a proof gap',()=>{
  const s=buildProspectSecuritySignalV21(snap({'agent.py':`def plot_graph(x,y): plt.plot(x,y)\navailable_functions={'plot_graph':plot_graph}\nfor tool_call in response.tool_calls:\n    fn=available_functions[tool_call.function.name]\n    fn(**args)`}),{segment:'application'})
  assert.notEqual(s.classification,'PROOF_GAP')
})

test('edit file dispatch is a proof gap',()=>{
  const s=buildProspectSecuritySignalV21(snap({'agent.py':`def edit_file(path,old,new):\n    with open(path,'w') as f: f.write(new)\nself_tools={'edit_file':edit_file}\nfor tool_call in response.tool_calls:\n    tool_name=tool_call.function.name\n    tool_func=self_tools[tool_name]\n    tool_func(**args)`}),{segment:'application'})
  assert.equal(s.classification,'PROOF_GAP')
  assert.ok(s.evidence.consequences.length>0)
})

test('tool_mapping with write-file surface recovers false negative',()=>{
  const s=buildProspectSecuritySignalV21(snap({
    'agent.py':`tool_name = tool_call.function.name\nif tool_name in self.tool_mapping:\n    tool_result = self.tool_mapping[tool_name](**tool_args)`,
    'tools/write_file_tool.py':`def write_file(path, content):\n    with open(path,'w') as f: f.write(content)`
  }),{segment:'application'})
  assert.equal(s.classification,'PROOF_GAP')
})

test('framework with bash surface remains review signal',()=>{
  const s=buildProspectSecuritySignalV21(snap({
    'agent.py':`for tool_call in response.tool_calls:\n    function_name=tool_call.function.name\n    tool=self.tools[function_name]\n    tool.execute(**arguments)`,
    'tools/bash_tool.py':`class BashTool:\n    def execute(self, command): return subprocess.run(command, shell=True)`
  }),{segment:'agent framework'})
  assert.equal(s.classification,'REVIEW_SIGNAL')
})

test('explicit authority gate does not become proof gap',()=>{
  const s=buildProspectSecuritySignalV21(snap({'agent.py':`def write_file(path,data):\n    open(path,'w').write(data)\ntool_name=tool_call.function.name\nif not authorize(tool_name): raise PermissionError()\nfunc=available_functions[tool_name]\nfunc(**args)`}),{segment:'application'})
  assert.notEqual(s.classification,'PROOF_GAP')
})
