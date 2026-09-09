import assert from 'node:assert/strict'
import test from 'node:test'
import { buildProspectSecuritySignalV22 } from './engine-v2.2.mjs'

const snap=(files)=>({repository_url:'https://github.com/acme/app',revision:'abc123',files})

test('search-only selectable registry is not a proof gap even if repo writes elsewhere',()=>{
  const s=buildProspectSecuritySignalV22(snap({
    'agent.py':`def search_web(query): return search(query)\navailable_functions={'search_web':search_web}\nfor tool_call in message.tool_calls:\n    func=available_functions[tool_call.function.name]\n    func(**args)`,
    'maintenance.py':`def delete_note(x): pass\nopen('cache.json','w').write('x')`
  }),{segment:'application'})
  assert.notEqual(s.classification,'PROOF_GAP')
})

test('send_email in selectable registry remains proof gap',()=>{
  const s=buildProspectSecuritySignalV22(snap({'email_agent.py':`def send_email(to,body):\n    return service.users().messages().send(userId='me',body=body).execute()\navailable_functions={'send_email':send_email}\nfor tool_call in result.tool_calls:\n    fn=available_functions[tool_call.function.name]\n    fn(**args)`}),{segment:'application'})
  assert.equal(s.classification,'PROOF_GAP')
  assert.equal(s.evidence.registryCoupled,true)
})

test('Resend email effect in model-selectable registry is a proof gap',()=>{
  const s=buildProspectSecuritySignalV22(snap({'app.py':`def send_email(to,subject,text):\n    return resend.Emails.send({'to':[to],'subject':subject,'text':text})\navailable={'send_email':send_email}\nfor tool_call in message.tool_calls:\n    name=tool_call.function.name\n    fn=available.get(name)\n    fn(**args)`}),{segment:'application'})
  assert.equal(s.classification,'PROOF_GAP')
  assert.equal(s.evidence.registryCoupled,true)
})

test('registered install_package one-hop dispatcher remains proof gap',()=>{
  const s=buildProspectSecuritySignalV22(snap({'main.py':`available_functions={}\ndef register_tool(name,func): available_functions[name]=func\ndef install_package(package_name): return subprocess.check_call(['pip','install',package_name])\nregister_tool('install_package',install_package)\ndef call_tool(function_name,args): return available_functions.get(function_name)(**args)\nfor tool_call in response.tool_calls:\n    function_name=tool_call.function.name\n    return call_tool(function_name,args)`}),{segment:'application'})
  assert.equal(s.classification,'PROOF_GAP')
})

test('dynamic discovered write-file tool remains proof gap',()=>{
  const s=buildProspectSecuritySignalV22(snap({
    'agent.py':`from tools import discover_tools\nself.discovered_tools=discover_tools()\nself.tool_mapping={name:tool.execute for name,tool in self.discovered_tools.items()}\ntool_name=tool_call.function.name\nresult=self.tool_mapping[tool_name](**args)`,
    'tools/write_file_tool.py':`def write_file(path,data):\n    open(path,'w').write(data)`
  }),{segment:'application'})
  assert.equal(s.classification,'PROOF_GAP')
})

test('constructor-injected self.tools registry recovers Au-style false negative',()=>{
  const s=buildProspectSecuritySignalV22(snap({
    'main.py':`def edit_file(path, old, new):\n    with open(path,'w') as f: f.write(new)\nclass Agent:\n    def execute_single_tool_call(self, tool_call):\n        tool_name = tool_call.function.name\n        tool_func = self.tools[tool_name].function\n        return tool_func(**args)\ntool_dic = {'read_file': read_file, 'edit_file': edit_file}\nagent = Agent(client=cli, tools=tool_dic)`
  }),{segment:'application'})
  assert.equal(s.classification,'PROOF_GAP')
  assert.equal(s.evidence.selectableConsequences.some(x=>x.kind==='constructor_injected_registry'),true)
})
