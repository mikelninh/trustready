import { buildProspectSecuritySignalV21 } from './engine-v2.1.mjs'

export const PROSPECT_V22_VERSION = 'trustready-prospect-security-signal/v2.2'

const SKIP_PATH = /(^|\/)(?:__?tests?__?|integration[_-]?tests?|testdata|fixtures?|examples?|samples?|docs?|playgrounds?|benchmarks?|evals?|migrations?|node_modules|vendor)(\/|$)/i
const CONSEQ_NAME = /(?:^|[_-])(?:send(?:_email|_message|_sms)?|reply_email|write|edit|delete|remove|create_file|write_file|edit_file|delete_file|install_package|execute_command|run_command|shell|bash|publish|deploy|release|payment|pay|charge|refund|transfer|home_assistant|turn_on|turn_off)(?:$|[_-])/i
const CONSEQ_IMPL = /(?:messages\(\)\.send\s*\(|messages\.send\s*\(|subprocess\.(?:run|call|check_call|Popen)\s*\(|os\.system\s*\(|open\s*\([^\n]{0,160},\s*['\"](?:w|a|x|wb|ab)['\"]|\.write_text\s*\(|os\.(?:remove|unlink)\s*\(|requests\.(?:post|put|patch|delete)\s*\(|stripe\.|\.activate\s*\(|\.deactivate\s*\()/i

function reEscape(v){ return String(v||'').replace(/[.*+?^${}()|[\]\\]/g,'\\$&') }
function lineNo(content,offset){ return String(content||'').slice(0,offset).split('\n').length }

function registryNameFromFlow(flow){
  const s=String(flow?.sinkSnippet||'')
  const m=/(available_functions|AVAILABLE_FUNCTIONS|tool_mapping|tool_map|tool_fn_map|self\.tools|tools|handlers|actions|functions)/i.exec(s)
  return m?.[1]||null
}

function dictEntries(content, registry) {
  if(!registry) return []
  const bare=registry.replace(/^self\./,'')
  const names=[registry,bare]
  const out=[]
  for(const n of names){
    const esc=reEscape(n)
    const re=new RegExp(`${esc}\\s*=\\s*\\{([\\s\\S]{0,2200}?)\\}`,'gi')
    let m
    while((m=re.exec(content))){
      const body=m[1]
      const keyRe=/['\"]([^'\"]+)['\"]\s*:\s*([A-Za-z_$][\w$.]*)/g
      let k
      while((k=keyRe.exec(body))) out.push({name:k[1],implementation:k[2],line:lineNo(content,m.index)})
    }
  }
  return out
}

function registerToolEntries(content){
  const out=[]
  const re=/\bregister_tool\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*([A-Za-z_$][\w$.]*)/g
  let m
  while((m=re.exec(content))) out.push({name:m[1],implementation:m[2],line:lineNo(content,m.index)})
  return out
}

function functionLooksConsequential(content,name){
  if(CONSEQ_NAME.test(name)) { CONSEQ_NAME.lastIndex=0; return true }
  CONSEQ_NAME.lastIndex=0
  const esc=reEscape(name.split('.').pop())
  const re=new RegExp(`(?:async\\s+def|def|function)\\s+${esc}\\b[\\s\\S]{0,1800}`,'i')
  const m=re.exec(content)
  return !!(m && CONSEQ_IMPL.test(m[0]))
}

function dynamicDiscoveredToolsEvidence(snapshot, flowPath, content, registry){
  const out=[]
  if(!/(?:discover_tools|discovered_tools)/i.test(content)) return out
  if(!/(?:tool_mapping|self\.tools|tools)/i.test(String(registry||''))) return out
  for(const [path,body] of Object.entries(snapshot?.files||{})){
    if(SKIP_PATH.test(path) || !/(^|\/)tools?\//i.test(path)) continue
    const base=path.split('/').pop()?.replace(/\.[^.]+$/,'')||''
    const nameHit=CONSEQ_NAME.test(base); CONSEQ_NAME.lastIndex=0
    const implHit=CONSEQ_IMPL.test(String(body||'')); CONSEQ_IMPL.lastIndex=0
    if(nameHit || (implHit && /(?:write|edit|delete|send|shell|bash|command|payment|deploy)/i.test(base))){
      out.push({flowPath,registry,toolName:base,implementationPath:path,kind:'dynamic_discovered_tool'})
    }
  }
  return out
}

function selectableConsequences(snapshot, flows){
  const out=[]
  for(const flow of flows||[]){
    const content=String(snapshot?.files?.[flow.path]||'')
    if(!content) continue
    const registry=registryNameFromFlow(flow)
    const entries=[...dictEntries(content,registry),...registerToolEntries(content)]
    for(const e of entries){
      if(functionLooksConsequential(content,e.name) || functionLooksConsequential(content,e.implementation)){
        out.push({flowPath:flow.path,registry,toolName:e.name,implementation:e.implementation,line:e.line,kind:'local_registry_entry'})
      }
    }

    // one-hop dispatcher: model selector -> call_tool(name) -> available_functions.get(name)
    if(/\bcall_tool\s*\(/.test(String(flow.sinkSnippet||''))){
      for(const e of registerToolEntries(content)){
        if(functionLooksConsequential(content,e.name) || functionLooksConsequential(content,e.implementation))
          out.push({flowPath:flow.path,registry:'available_functions via call_tool',toolName:e.name,implementation:e.implementation,line:e.line,kind:'registered_dispatch_entry'})
      }
    }

    out.push(...dynamicDiscoveredToolsEvidence(snapshot,flow.path,content,registry))
  }
  const seen=new Set()
  return out.filter(x=>{const k=`${x.flowPath}:${x.registry}:${x.toolName}:${x.implementationPath||x.implementation||''}`;if(seen.has(k))return false;seen.add(k);return true}).slice(0,30)
}

export function buildProspectSecuritySignalV22(snapshot,opts={}){
  const s=buildProspectSecuritySignalV21(snapshot,opts)
  const selectable=selectableConsequences(snapshot,s.evidence?.selectorFlows||[])
  let classification=s.classification, priority=s.priority, rationale=s.rationale

  if(classification==='PROOF_GAP' && selectable.length===0){
    classification='ARCHITECTURE_UNCERTAIN'
    priority=38
    rationale='Selector-controlled dispatch is visible, but the bounded source snapshot did not prove that the model-selectable registry contains a consequential tool. Unrelated repository writes/processes do not qualify.'
  }

  return {
    ...s,
    version:PROSPECT_V22_VERSION,
    classification,priority,rationale,
    evidence:{...(s.evidence||{}),selectableConsequences:selectable,registryCoupled:selectable.length>0},
    reviewRequired:['PROOF_GAP','REVIEW_SIGNAL'].includes(classification),
    truthBoundary:'Passive public-source static analysis only. This does not execute the target, test production, prove exploitability, or confirm a vulnerability. A PROOF_GAP requires selector-controlled dispatch plus a consequential model-selectable tool surface without an independently visible authority gate; owned-environment validation is still required.'
  }
}
