export const PROSPECT_V2_VERSION = 'trustready-prospect-security-signal/v2'

const SKIP_PATH = /(^|\/)(?:__?tests?__?|integration[_-]?tests?|testdata|fixtures?|examples?|samples?|docs?|playgrounds?|benchmarks?|evals?|migrations?|node_modules|vendor)(\/|$)/i
const ADAPTER_PATH = /(^|\/)(?:llm|llms|models?|providers?|serializers?|parsers?|normalizers?|backends?)(\/|$)/i
const FRAMEWORK_HINT = /(?:sdk|framework|library|orchestrat|toolkit|runtime|protocol|calibration framework)/i
const CONTROL_RE = /(?:human[_-]?approval|humanApproval|approval[_-]?required|approvalRequired|requires[_-]?approval|requiresApproval|approved[_-]?by|approvedBy|ToolApproved|ToolDenied|ApprovalRequired|authorize|authorization|permission|capability[_-]?check|capabilityCheck|policy[_-]?gate|policyGate|security[_-]?boundary|securityBoundary|allow[_-]?list|allowlist|allowed[_-]?(?:tools|actions|targets|domains)|allowed(?:Tools|Actions|Targets|Domains))/i
const EFFECT_RE = /(?:send[_-]?(?:email|message|sms)|messages\.create|smtp\.|twilio\.|slack[^\n]{0,100}\.post|requests\.(?:post|put|patch|delete)|httpx\.(?:post|put|patch|delete)|axios\.(?:post|put|patch|delete)|fetch\s*\(|subprocess\.|os\.system|child_process|spawn\s*\(|exec(?:File)?\s*\(|\.insert\s*\(|\.update\s*\(|\.delete\s*\(|\.save\s*\(|session\.call_tool\s*\(|call_tool\s*\(|invoke_tool\s*\(|execute_tool\s*\()/i

function rows(content){ return String(content||'').split('\n') }
function lineNo(content, offset){ return String(content||'').slice(0,offset).split('\n').length }
function offsetForLine(content,line){
  if(line<=1) return 0
  let off=0
  const rs=rows(content)
  for(let i=0;i<Math.min(line-1,rs.length);i++) off += rs[i].length+1
  return off
}
function reEscape(v){ return String(v||'').replace(/[.*+?^${}()|[\]\\]/g,'\\$&') }

function detectRole(path,content,meta={}){
  if(SKIP_PATH.test(path)) return 'nonproduction'
  if(ADAPTER_PATH.test(path) || /\b(?:serializer|provider adapter|model backend|chat completion wrapper|normalize tool calls)\b/i.test(content)) return 'model_adapter'
  if(/(?:mcp|tool registry|registry|executor|engine|agent loop|dispatch)/i.test(path+' '+content.slice(0,1200))) return 'execution_layer'
  if(FRAMEWORK_HINT.test(String(meta.segment||'')) || FRAMEWORK_HINT.test(String(meta.description||''))) return 'framework'
  return 'application'
}

function selectorCandidates(content){
  const out=[]
  const assignment=/(?:const|let|var\s+)?([A-Za-z_$][\w$]*)\s*=\s*([^\n;]*(?:tool[_]?call|toolCall|function[_]?call|functionCall)[^\n;]*(?:\.function\.name|\.tool_name|\.toolName|\.name|\[['"]name['"]\]))/gi
  let a
  while((a=assignment.exec(content))) out.push({kind:'assignment',variable:a[1],expr:a[2].trim(),line:lineNo(content,a.index)})

  const pyLoop=/\b(?:async\s+for|for)\s+([A-Za-z_][\w]*)\s+in\s+(?:iter_to_aiter\s*\(\s*)?([^\n:)]*(?:tool_calls|toolCalls)[^\n:)]*)\)?\s*:/gi
  let p
  while((p=pyLoop.exec(content))) out.push({kind:'loop_item',variable:p[1],expr:`${p[1]}.function.name`,source:p[2].trim(),line:lineNo(content,p.index)})

  const jsLoop=/for\s*\(\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s+of\s+([^)]*(?:tool_calls|toolCalls)[^)]*)\)/gi
  let j
  while((j=jsLoop.exec(content))) out.push({kind:'loop_item',variable:j[1],expr:`${j[1]}.function.name`,source:j[2].trim(),line:lineNo(content,j.index)})

  const direct=/(?:tool[_]?call|toolCall|function[_]?call|functionCall)[\w.\[\]'"?]*?(?:\.function\.name|\.tool_name|\.toolName|\[['"]name['"]\])/gi
  let d
  while((d=direct.exec(content))) out.push({kind:'direct',variable:null,expr:d[0],line:lineNo(content,d.index)})
  return out.slice(0,40)
}

function sinkPatterns(candidate){
  const patterns=[]
  const v=candidate.variable?reEscape(candidate.variable):null
  const expr=reEscape(candidate.expr)
  if(v){
    patterns.push(
      new RegExp(`(?:call_tool|callTool|invoke_tool|invokeTool|execute_tool|executeTool|run_tool|runTool)\\s*\\(\\s*${v}\\b`,'i'),
      new RegExp(`getattr\\s*\\([^\\n]{0,240},\\s*${v}\\s*[,)]`,'i'),
      new RegExp(`(?:available_functions|AVAILABLE_FUNCTIONS|registry|tools?|handlers?|actions?|functions?)\\s*(?:\\.get\\s*\\(\\s*${v}\\s*\\)|\\[\\s*${v}\\s*\\])`,'i')
    )
  }
  if(candidate.kind==='loop_item' && v){
    patterns.push(
      new RegExp(`(?:session\\.)?(?:call_tool|callTool)\\s*\\(\\s*${v}(?:\\.function)?\\.(?:name|tool_name|toolName)\\b`,'i'),
      new RegExp(`getattr\\s*\\([^\\n]{0,240},\\s*${v}(?:\\.function)?\\.(?:name|tool_name|toolName)`,'i'),
      new RegExp(`(?:available_functions|AVAILABLE_FUNCTIONS|registry|tools?|handlers?|actions?|functions?)\\s*\\[\\s*${v}(?:\\.function)?\\.(?:name|tool_name|toolName)\\s*\\]`,'i')
    )
  }
  patterns.push(
    new RegExp(`(?:session\\.)?(?:call_tool|callTool)\\s*\\(\\s*${expr}`,'i'),
    new RegExp(`getattr\\s*\\([^\\n]{0,240},\\s*${expr}`,'i'),
    new RegExp(`(?:available_functions|AVAILABLE_FUNCTIONS|registry|tools?|handlers?|actions?|functions?)\\s*\\[\\s*${expr}\\s*\\]`,'i')
  )
  return patterns
}

function findForwardSink(content,candidate){
  const start=offsetForLine(content,candidate.line)
  const tail=content.slice(start)
  let best=null
  for(const re of sinkPatterns(candidate)){
    const m=re.exec(tail)
    if(!m) continue
    const abs=start+m.index
    if(!best || abs<best.offset) best={offset:abs,line:lineNo(content,abs),snippet:m[0].slice(0,500)}
  }
  return best
}

function localControlBetween(content,fromLine,toLine){
  const rs=rows(content)
  const lo=Math.max(0,Math.min(fromLine,toLine)-2)
  const hi=Math.min(rs.length,Math.max(fromLine,toLine)+2)
  return CONTROL_RE.test(rs.slice(lo,hi).join('\n'))
}

function effectEvidence(content){
  const out=[]
  rows(content).forEach((r,i)=>{ if(EFFECT_RE.test(r)) out.push({line:i+1,text:r.trim().slice(0,260)}); EFFECT_RE.lastIndex=0 })
  return out.slice(0,16)
}

export function analyzeFile(path,content,meta={}){
  const role=detectRole(path,content,meta)
  if(role==='nonproduction') return {path,role,selectorFlows:[],effects:[],controls:[]}
  const flows=[]
  for(const candidate of selectorCandidates(content)){
    const sink=findForwardSink(content,candidate)
    if(!sink) continue
    const localAuthorityControl=localControlBetween(content,candidate.line,sink.line)
    flows.push({selectorKind:candidate.kind,selectorLine:candidate.line,selectorExpr:candidate.expr.slice(0,240),selectorVariable:candidate.variable||null,selectorSource:candidate.source||null,sinkLine:sink.line,sinkSnippet:sink.snippet,localAuthorityControl})
  }
  const controls=[]
  rows(content).forEach((r,i)=>{ if(CONTROL_RE.test(r)) controls.push(i+1); CONTROL_RE.lastIndex=0 })
  return {path,role,selectorFlows:flows.slice(0,16),effects:effectEvidence(content),controls:controls.slice(0,16)}
}

export function buildProspectSecuritySignalV2(snapshot,{repository=null,segment=null,description=null}={}){
  const files=Object.entries(snapshot?.files||{}).map(([path,content])=>analyzeFile(path,content,{segment,description}))
  const production=files.filter(f=>f.role!=='nonproduction')
  const allFlows=production.flatMap(f=>f.selectorFlows.map(flow=>({...flow,path:f.path,role:f.role})))
  const executableFlows=allFlows.filter(f=>f.role!=='model_adapter')
  const adapterFlows=allFlows.filter(f=>f.role==='model_adapter')
  const unguarded=executableFlows.filter(f=>!f.localAuthorityControl)
  const guarded=executableFlows.filter(f=>f.localAuthorityControl)
  const effects=production.flatMap(f=>f.effects.map(e=>({...e,path:f.path,role:f.role}))).filter(e=>e.role!=='model_adapter')
  const frameworkLike=production.some(f=>f.role==='framework') || FRAMEWORK_HINT.test(String(segment||''))

  let classification='NO_ACTIONABLE_SIGNAL',priority=0,rationale='No selector-controlled consequential effect path was proven in the bounded public-source snapshot.'
  if(unguarded.length && !frameworkLike){
    classification='PROOF_GAP'; priority=96
    rationale='A model-selected tool/action identifier appears to control a real invocation sink, and no approval/authorization/allowlist control was observed between selector and sink in that path.'
  }else if(unguarded.length && frameworkLike){
    classification='REVIEW_SIGNAL'; priority=72
    rationale='A selector-controlled dispatch path is visible in a framework/SDK surface. Authorization may intentionally be delegated to the application/tool implementation, so human architecture review is required.'
  }else if(guarded.length){
    classification='REVIEW_SIGNAL'; priority=70
    rationale='A selector-controlled dispatch path is visible together with a local authority-control signal. Runtime enforcement and bypass resistance remain unproven.'
  }else if(adapterFlows.length && !executableFlows.length){
    classification='NO_ACTIONABLE_SIGNAL'; priority=0
    rationale='Tool-selection data is present only in model/provider adapter code; no selector-controlled business/tool effect sink was proven.'
  }else if(effects.length){
    classification='ARCHITECTURE_UNCERTAIN'; priority=30
    rationale='Consequential effect code exists, but the bounded analysis did not prove that a model-selected identifier controls the effect sink.'
  }

  return {
    version:PROSPECT_V2_VERSION,
    repository:repository||snapshot?.repository_url||null,
    revision:snapshot?.revision||null,
    filesScanned:Object.keys(snapshot?.files||{}).length,
    classification,priority,rationale,
    evidence:{selectorFlows:executableFlows.slice(0,16),adapterFlows:adapterFlows.slice(0,8),effects:effects.slice(0,16)},
    reviewRequired:['PROOF_GAP','REVIEW_SIGNAL'].includes(classification),
    truthBoundary:'Passive public-source static analysis only. This does not execute the target, test production, prove exploitability, or confirm a vulnerability. A PROOF_GAP means the observed source path deserves owned-environment validation.'
  }
}

export function precisionMetrics(items){
  const reviewed=items.filter(x=>['TRUE_SIGNAL','FALSE_POSITIVE','UNCERTAIN'].includes(x.humanLabel))
  const predicted=reviewed.filter(x=>x.signal?.classification==='PROOF_GAP')
  const tp=predicted.filter(x=>x.humanLabel==='TRUE_SIGNAL').length
  const fp=predicted.filter(x=>x.humanLabel==='FALSE_POSITIVE').length
  return {reviewed:reviewed.length,predictedProofGaps:predicted.length,truePositives:tp,falsePositives:fp,precision:(tp+fp)?tp/(tp+fp):null}
}
