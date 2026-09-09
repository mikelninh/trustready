export const PROSPECT_V2_VERSION = 'trustready-prospect-security-signal/v2'

const SKIP_PATH = /(^|\/)(?:__?tests?__?|integration[_-]?tests?|testdata|fixtures?|examples?|samples?|docs?|playgrounds?|benchmarks?|evals?|migrations?|node_modules|vendor)(\/|$)/i
const ADAPTER_PATH = /(^|\/)(?:llm|llms|models?|providers?|serializers?|parsers?|normalizers?|backends?)(\/|$)/i
const FRAMEWORK_HINT = /(?:sdk|framework|library|orchestrat|toolkit|runtime|protocol)/i

const CONTROL_RE = /(?:human[_-]?approval|humanApproval|approval[_-]?required|approvalRequired|requires[_-]?approval|requiresApproval|approved[_-]?by|approvedBy|ToolApproved|ToolDenied|ApprovalRequired|authorize|authorization|permission|capability[_-]?check|capabilityCheck|policy[_-]?gate|policyGate|security[_-]?boundary|securityBoundary|allow[_-]?list|allowlist|allowed[_-]?(?:tools|actions|targets|domains)|allowed(?:Tools|Actions|Targets|Domains))/i
const EFFECT_RE = /(?:send[_-]?(?:email|message|sms)|messages\.create|smtp\.|twilio\.|slack[^\n]{0,100}\.post|requests\.(?:post|put|patch|delete)|httpx\.(?:post|put|patch|delete)|axios\.(?:post|put|patch|delete)|fetch\s*\(|subprocess\.|os\.system|child_process|spawn\s*\(|exec(?:File)?\s*\(|\.insert\s*\(|\.update\s*\(|\.delete\s*\(|\.save\s*\(|session\.call_tool\s*\(|call_tool\s*\(|invoke_tool\s*\(|execute_tool\s*\()/i

const MODEL_SELECTOR_RE = /(?:tool[_]?call|toolCall|function[_]?call|functionCall|message\.tool_calls|message\.toolCalls|choice\.message\.tool_calls|choice\.message\.toolCalls)/i
const SELECTOR_PROP_RE = /(?:\.function\.name|\.tool_name|\.toolName|\.name|\[['"]name['"]\]|\.function\[['"]name['"]\])/i
const ARG_PROP_RE = /(?:\.function\.arguments|\.arguments|\.args|\.input|\[['"]arguments['"]\])/i

function rows(content){ return String(content||'').split('\n') }
function lineNo(content, offset){ return String(content||'').slice(0,offset).split('\n').length }
function cleanVar(v){ return String(v||'').replace(/[^A-Za-z0-9_$]/g,'') }

function detectRole(path, content, repoMeta={}) {
  if(SKIP_PATH.test(path)) return 'nonproduction'
  if(ADAPTER_PATH.test(path) || /\b(?:serializer|provider adapter|model backend|chat completion wrapper|normalize tool calls)\b/i.test(content)) return 'model_adapter'
  if(/(?:mcp|tool registry|registry|executor|engine|agent loop|dispatch)/i.test(path+' '+content.slice(0,1200))) return 'execution_layer'
  if(FRAMEWORK_HINT.test(String(repoMeta?.segment||'')) || FRAMEWORK_HINT.test(String(repoMeta?.description||''))) return 'framework'
  return 'application'
}

function selectorCandidates(content) {
  const out=[]
  const patterns=[
    /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]*(?:tool[_]?call|toolCall|function[_]?call|functionCall)[^;\n]*(?:\.function\.name|\.tool_name|\.toolName|\.name|\[['"]name['"]\]))/gi,
    /([A-Za-z_][\w]*)\s*=\s*([^\n]*(?:tool[_]?call|function[_]?call)[^\n]*(?:\.function\.name|\.tool_name|\.name|\[['"]name['"]\]))/gi,
  ]
  for(const re of patterns){
    let m
    while((m=re.exec(content))){ out.push({variable:cleanVar(m[1]),expr:m[2],line:lineNo(content,m.index)}) }
  }
  // Direct selector expressions without an intermediate variable.
  const direct=/(?:tool[_]?call|toolCall|function[_]?call|functionCall)[\w.\[\]'"?]*?(?:\.function\.name|\.tool_name|\.toolName|\[['"]name['"]\])/gi
  let d
  while((d=direct.exec(content))){ out.push({variable:null,expr:d[0],line:lineNo(content,d.index)}) }
  return out.slice(0,20)
}

function selectorControlsSink(content, candidate) {
  const escaped = candidate.variable ? candidate.variable.replace(/[.*+?^${}()|[\]\\]/g,'\\$&') : null
  const expr = candidate.expr.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')
  const sinkPatterns=[]
  if(escaped){
    sinkPatterns.push(
      new RegExp(`(?:registry|tools?|handlers?|actions?|functions?)\\s*\\[\\s*${escaped}\\s*\\][\\s\\S]{0,400}(?:\\(|invoke|execute|run|call)`, 'i'),
      new RegExp(`getattr\\s*\\([^\\n]{0,220},\\s*${escaped}\\s*[,)]\\s*[\\s\\S]{0,500}(?:await\\s+)?[A-Za-z_][\\w]*\\s*\\(`,'i'),
      new RegExp(`(?:call_tool|callTool|invoke_tool|invokeTool|execute_tool|executeTool|run_tool|runTool)\\s*\\(\\s*${escaped}\\b`,'i'),
      new RegExp(`(?:handler|tool|action|fn|func)\\s*=\\s*(?:registry|tools?|handlers?|actions?|functions?)\\s*\\[\\s*${escaped}\\s*\\][\\s\\S]{0,500}(?:handler|tool|action|fn|func)\\s*\\(`,'i'),
    )
  }
  sinkPatterns.push(
    new RegExp(`(?:session\\.)?(?:call_tool|callTool)\\s*\\(\\s*${expr}`,'i'),
    new RegExp(`getattr\\s*\\([^\\n]{0,220},\\s*${expr}`,'i'),
  )
  for(const re of sinkPatterns){
    const m=re.exec(content)
    if(m) return {matched:true,line:lineNo(content,m.index),snippet:m[0].slice(0,500)}
  }
  return {matched:false}
}

function localControlBetween(content, fromLine, toLine) {
  const rs=rows(content)
  const lo=Math.max(0,Math.min(fromLine,toLine)-4)
  const hi=Math.min(rs.length,Math.max(fromLine,toLine)+2)
  const window=rs.slice(lo,hi).join('\n')
  return CONTROL_RE.test(window)
}

function effectEvidence(content){
  const out=[]
  let offset=0
  for(const row of rows(content)){
    if(EFFECT_RE.test(row)) out.push({line:lineNo(content,offset),text:row.trim().slice(0,260)})
    EFFECT_RE.lastIndex=0
    offset += row.length+1
  }
  return out.slice(0,12)
}

export function analyzeFile(path, content, repoMeta={}) {
  const role=detectRole(path,content,repoMeta)
  if(role==='nonproduction') return {path,role,selectorFlows:[],effects:[],controls:[]}
  const selectors=selectorCandidates(content)
  const flows=[]
  for(const candidate of selectors){
    const sink=selectorControlsSink(content,candidate)
    if(!sink.matched) continue
    const localControl=localControlBetween(content,candidate.line,sink.line)
    flows.push({selectorLine:candidate.line,selectorExpr:candidate.expr.slice(0,240),selectorVariable:candidate.variable,sinkLine:sink.line,sinkSnippet:sink.snippet,localAuthorityControl:localControl})
  }
  const controls=[]
  rows(content).forEach((r,i)=>{ if(CONTROL_RE.test(r)) controls.push(i+1); CONTROL_RE.lastIndex=0 })
  return {path,role,selectorFlows:flows.slice(0,10),effects:effectEvidence(content),controls:controls.slice(0,12)}
}

export function buildProspectSecuritySignalV2(snapshot,{repository=null,segment=null,description=null}={}) {
  const files=[]
  for(const [path,content] of Object.entries(snapshot?.files||{})) files.push(analyzeFile(path,content,{segment,description}))
  const production=files.filter(f=>f.role!=='nonproduction')
  const selectorFlows=production.flatMap(f=>f.selectorFlows.map(flow=>({...flow,path:f.path,role:f.role})))
  const executableFlows=selectorFlows.filter(f=>f.role!=='model_adapter')
  const unguarded=executableFlows.filter(f=>!f.localAuthorityControl)
  const guarded=executableFlows.filter(f=>f.localAuthorityControl)
  const effects=production.flatMap(f=>f.effects.map(e=>({...e,path:f.path,role:f.role}))).filter(e=>e.role!=='model_adapter')
  const adapterOnly=selectorFlows.length>0 && executableFlows.length===0
  const frameworkLike=production.some(f=>f.role==='framework') || /framework|sdk|library|protocol|orchestrat/i.test(String(segment||''))

  let classification='NO_ACTIONABLE_SIGNAL', priority=0, rationale='No selector-controlled consequential effect path was proven in the bounded public-source snapshot.'
  if(unguarded.length && !frameworkLike){
    classification='PROOF_GAP'; priority=96
    rationale='A model-selected tool/action identifier appears to control a real invocation sink, and no approval/authorization/allowlist control was observed between selector and sink in that path.'
  } else if(unguarded.length && frameworkLike){
    classification='REVIEW_SIGNAL'; priority=72
    rationale='A selector-controlled dispatch path is visible in a framework/SDK surface. That may be intentional delegation to application-level authorization, so human architecture review is required before treating it as a commercial security gap.'
  } else if(guarded.length){
    classification='REVIEW_SIGNAL'; priority=70
    rationale='A selector-controlled dispatch path is visible together with a local authority-control signal. Runtime enforcement and bypass resistance remain unproven.'
  } else if(adapterOnly){
    classification='NO_ACTIONABLE_SIGNAL'; priority=0
    rationale='Tool-selection data is present only in model/provider adapter code; no selector-controlled business/tool effect sink was proven.'
  } else if(effects.length){
    classification='ARCHITECTURE_UNCERTAIN'; priority=30
    rationale='Consequential effect code exists, but the bounded analysis did not prove that a model-selected identifier controls the effect sink.'
  }

  return {
    version:PROSPECT_V2_VERSION,
    repository:repository||snapshot?.repository_url||null,
    revision:snapshot?.revision||null,
    filesScanned:Object.keys(snapshot?.files||{}).length,
    classification,priority,rationale,
    evidence:{selectorFlows:executableFlows.slice(0,12),adapterFlows:selectorFlows.filter(f=>f.role==='model_adapter').slice(0,8),effects:effects.slice(0,16)},
    reviewRequired:['PROOF_GAP','REVIEW_SIGNAL'].includes(classification),
    truthBoundary:'Passive public-source static analysis only. This does not execute the target, test production, prove exploitability, or confirm a vulnerability. A PROOF_GAP means the observed source path deserves owned-environment validation.'
  }
}

export function precisionMetrics(rows){
  const reviewed=rows.filter(x=>['TRUE_SIGNAL','FALSE_POSITIVE','UNCERTAIN'].includes(x.humanLabel))
  const predicted=reviewed.filter(x=>x.signal?.classification==='PROOF_GAP')
  const tp=predicted.filter(x=>x.humanLabel==='TRUE_SIGNAL').length
  const fp=predicted.filter(x=>x.humanLabel==='FALSE_POSITIVE').length
  return {reviewed:reviewed.length,predictedProofGaps:predicted.length,truePositives:tp,falsePositives:fp,precision:(tp+fp)?tp/(tp+fp):null}
}
