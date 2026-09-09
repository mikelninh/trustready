import { buildProspectSecuritySignalV2 as baseBuild } from './engine-v2.mjs'

export const PROSPECT_V21_VERSION = 'trustready-prospect-security-signal/v2.1'

const SKIP_PATH = /(^|\/)(?:__?tests?__?|integration[_-]?tests?|testdata|fixtures?|examples?|samples?|docs?|playgrounds?|benchmarks?|evals?|migrations?|node_modules|vendor)(\/|$)/i
const CONTROL_RE = /(?:human[_-]?approval|humanApproval|approval[_-]?required|approvalRequired|requires[_-]?approval|requiresApproval|approved[_-]?by|approvedBy|ToolApproved|ToolDenied|ApprovalRequired|authorize|authorization|permission|capability[_-]?check|capabilityCheck|policy[_-]?gate|policyGate|security[_-]?boundary|securityBoundary|allow[_-]?list|allowlist|allowed[_-]?(?:tools|actions|targets|domains)|allowed(?:Tools|Actions|Targets|Domains))/i

// High-confidence consequential tool/API semantics. Read-only search/retrieval/math/plotting intentionally do not match.
const CONSEQUENTIAL_NAME_RE = /(?:^|[_-])(?:send(?:_email|_message|_sms)?|reply_email|write|edit|delete|remove|create_file|write_file|edit_file|delete_file|install_package|execute|exec|shell|bash|run_command|publish|deploy|release|payment|pay|charge|refund|transfer|home_assistant|turn_on|turn_off|activate|deactivate)(?:$|[_-])/i
const CONSEQUENTIAL_CODE_RE = /(?:messages\(\)\.send\s*\(|messages\.send\s*\(|smtp\.|twilio\.|subprocess\.(?:run|call|check_call|Popen)\s*\(|os\.system\s*\(|shell\s*=\s*True|open\s*\([^\n]{0,160},\s*['\"](?:w|a|x|wb|ab)['\"]|\.write_text\s*\(|\.write_bytes\s*\(|os\.(?:remove|unlink|rename|replace)\s*\(|shutil\.(?:rmtree|move|copy)\s*\(|requests\.(?:post|put|patch|delete)\s*\(|httpx\.(?:post|put|patch|delete)\s*\(|axios\.(?:post|put|patch|delete)\s*\(|stripe\.|kubectl\s+(?:apply|delete)|terraform\s+apply|\.activate\s*\(|\.deactivate\s*\()/i

const FRAMEWORK_RE = /(?:framework|sdk|library|protocol|orchestrat|toolkit|runtime|calibration framework)/i

function lines(content, re) {
  const out=[]
  String(content||'').split('\n').forEach((row,i)=>{ if(re.test(row)) out.push({line:i+1,text:row.trim().slice(0,260)}); re.lastIndex=0 })
  return out
}

function consequenceEvidence(snapshot) {
  const out=[]
  for(const [path,content] of Object.entries(snapshot?.files||{})) {
    if(SKIP_PATH.test(path)) continue
    const rows=String(content||'').split('\n')
    rows.forEach((row,i)=>{
      const fn=/\b(?:async\s+def|def|function)\s+([A-Za-z_$][\w$]*)\b/.exec(row)
      const cls=/\bclass\s+([A-Za-z_$][\w$]*)\b/.exec(row)
      const symbol=(fn||cls)?.[1]
      if(symbol && CONSEQUENTIAL_NAME_RE.test(symbol)) out.push({path,line:i+1,kind:'consequential_symbol',symbol,text:row.trim().slice(0,260)})
      CONSEQUENTIAL_NAME_RE.lastIndex=0
      if(CONSEQUENTIAL_CODE_RE.test(row)) out.push({path,line:i+1,kind:'consequential_code',symbol:null,text:row.trim().slice(0,260)})
      CONSEQUENTIAL_CODE_RE.lastIndex=0
    })
    // File names like write_file_tool.py / bash_tool.py are useful when tool implementations are class-based.
    const fileBase=path.split('/').pop()?.replace(/\.[^.]+$/,'')||''
    if(CONSEQUENTIAL_NAME_RE.test(fileBase)) out.push({path,line:1,kind:'consequential_filename',symbol:fileBase,text:path})
    CONSEQUENTIAL_NAME_RE.lastIndex=0
  }
  const seen=new Set()
  return out.filter(x=>{ const k=`${x.path}:${x.line}:${x.kind}:${x.symbol||''}`; if(seen.has(k)) return false; seen.add(k); return true }).slice(0,40)
}

function mappingSelectorFlows(snapshot) {
  const flows=[]
  for(const [path,content] of Object.entries(snapshot?.files||{})) {
    if(SKIP_PATH.test(path)) continue
    const rows=String(content||'').split('\n')
    for(let i=0;i<rows.length;i++) {
      const row=rows[i]
      const assign=/\b([A-Za-z_$][\w$]*)\s*=\s*[^\n]*(?:tool_call|toolCall)[^\n]*\.function\.name/.exec(row)
      if(!assign) continue
      const variable=assign[1]
      const tail=rows.slice(i,Math.min(rows.length,i+18)).join('\n')
      const v=variable.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')
      const mapRe=new RegExp(`(?:self\\.)?(?:tool_mapping|tool_map|tool_fn_map|tools|handlers|actions|functions|available_functions|AVAILABLE_FUNCTIONS)\\s*(?:\\[\\s*${v}\\s*\\]|\\.get\\s*\\(\\s*${v}\\s*\\))`,'i')
      const m=mapRe.exec(tail)
      if(!m) continue
      const before=tail.slice(0,m.index+m[0].length)
      const localAuthorityControl=CONTROL_RE.test(before)
      flows.push({path,selectorLine:i+1,selectorExpr:row.trim().slice(0,240),selectorVariable:variable,sinkLine:i+1+before.split('\n').length-1,sinkSnippet:m[0],localAuthorityControl,selectorKind:'mapping_assignment_v21',role:'application'})
    }
  }
  return flows.slice(0,20)
}

export function buildProspectSecuritySignalV21(snapshot,{repository=null,segment=null,description=null}={}) {
  const base=baseBuild(snapshot,{repository,segment,description})
  const consequences=consequenceEvidence(snapshot)
  const mappingFlows=mappingSelectorFlows(snapshot)
  const frameworkLike=FRAMEWORK_RE.test(String(segment||''))

  const selectorFlows=[...(base.evidence?.selectorFlows||[])]
  const existingKeys=new Set(selectorFlows.map(f=>`${f.path}:${f.selectorLine}:${f.sinkLine}`))
  for(const f of mappingFlows) {
    const k=`${f.path}:${f.selectorLine}:${f.sinkLine}`
    if(!existingKeys.has(k)) selectorFlows.push(f)
  }

  const unguarded=selectorFlows.filter(f=>!f.localAuthorityControl)
  const guarded=selectorFlows.filter(f=>f.localAuthorityControl)
  const hasConsequentialSurface=consequences.length>0

  let classification=base.classification
  let priority=base.priority
  let rationale=base.rationale

  // Selector-controlled dispatch is necessary but not sufficient for a sales-grade proof gap.
  if(classification==='PROOF_GAP' && !hasConsequentialSurface) {
    classification='ARCHITECTURE_UNCERTAIN'
    priority=35
    rationale='A model-selected identifier controls a dispatch sink, but the reviewed repository snapshot did not expose a high-confidence consequential effect surface tied to this system. Read-only/demo dispatch is not a sales-grade proof gap.'
  }

  // Recover selector flows missed by v2 when a named tool mapping is used and a consequential surface is present.
  if(!frameworkLike && unguarded.length && hasConsequentialSurface && !['PROOF_GAP'].includes(classification)) {
    classification='PROOF_GAP'
    priority=97
    rationale='A model-selected tool identifier controls a dispatch mapping, the repository exposes a high-confidence consequential effect surface, and no independent authority gate was observed in the selector-to-dispatch path.'
  }

  // Frameworks remain review-only even when they bundle consequential tools.
  if(frameworkLike && unguarded.length && hasConsequentialSurface) {
    classification='REVIEW_SIGNAL'
    priority=Math.max(priority,74)
    rationale='A selector-controlled dispatch path and consequential tool surface are visible in a framework/runtime, but application-level authorization may be delegated. Human architecture review is required before any gap claim.'
  }

  if(guarded.length && classification==='PROOF_GAP') {
    classification='REVIEW_SIGNAL'
    priority=72
    rationale='A consequential selector-controlled dispatch path is visible together with a local authority-control signal; runtime enforcement still requires validation.'
  }

  return {
    ...base,
    version:PROSPECT_V21_VERSION,
    classification,priority,rationale,
    evidence:{
      ...(base.evidence||{}),
      selectorFlows:selectorFlows.slice(0,20),
      consequences,
      consequenceCoupled:hasConsequentialSurface && selectorFlows.length>0,
    },
    reviewRequired:['PROOF_GAP','REVIEW_SIGNAL'].includes(classification),
    truthBoundary:'Passive public-source static analysis only. This does not execute the target, test production, prove exploitability, or confirm a vulnerability. A PROOF_GAP means selector-controlled dispatch and a consequential effect surface were observed without an independently visible authority gate; owned-environment validation is still required.'
  }
}
