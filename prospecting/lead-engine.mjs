export const PROSPECT_SIGNAL_VERSION = 'trustready-prospect-security-signal/v1'

const EFFECT_PATTERNS = [
  ['shell_or_process', /child_process|spawn\s*\(|exec(File)?\s*\(|subprocess\.|os\.system\s*\(|shell\s*=\s*true/i],
  ['browser_or_ui_action', /click\s*\(|page\.goto\s*\(|navigate\s*\(|browser\.(click|type)|computer[_ -]?use/i],
  ['outbound_message', /send[_ -]?(email|message|sms)\s*\(|smtp\.|twilio\.|slack[^\n]{0,120}\.post\s*\(|messages\.create\s*\(/i],
  ['database_or_record_write', /(?:db|database|collection|table|record|client)[A-Za-z0-9_\.]*\.(insert|update|delete|save)\s*\(|\bINSERT\s+INTO\b|\bUPDATE\s+[A-Za-z0-9_]+\s+SET\b|\bDELETE\s+FROM\b/i],
  ['external_http', /requests\.(post|put|patch|delete)\s*\(|httpx\.(post|put|patch|delete)\s*\(|axios\.(post|put|patch|delete)\s*\(|fetch\s*\([^\n]{0,180}method\s*:\s*['\"](?:POST|PUT|PATCH|DELETE)['\"]/i],
  ['deployment_or_publish', /(?:deploy|publish|release)\s*\(|kubectl\s+(apply|delete)|terraform\s+apply|vercel\s+deploy|git\s+push/i],
  ['payment_or_transfer', /stripe\.|checkout\.sessions|payment[_ -]?intent|charge\.create|refund\s*\(|transfer\s*\(/i],
]

const AGENT_PATTERNS = [
  /tool_calls|tool_choice|function_call/i,
  /agent[_ -]?(loop|executor|runner)|run[_ -]?agent/i,
  /mcp\.tool|FastMCP|ModelContextProtocol/i,
  /openai|anthropic|gemini|litellm|llm/i,
]

const BOUNDARY_PATTERNS = [
  ['approval', /human[_ -]?approval|approval_required|requires[_ -]?approval|approved_by|confirm[_ -]?before/i],
  ['authorization', /authorize|authorization|permission|capability[_ -]?check|policy[_ -]?gate|security[_ -]?boundary/i],
  ['tenant_scope', /tenant[_ -]?id|organization[_ -]?id|org[_ -]?id|workspace[_ -]?id/i],
  ['allowlist', /allowlist|allow_list|allowed[_ -]?(domains|tools|actions|targets)/i],
  ['execution_budget', /max[_ -]?(tool|step|iteration)|tool[_ -]?budget|timeout|rate[_ -]?limit/i],
  ['audit', /audit|trace[_ -]?id|event[_ -]?log|tool[_ -]?trace/i],
]

const DIRECT_DISPATCH_PATTERNS = [
  /message\.tool_calls[\s\S]{0,2200}session\.call_tool\s*\(/i,
  /message\.tool_calls[\s\S]{0,2200}getattr\([^\n]+tool\.name[\s\S]{0,900}(?:await\s+)?func\s*\(/i,
  /tool_calls[\s\S]{0,2200}(?:execute_tool|invoke_tool|call_tool|callTool|run_tool|runTool)\s*\(/i,
  /tool_choice[\s\S]{0,1800}(?:handler|tool|action)[A-Za-z0-9_\.\[\]'\"]*[\s\S]{0,500}\(/i,
]

const FALSE_POSITIVE_PATH = /(^|\/)(__?tests?__?|testdata|fixtures?|examples?|samples?|docs?|playgrounds?|benchmarks?|evals?|migrations?|node_modules|vendor)(\/|$)/i

function lines(content, regex) {
  const out=[]
  const rows=String(content||'').split('\n')
  rows.forEach((row,i)=>{ if(regex.test(row)) out.push(i+1); regex.lastIndex=0 })
  return out.slice(0,6)
}

function evidenceFor(files, patterns, { skipTestPaths=true }={}) {
  const hits=[]
  for (const [path,content] of Object.entries(files||{})) {
    if(skipTestPaths && FALSE_POSITIVE_PATH.test(path)) continue
    for (const [id,regex] of patterns) {
      const ls=lines(content,regex)
      if(ls.length) hits.push({id,path,lines:ls})
    }
  }
  return hits
}

function agentEvidence(files) {
  const hits=[]
  for (const [path,content] of Object.entries(files||{})) {
    if(FALSE_POSITIVE_PATH.test(path)) continue
    const matched=AGENT_PATTERNS.filter(r=>r.test(content)).length
    if(matched>=2) hits.push({path,signals:matched})
  }
  return hits
}

function directDispatchEvidence(files) {
  const hits=[]
  for (const [path,content] of Object.entries(files||{})) {
    if(FALSE_POSITIVE_PATH.test(path)) continue
    const direct=DIRECT_DISPATCH_PATTERNS.some(r=>r.test(content))
    if(!direct) continue
    const localControls=BOUNDARY_PATTERNS.filter(([,r])=>r.test(content)).map(([id])=>id)
    const modelLines=lines(content,/tool_calls|tool_choice|function_call/i)
    const sinkLines=lines(content,/session\.call_tool\s*\(|execute_tool\s*\(|invoke_tool\s*\(|call_tool\s*\(|getattr\([^\n]+tool\.name|handler[^\n]{0,120}\(/i)
    hits.push({path,modelLines,sinkLines,localControls})
  }
  return hits
}

function uniq(values){ return [...new Set(values)] }

export function buildProspectSecuritySignal(snapshot,{repository=null}={}) {
  const effects=evidenceFor(snapshot?.files,EFFECT_PATTERNS)
  const controls=evidenceFor(snapshot?.files,BOUNDARY_PATTERNS)
  const agents=agentEvidence(snapshot?.files)
  const directDispatch=directDispatchEvidence(snapshot?.files)
  const directWithoutLocalBoundary=directDispatch.filter(x=>!x.localControls.some(c=>['approval','authorization','allowlist'].includes(c)))
  const effectClasses=uniq(effects.map(x=>x.id))
  const controlClasses=uniq(controls.map(x=>x.id))
  const consequential=effectClasses.filter(x=>x!=='browser_or_ui_action' || agents.length>0)
  const hasAgent=agents.length>0
  const hasEffect=consequential.length>0
  const independentControl=controlClasses.some(x=>['approval','authorization','allowlist'].includes(x))

  let classification='NO_ACTIONABLE_SIGNAL'
  let priority=0
  let rationale='No agent-linked consequential effect surface was observed in the bounded source snapshot.'
  if(directWithoutLocalBoundary.length){
    classification='PROOF_GAP'
    priority=95
    rationale='A same-file source path appears to consume model-selected tool calls and dispatch them to a tool/handler sink without an independently observable approval/authorization/allowlist check in that dispatch path. Runtime controls may still exist elsewhere and must be validated.'
  } else if(directDispatch.length){
    classification='REVIEW_SIGNAL'
    priority=68
    rationale='A same-file model-to-tool dispatch path is visible together with a local approval/authorization/allowlist signal. The control appears relevant, but runtime enforcement and bypass resistance still require validation.'
  } else if(hasAgent && hasEffect && !independentControl){
    classification='PROOF_GAP'
    priority=70 + Math.min(20, consequential.length*4)
    rationale='Agent/LLM code and consequential effect signals are present, but the bounded public snapshot did not expose an independently enforceable approval/authorization/allowlist control.'
  } else if(hasAgent && hasEffect && independentControl){
    classification='REVIEW_SIGNAL'
    priority=45 + Math.min(20, consequential.length*3)
    rationale='Agent-linked consequential effects and some control signals are both present. Runtime reachability and enforcement still require validation before any vulnerability claim.'
  } else if(hasEffect){
    classification='ARCHITECTURE_UNCERTAIN'
    priority=25
    rationale='Consequential effect code is present, but the bounded snapshot did not confidently establish an agent-controlled path.'
  }

  const publicEvidence={
    directDispatch:directDispatch.slice(0,8),
    agentFiles:agents.slice(0,8),
    effects:effects.slice(0,16),
    controls:controls.slice(0,16),
  }
  const potentialConsequences=[]
  if(effectClasses.includes('database_or_record_write')) potentialConsequences.push('unauthorized data mutation or record-integrity loss')
  if(effectClasses.includes('outbound_message')) potentialConsequences.push('unauthorized customer/user communication')
  if(effectClasses.includes('external_http')) potentialConsequences.push('unintended external side effects or data egress')
  if(effectClasses.includes('shell_or_process')) potentialConsequences.push('model-influenced local process execution')
  if(effectClasses.includes('deployment_or_publish')) potentialConsequences.push('unapproved publication or deployment effects')
  if(effectClasses.includes('payment_or_transfer')) potentialConsequences.push('unauthorized financial effects')
  if(effectClasses.includes('browser_or_ui_action')) potentialConsequences.push('unintended actions in authenticated browser sessions')
  if(directWithoutLocalBoundary.length && !potentialConsequences.length) potentialConsequences.push('a model-selected tool call reaching a real handler effect without a separately observed dispatch-time authority check')

  const outreachAllowed=['PROOF_GAP','REVIEW_SIGNAL'].includes(classification)
  return {
    version:PROSPECT_SIGNAL_VERSION,
    repository:repository||snapshot?.repository_url||null,
    revision:snapshot?.revision||null,
    filesScanned:Object.keys(snapshot?.files||{}).length,
    classification,
    priority,
    rationale,
    observed:{hasAgent,effectClasses,controlClasses,directDispatchPaths:directDispatch.map(x=>x.path)},
    potentialConsequences,
    publicEvidence,
    outreach:{
      allowed:outreachAllowed,
      claim:'public_source_security_signal_only',
      recommendedCTA:classification==='PROOF_GAP'?'offer_owned_ci_validation':outreachAllowed?'offer_short_architecture_validation':'do_not_outreach',
    },
    truthBoundary:'This is passive public-source analysis. It does not execute the target, test production, prove exploitability, or establish that the repository is vulnerable. Missing public evidence is a proof gap, not proof that a control is absent at runtime.'
  }
}

export function draftSecuritySignalMessage(signal,{name='there'}={}) {
  if(!signal?.outreach?.allowed) return null
  const repo=signal.repository||'your repository'
  const direct=(signal.publicEvidence?.directDispatch||[])[0]
  const effects=(signal.observed?.effectClasses||[]).slice(0,3).join(', ')
  const controls=(signal.observed?.controlClasses||[]).join(', ')
  const directHasBoundary=direct?.localControls?.some(c=>['approval','authorization','allowlist'].includes(c))
  const directSentence=direct
    ? directHasBoundary
      ? `The strongest source signal is in ${direct.path}: model-selected tool calls appear to flow to a tool/handler dispatch sink, with a local control signal (${direct.localControls.join(', ')}) that is worth validating for runtime enforcement.`
      : `The strongest source signal is in ${direct.path}: model-selected tool calls appear to flow to a tool/handler dispatch sink; I could not verify an independent approval/authorization/allowlist check in that same dispatch path.`
    : `The observed effect surface includes ${effects}.`
  const controlSentence=controls?`I also saw control signals elsewhere in the repository (${controls}), so I am not treating this as a vulnerability claim.`:'I did not observe a repository-level approval/authorization/allowlist signal in the bounded snapshot.'
  return `Hi ${name},\n\nI ran a passive TrustReady source review on ${repo}. ${directSentence} ${controlSentence}\n\nThis is intentionally a source-level security signal, not a claim that the system is exploitable. The useful next step is to replay the path safely in infrastructure you own and measure whether an unauthorized model/tool proposal can actually reach the effect sink.\n\nIf useful, I can do that as a fixed-scope Security Delta validation: same named attack inputs before/after the boundary, benign-regression checks, and a CI gate if we confirm something actionable.\n\nPotential impact if the path is insufficiently bounded: ${(signal.potentialConsequences||[]).slice(0,2).join('; ') || 'unintended real-world effects'}.\n\nWould a 20-minute technical check be useful?\n\nMichael\nTrustReady`
}
