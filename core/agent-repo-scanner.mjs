export const AGENT_REPO_SCANNER_VERSION = 'agent-repo-source-preflight/v1'

const CODE_EXT = /\.(py|js|mjs|cjs|ts|tsx)$/i
const IGNORE_PATH = /(^|\/)(tests?|migrations?|alembic|scripts|benchmarks?|evals?)(\/|$)/i
const pathNorm = (value) => String(value ?? '').replaceAll('\\', '/')

function lineOf(content, needle) {
  const index = content.indexOf(needle)
  return index < 0 ? null : content.slice(0, index).split('\n').length
}

function inferRisk(name, nearby = '') {
  const lower = String(name ?? '').toLowerCase()
  const text = String(nearby ?? '').toLowerCase()
  if (/(delete|destroy|transfer|payment|refund|submit|send|publish|deploy|execute|write|update|create)/.test(lower)) {
    return { risk: 'consequential', external: /(send|submit|publish|deploy|transfer|payment|refund)/.test(lower) || /https?:\/\//.test(text) }
  }
  if (/archive/.test(lower)) return { risk: 'read', external: true, effectClass: 'bounded_external' }
  if (/(read|get|list|check|detect|classify|determine|generate|draft|build|search|lookup)/.test(lower)) return { risk: 'read', external: false }
  return { risk: 'unknown', external: /requests\.|httpx\.|fetch\(|axios|https?:\/\//.test(text) }
}

function resolvePythonModule(paths, moduleName) {
  const suffixes = [`${moduleName.replaceAll('.', '/')}.py`, `${moduleName.replaceAll('.', '/')}/__init__.py`]
  for (const suffix of suffixes) {
    const matches = paths.filter((path) => path === suffix || path.endsWith(`/${suffix}`))
    if (matches.length === 1) return matches[0]
  }
  return null
}

function pythonEdges(source, content, paths) {
  const edges = []
  for (const match of content.matchAll(/^\s*from\s+([A-Za-z0-9_.]+)\s+import\s+([^#\n]+)/gm)) {
    const base = match[1]
    const names = match[2].split(',').map((part) => part.trim().split(/\s+as\s+/)[0]).filter(Boolean)
    const baseTarget = resolvePythonModule(paths, base)
    if (baseTarget) edges.push({ from: source, to: baseTarget, relation: 'imports' })
    for (const name of names) {
      const child = resolvePythonModule(paths, `${base}.${name}`)
      if (child) edges.push({ from: source, to: child, relation: 'imports' })
    }
  }
  for (const match of content.matchAll(/^\s*import\s+([A-Za-z0-9_.]+)/gm)) {
    const target = resolvePythonModule(paths, match[1])
    if (target) edges.push({ from: source, to: target, relation: 'imports' })
  }
  return edges
}

function resolveJsImport(source, specifier, paths) {
  if (!specifier.startsWith('.')) return null
  const sourceParts = source.split('/')
  sourceParts.pop()
  for (const part of specifier.split('/')) {
    if (!part || part === '.') continue
    if (part === '..') sourceParts.pop()
    else sourceParts.push(part)
  }
  const base = sourceParts.join('/')
  return [base, `${base}.js`, `${base}.mjs`, `${base}.cjs`, `${base}.ts`, `${base}.tsx`, `${base}/index.js`, `${base}/index.ts`].find((candidate) => paths.includes(candidate)) ?? null
}

function jsEdges(source, content, paths) {
  const edges = []
  for (const match of content.matchAll(/(?:from\s+|import\s*\()\s*["']([^"']+)["']/g)) {
    const target = resolveJsImport(source, match[1], paths)
    if (target) edges.push({ from: source, to: target, relation: 'imports' })
  }
  return edges
}

function reachableFrom(entrypoints, edges) {
  const adjacency = new Map()
  for (const edge of edges) {
    if (!adjacency.has(edge.from)) adjacency.set(edge.from, [])
    adjacency.get(edge.from).push(edge.to)
  }
  const seen = new Set(entrypoints)
  const queue = [...entrypoints]
  while (queue.length) {
    const current = queue.shift()
    for (const next of adjacency.get(current) ?? []) {
      if (seen.has(next)) continue
      seen.add(next)
      queue.push(next)
    }
  }
  return seen
}

function parseTools(path, content) {
  const tools = []
  for (const match of content.matchAll(/ToolDef\(\s*name\s*=\s*["']([^"']+)["']/gms)) {
    const nearby = content.slice(match.index ?? 0, (match.index ?? 0) + 1800)
    const inferred = inferRisk(match[1], nearby)
    tools.push({ id: match[1], name: match[1], provider: 'python_tooldef', source: path, ...inferred })
  }
  for (const match of content.matchAll(/@mcp\.tool\([^)]*\)\s*(?:@[^\n]+\s*)*(?:async\s+)?def\s+([A-Za-z0-9_]+)\s*\(/gms)) {
    const inferred = inferRisk(match[1], content.slice(match.index ?? 0, (match.index ?? 0) + 1200))
    tools.push({ id: `mcp:${match[1]}`, name: match[1], provider: 'mcp', source: path, ...inferred })
  }
  for (const match of content.matchAll(/(?:name|id)\s*:\s*["']([^"']+)["'][\s\S]{0,500}?risk\s*:\s*["'](read|write|consequential|irreversible)["']/g)) {
    const nearby = content.slice(match.index ?? 0, (match.index ?? 0) + 800)
    tools.push({ id: match[1], name: match[1], provider: 'declared_capability', source: path, risk: match[2], external: /external\s*:\s*true/.test(nearby) })
  }
  return tools
}

function attacksFor(tool, multiTenant) {
  const kinds = []
  const effectful = ['write', 'consequential', 'irreversible'].includes(tool.risk) || tool.external === true
  if (effectful) {
    kinds.push('untrusted_instruction_effect', 'hostile_tool_result', 'approval_bypass', 'parameter_tampering')
    if (multiTenant) kinds.push('cross_tenant_effect', 'confused_deputy')
  }
  if (tool.risk === 'read') kinds.push('protected_scope_exfiltration', 'sensitive_egress')
  return kinds
}

export function scanAgentRepositorySnapshot(snapshot) {
  const files = Object.entries(snapshot?.files ?? {}).filter(([path]) => CODE_EXT.test(path)).map(([path, content]) => [pathNorm(path), String(content ?? '')])
  const paths = files.map(([path]) => path)
  const agents = []
  const mcpServers = []
  const tools = []
  const edges = []
  const findings = []
  let deterministicBoundary = false
  let boundedExecution = false
  let auditTrail = false
  let explicitApproval = false
  let multiTenant = false
  let directExecutor = false

  for (const [path, content] of files) {
    const lowerPath = path.toLowerCase()
    const pathAgent = /(^|\/)(agents?|.*agent.*)\.(py|js|mjs|cjs|ts|tsx)$/.test(lowerPath) || /agent_loop/.test(lowerPath)
    const signals = [
      ['chat_with_tools', 'llm_tool_calling'], ['run_agent(', 'agent_loop'], ['runAgent(', 'agent_loop'], ['AgentGateway', 'agent_gateway'], ['tool_calls', 'tool_call_dispatch'],
    ].filter(([needle]) => content.includes(needle))
    const strong = signals.filter(([, kind]) => kind !== 'tool_call_dispatch')
    if (pathAgent && !IGNORE_PATH.test(path) && strong.length) {
      const framework = /agent[_-]?loop/.test(lowerPath.split('/').at(-1)) && !/system_prompt\s*=|SYSTEM_PROMPT\s*=/.test(content)
      agents.push({ path, kind: framework ? 'framework' : 'entrypoint', signals: signals.map(([, kind]) => kind) })
    }
    if (/FastMCP\s*\(|@mcp\.tool\(/.test(content)) mcpServers.push({ path, tools: [...content.matchAll(/@mcp\.tool\(/g)].length })
    tools.push(...parseTools(path, content))
    if (/\.py$/.test(path)) edges.push(...pythonEdges(path, content, paths))
    else edges.push(...jsEdges(path, content, paths))
    if (/trustready_authorize_tool_call|SecurityBoundary|security-boundary|makeSecurityContext|AgentGateway/.test(content)) deterministicBoundary = true
    if (/max_iterations|maxToolCalls|max_tool_calls|max_cost_usd|tool budget/i.test(content)) boundedExecution = true
    if (/ToolCallLog|audit|traceId|trace_id|tool_trace/.test(content)) auditTrail = true
    if (/approvalRequired|approval_required|approvedBy|approved_by|human[_ -]approval|requires_human_approval/i.test(content)) explicitApproval = true
    if (/multi[_ -]tenant|tenant_id|tenantId|organization_id|org_id/.test(content)) multiTenant = true
    const executor = content.match(/tool_def\.handler\s*\(|tool\.handler\s*\(|handler\s*\(args\)/)
    if (executor && /tool_calls|chat_with_tools|model/i.test(content)) {
      directExecutor = true
      findings.push({ kind: 'direct_model_to_tool_executor', path, line: lineOf(content, executor[0]) })
    }
  }

  const entrypoints = agents.filter((agent) => agent.kind === 'entrypoint')
  const frameworks = agents.filter((agent) => agent.kind === 'framework')
  const reachableSources = reachableFrom(entrypoints.map((agent) => agent.path), edges)
  const dedupTools = [...new Map(tools.map((tool) => [`${tool.source}:${tool.id}`, tool])).values()].map((tool) => ({ ...tool, reachable: reachableSources.has(tool.source) }))
  const reachableTools = dedupTools.filter((tool) => tool.reachable)
  const isolatedTools = dedupTools.filter((tool) => !tool.reachable)
  const isolatedMcpServers = mcpServers.filter((server) => !reachableSources.has(server.path))
  const reachableMcpServers = mcpServers.filter((server) => reachableSources.has(server.path))
  const unknownRisk = reachableTools.filter((tool) => tool.risk === 'unknown')
  const attackCases = reachableTools.flatMap((tool) => attacksFor(tool, multiTenant).map((kind) => ({ capabilityId: tool.id, kind })))
  const blockers = []
  if (entrypoints.length === 0) blockers.push('no_agent_entrypoint_detected')
  if (entrypoints.length > 1) blockers.push('multiple_agent_entrypoints_require_connected_reachability')
  if (entrypoints.length && reachableTools.length === 0) blockers.push('no_reachable_tool_surface_detected')
  if (unknownRisk.length) blockers.push('unknown_reachable_tool_risk')
  if (directExecutor && !deterministicBoundary) blockers.push('model_selected_executor_has_no_deterministic_boundary')
  if (directExecutor && !boundedExecution) blockers.push('model_tool_loop_has_no_observed_execution_budget')

  let decision = 'CONDITIONAL'
  if (blockers.length) decision = 'TECHNICAL_NO_GO'
  else if (entrypoints.length === 1 && directExecutor && deterministicBoundary && attackCases.length > 0) decision = 'SOURCE_PRECHECK_GO'

  return {
    version: AGENT_REPO_SCANNER_VERSION,
    assessmentKind: 'public_source_preflight',
    repository: { url: snapshot?.repository_url ?? null, revision: snapshot?.revision ?? null, filesScanned: files.length },
    topology: {
      entrypoints: entrypoints.map((agent) => agent.path),
      frameworks: frameworks.map((agent) => agent.path),
      mcpServers: mcpServers.map((server) => server.path),
      reachableMcpServers: reachableMcpServers.map((server) => server.path),
      isolatedMcpServers: isolatedMcpServers.map((server) => server.path),
      importEdges: edges.length,
    },
    controls: { deterministicBoundary, boundedExecution, auditTrail, explicitApproval, multiTenant, directModelToToolExecutor: directExecutor },
    tools: { discovered: dedupTools.length, reachable: reachableTools, isolated: isolatedTools, unknownReachableRisk: unknownRisk.map((tool) => tool.name) },
    attackPlan: { generated: attackCases.length, kinds: [...new Set(attackCases.map((item) => item.kind))], cases: attackCases },
    blockers,
    release: { decision, runtimeProofRequired: true, reason: decision === 'SOURCE_PRECHECK_GO' ? 'source_controls_observed_runtime_attack_retest_still_required' : decision === 'TECHNICAL_NO_GO' ? 'source_blockers_found' : 'source_evidence_insufficient_for_go_no_go' },
    remediation: { automaticCandidate: blockers.includes('model_selected_executor_has_no_deterministic_boundary') && entrypoints.length === 1 && findings.filter((item) => item.kind === 'direct_model_to_tool_executor').length === 1, suggested: blockers },
    truthBoundary: 'This is a public-source preflight, not runtime proof. SOURCE_PRECHECK_GO means the observed source shape is eligible for connected attack→effect→retest. Only the connected runner may issue TECHNICAL_GO.',
  }
}
