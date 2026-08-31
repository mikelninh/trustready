export const PLAN_CATALOG = Object.freeze({
  developer: Object.freeze({
    id: 'developer',
    name: 'TrustReady Developer',
    monthly_eur_cents: 4900,
    monthly_units: 500,
    description: 'API/MCP access, scan history, private repository scans with customer-supplied GitHub credentials, and evidence remediation packs.',
  }),
  team: Object.freeze({
    id: 'team',
    name: 'TrustReady Team',
    monthly_eur_cents: 24900,
    monthly_units: 5000,
    description: 'Higher-volume API/MCP usage for teams plus paid remediation workflows and procurement-readiness history.',
  }),
})

export const CAPABILITY_UNITS = Object.freeze({
  public_scan: 1,
  private_scan: 5,
  remediation_pack: 10,
})

const POINTS_PER_CONTROL = 5

const TEMPLATE_BY_CONTROL = Object.freeze({
  'TR-GOV-001': {
    path: 'SYSTEM_PURPOSE.md',
    content: `# System purpose\n\nPurpose: TODO describe the bounded system purpose.\n\nIntended users: TODO name the intended user groups.\n\nIntended workflow: TODO describe what the system does and where people remain responsible.\n\nNon-goals: TODO list uses this system is not designed for.\n`,
  },
  'TR-AI-001': {
    path: 'MODEL_VENDOR_INVENTORY.md',
    content: `# Model and provider inventory\n\n| Provider | Model | Version | Purpose | Data sent | Owner |\n| --- | --- | --- | --- | --- | --- |\n| TODO | TODO | TODO | TODO | TODO | TODO |\n\nReview cadence: TODO\n`,
  },
  'TR-AI-004': {
    path: 'LIMITATIONS.md',
    content: `# Known limitations and prohibited uses\n\n## Known limitations\n- TODO\n\n## Prohibited / non-goal uses\n- TODO\n\n## Human escalation\nTODO describe when a user must stop and escalate.\n`,
  },
  'TR-DATA-001': {
    path: 'DATA_FLOW.md',
    content: `# End-to-end data flow\n\nInput: TODO\n\nIngest / transformation: TODO\n\nStorage / persistence: TODO\n\nProcessors / model providers: TODO\n\nOutput: TODO\n\nRetention / deletion: TODO\n`,
  },
  'TR-DATA-002': {
    path: 'SUBPROCESSORS.md',
    content: `# Processors and subprocessors\n\n| Vendor / processor | Service | Purpose | Data categories | Region | DPA / terms | Owner |\n| --- | --- | --- | --- | --- | --- | --- |\n| TODO | TODO | TODO | TODO | TODO | TODO | TODO |\n\nLast reviewed: TODO\n`,
  },
  'TR-SEC-002': {
    path: 'SECURITY.md',
    content: `# Security and vulnerability reporting\n\nSecurity contact: TODO provide a monitored security contact.\n\nHow to report a vulnerability: TODO\n\nAcknowledgement target: TODO\n\nTriage and remediation process: TODO\n\nDisclosure / coordination process: TODO\n`,
  },
  'TR-BUY-001': {
    path: 'TRUST_CENTER.md',
    content: `# Trust Center\n\nThis page must cite current evidence and preserve unknowns.\n\n## Evidence\n- TODO link the relevant evidence sources and immutable revisions.\n\n## Unknown / not yet proven\n- TODO list unresolved controls exactly as TrustReady reports them.\n\n## Limitations\n- TODO\n\nDo not remove unresolved gaps to improve presentation.\n`,
  },
  'TR-BUY-002': {
    path: 'ASSURANCE_MANIFEST.json',
    content: `{"observed_at":"TODO","valid_until":"TODO","sha256":"TODO","note":"Template only. Replace placeholders with real evidence metadata before verification."}\n`,
  },
})

function satisfied(status) {
  return ['verified', 'attested', 'not_applicable'].includes(status)
}

export function buildRoadmap(scan, profile) {
  const resultById = new Map(scan.evaluation.results.map((item) => [item.control_id, item]))
  const gapById = new Map(scan.gaps.map((item) => [item.control_id, item]))
  const phases = [
    { id: 'build-evidence', title: 'Build missing evidence', lane: 'E1/E2', description: 'Complete dedicated documents, inventories, CI/eval proof and buyer evidence, then let the deterministic scanner verify them.', controls: [] },
    { id: 'human-attestation', title: 'Authorised human attestation', lane: 'E4', description: 'Organisational/legal claims that TrustReady must never self-attest.', controls: [] },
    { id: 'runtime-proof', title: 'Prove deployed behaviour', lane: 'E3', description: 'Environment-bound runtime tests and independent observations. Repository text cannot satisfy these.', controls: [] },
  ]

  const controls = profile.controls.map((control) => {
    const result = resultById.get(control.id)
    const gap = gapById.get(control.id)
    const isSatisfied = satisfied(result.status)
    const lane = control.attestation_only ? 'E4' : (control.require_independent || control.minimum_strength === 'E3' ? 'E3' : 'E1/E2')
    const row = {
      ...control,
      status: result.status,
      reason: result.reason,
      points: isSatisfied ? POINTS_PER_CONTROL : 0,
      potential_points: isSatisfied ? 0 : POINTS_PER_CONTROL,
      lane,
      next_proof: gap?.next_proof || null,
      remediation_lane: gap?.remediation_lane || 'none',
      evidence: gap?.evidence || [],
    }
    if (!isSatisfied) {
      const phase = lane === 'E4' ? phases[1] : lane === 'E3' ? phases[2] : phases[0]
      phase.controls.push(row)
    }
    return row
  })

  let cursor = scan.evaluation.score
  const path = phases.map((phase) => {
    const gain = phase.controls.length * POINTS_PER_CONTROL
    const from = cursor
    const to = Math.min(100, cursor + gain)
    cursor = to
    return { ...phase, from, to, gain }
  })

  return { controls, path }
}

export function publicScanShape(scan, profile) {
  const roadmap = buildRoadmap(scan, profile)
  return {
    schema: 'trustready-public-scan-api-v1',
    subject: scan.subject,
    profile: { id: profile.id, version: profile.version, title: profile.title },
    score: scan.evaluation.score,
    coverage_pct: scan.evaluation.coverage_pct,
    ready: scan.evaluation.ready,
    source_revision: scan.source_revision,
    observed_at: scan.observed_at,
    provenance_complete: scan.provenance_complete,
    blocking_findings: scan.evaluation.blocking_findings,
    controls: roadmap.controls,
    path_to_100: roadmap.path,
    boundary: scan.boundary,
  }
}

export function buildRemediationPack(scan, profile) {
  const roadmap = buildRoadmap(scan, profile)
  const unresolved = roadmap.controls.filter((control) => !satisfied(control.status))
  const files = []
  const tasks = []

  for (const control of unresolved) {
    if (control.lane === 'E4') {
      tasks.push({
        control_id: control.id,
        title: control.title,
        lane: 'E4',
        action: 'authenticated_attestation',
        required_proof: control.next_proof,
        score_effect: 'Only an authenticated, authorised attestation can satisfy this control.',
      })
      continue
    }

    if (control.lane === 'E3') {
      tasks.push({
        control_id: control.id,
        title: control.title,
        lane: 'E3',
        action: 'runtime_proof',
        required_proof: control.next_proof,
        score_effect: 'Repository text cannot satisfy this control; collect environment-bound runtime/independent evidence.',
      })
      continue
    }

    const template = TEMPLATE_BY_CONTROL[control.id]
    if (template) {
      files.push({
        control_id: control.id,
        title: control.title,
        path: template.path,
        content: template.content,
        verification_status: 'template_only',
        required_proof: control.next_proof,
        warning: 'This file intentionally contains placeholders. TrustReady scanner rules reject placeholder templates, so generating this file cannot increase the readiness score by itself.',
      })
    } else {
      tasks.push({
        control_id: control.id,
        title: control.title,
        lane: 'E1/E2',
        action: control.id === 'TR-OPS-002' ? 'implement_and_run_evaluations' : control.id === 'TR-SUPPLY-001' ? 'pin_and_record_dependencies' : 'complete_technical_evidence',
        required_proof: control.next_proof,
        score_effect: 'Requires real implementation evidence; TrustReady will not manufacture it.',
      })
    }
  }

  const templateControlIds = new Set(files.map((file) => file.control_id))
  const potentialAfterCompletedTemplates = Math.min(100, scan.evaluation.score + templateControlIds.size * POINTS_PER_CONTROL)

  return {
    schema: 'trustready-remediation-pack-v1',
    subject: scan.subject,
    profile: { id: profile.id, version: profile.version, title: profile.title },
    source_revision: scan.source_revision,
    score_before: scan.evaluation.score,
    template_files: files,
    proof_tasks: tasks,
    path_to_100: roadmap.path,
    scenario_if_every_template_is_truthfully_completed_and_verified: potentialAfterCompletedTemplates,
    invariant: 'Template generation never changes a score. Only a re-scan with accepted evidence or authorised attestation can do that.',
  }
}

export function compactScanHistory(scan, profile) {
  return {
    score: scan.evaluation.score,
    coverage_pct: scan.evaluation.coverage_pct,
    ready: scan.evaluation.ready,
    blocking_findings: scan.evaluation.blocking_findings,
    verified_controls: scan.evaluation.results.filter((item) => item.status === 'verified').map((item) => item.control_id),
    attested_controls: scan.evaluation.results.filter((item) => item.status === 'attested').map((item) => item.control_id),
    unresolved_controls: scan.evaluation.results.filter((item) => !satisfied(item.status)).map((item) => ({ control_id: item.control_id, status: item.status })),
    profile: { id: profile.id, version: profile.version },
    scanner_ruleset_version: scan.scanner_ruleset_version,
    provenance_complete: scan.provenance_complete,
  }
}
