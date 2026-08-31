import { scanPublicGitHubInBrowser } from './browser-scan.mjs'

function controlSummary(scan, controlId) {
  const control = scan.controls.find((item) => item.id === controlId)
  if (!control) throw new Error(`Unknown control: ${controlId}`)
  return {
    subject: scan.subject,
    profile: scan.profile,
    score: scan.score,
    control: {
      id: control.id,
      title: control.title,
      status: control.status,
      blocking: control.blocking,
      lane: control.lane,
      reason: control.reason,
      next_proof: control.next_proof,
      evidence: control.evidence,
    },
    boundary: scan.boundary,
  }
}

async function registerWebMcp() {
  if (!document.modelContext?.registerTool) return

  await document.modelContext.registerTool({
    name: 'trustready.scan_public_repository',
    title: 'Scan public AI repository',
    description: 'Run a read-only TrustReady evidence scan of a public GitHub repository. Returns a versioned procurement-readiness score, control statuses, provenance and a path to 100. Candidate evidence never counts as verified. The result is not certification or legal advice.',
    inputSchema: {
      type: 'object',
      properties: {
        repository_url: { type: 'string', description: 'Public github.com repository URL.' }
      },
      required: ['repository_url'],
      additionalProperties: false
    },
    annotations: { readOnlyHint: true, untrustedContentHint: true },
    execute: async ({ repository_url }) => JSON.stringify(await scanPublicGitHubInBrowser(repository_url))
  })

  await document.modelContext.registerTool({
    name: 'trustready.explain_control',
    title: 'Explain a TrustReady control gap',
    description: 'Scan a public GitHub repository and return the evidence, status, reason and exact next proof for one TrustReady control. This is read-only and preserves unresolved uncertainty.',
    inputSchema: {
      type: 'object',
      properties: {
        repository_url: { type: 'string', description: 'Public github.com repository URL.' },
        control_id: { type: 'string', description: 'TrustReady control id, for example TR-AI-002.' }
      },
      required: ['repository_url', 'control_id'],
      additionalProperties: false
    },
    annotations: { readOnlyHint: true, untrustedContentHint: true },
    execute: async ({ repository_url, control_id }) => JSON.stringify(controlSummary(await scanPublicGitHubInBrowser(repository_url), control_id))
  })
}

registerWebMcp().catch((error) => console.warn('TrustReady WebMCP registration failed:', error))
