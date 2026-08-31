import fs from 'node:fs'
import { McpServer, createMcpHandler } from '@modelcontextprotocol/server'
import * as z from 'zod/v4'
import { collectPublicGitHubSnapshot } from '../collectors/github-public.mjs'
import { scanRepositorySnapshot } from '../core/scanner.mjs'
import { verifyAssuranceManifest } from '../core/trust-kernel.mjs'

const profile = JSON.parse(fs.readFileSync(new URL('../profiles/core-ai-procurement-2026.08.json', import.meta.url), 'utf8'))

async function runPublicScan(repositoryUrl) {
  const snapshot = await collectPublicGitHubSnapshot(repositoryUrl)
  if (snapshot.collection?.incomplete) {
    throw new Error('Evidence collection was incomplete. TrustReady refuses to score an incomplete repository snapshot as complete evidence.')
  }
  return scanRepositorySnapshot(snapshot, profile)
}

function compactScan(scan) {
  return {
    schema: scan.schema,
    subject: scan.subject,
    profile: scan.profile,
    score: scan.evaluation.score,
    coverage_pct: scan.evaluation.coverage_pct,
    ready: scan.evaluation.ready,
    source_revision: scan.source_revision,
    observed_at: scan.observed_at,
    provenance_complete: scan.provenance_complete,
    blocking_findings: scan.evaluation.blocking_findings,
    gaps: scan.gaps.map((gap) => ({
      control_id: gap.control_id,
      title: gap.title,
      status: gap.status,
      blocking: gap.blocking,
      reason: gap.reason,
      next_proof: gap.next_proof,
      remediation_lane: gap.remediation_lane,
      evidence: gap.evidence,
    })),
    boundary: scan.boundary,
  }
}

export function buildTrustReadyMcpServer() {
  const server = new McpServer({ name: 'trustready', version: '0.3.0' }, { capabilities: { tools: {} } })

  server.registerTool(
    'scan_public_repository',
    {
      title: 'Scan public repository',
      description: 'Run a read-only, evidence-first TrustReady scan of a public GitHub repository. Candidate evidence never earns verified credit. Returns the selected profile score, inspectable gaps, evidence provenance and exact next proof. This is not certification or legal advice.',
      inputSchema: z.object({ repository_url: z.string().url() }),
      annotations: { readOnlyHint: true },
    },
    async ({ repository_url }) => {
      const scan = compactScan(await runPublicScan(repository_url))
      return { content: [{ type: 'text', text: JSON.stringify(scan) }] }
    }
  )

  server.registerTool(
    'explain_control_gap',
    {
      title: 'Explain a control gap',
      description: 'Scan a public GitHub repository and explain one TrustReady control: status, evidence, why it is unresolved, and the exact proof required to close it.',
      inputSchema: z.object({ repository_url: z.string().url(), control_id: z.string().min(1) }),
      annotations: { readOnlyHint: true },
    },
    async ({ repository_url, control_id }) => {
      const scan = await runPublicScan(repository_url)
      const gap = scan.gaps.find((item) => item.control_id === control_id)
      if (!gap) throw new Error(`Unknown control_id: ${control_id}`)
      return { content: [{ type: 'text', text: JSON.stringify({ subject: scan.subject, profile: scan.profile, score: scan.evaluation.score, gap, boundary: scan.boundary }) }] }
    }
  )

  server.registerTool(
    'verify_assurance_manifest',
    {
      title: 'Verify assurance manifest integrity',
      description: 'Verify the cryptographic integrity of a TrustReady assurance manifest without trusting the issuer. This checks the manifest hash only; it does not independently re-collect the underlying evidence.',
      inputSchema: z.object({ manifest: z.record(z.string(), z.unknown()) }),
      annotations: { readOnlyHint: true },
    },
    async ({ manifest }) => {
      const verification = verifyAssuranceManifest(manifest)
      return { content: [{ type: 'text', text: JSON.stringify(verification) }] }
    }
  )

  return server
}

export const trustReadyMcpHandler = createMcpHandler(() => buildTrustReadyMcpServer())
