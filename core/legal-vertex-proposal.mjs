import { buildProposalOnlyModelRequestForPayload, validateAgentProposal } from './legal-content-guard.mjs'
import { sha256 } from './legal-key-identity.mjs'

function jsonBytes(value) { return Buffer.from(JSON.stringify(value), 'utf8') }

export function buildVertexProposalRequest({ payload, use_case }) {
  const proposalRequest = buildProposalOnlyModelRequestForPayload({ payload, use_case })
  const providerBody = {
    systemInstruction: {
      role: 'system',
      parts: [{ text: `${proposalRequest.instruction} Respond with one strict JSON object only. Never emit tool calls, function calls, URLs, recipients, executable code, or action instructions.` }],
    },
    contents: [{
      role: 'user',
      parts: [{ text: JSON.stringify({ use_case: proposalRequest.use_case, security: proposalRequest.security, untrusted_data: proposalRequest.untrusted_data }) }],
    }],
    generationConfig: {
      responseMimeType: 'application/json',
      temperature: 0,
      candidateCount: 1,
    },
  }
  if ('tools' in providerBody || 'toolConfig' in providerBody || 'functionDeclarations' in providerBody) throw new Error('Vertex proposal request unexpectedly contains tools')
  const bytes = jsonBytes(providerBody)
  return { proposal_request: proposalRequest, provider_body: providerBody, bytes, request_fingerprint: `sha256:${sha256(bytes)}` }
}

export function parseVertexProposalResponse(responseBytes) {
  let body
  try { body = JSON.parse(Buffer.from(responseBytes).toString('utf8')) } catch { return { valid: false, reason: 'Vertex response is not valid JSON' } }
  const candidates = body?.candidates
  if (!Array.isArray(candidates) || candidates.length !== 1) return { valid: false, reason: 'Vertex response must contain exactly one candidate' }
  const parts = candidates[0]?.content?.parts
  if (!Array.isArray(parts) || parts.length !== 1 || typeof parts[0]?.text !== 'string') return { valid: false, reason: 'Vertex candidate text missing or ambiguous' }
  if (parts[0].functionCall || parts[0].functionResponse || parts.some((part) => part?.functionCall || part?.functionResponse)) return { valid: false, reason: 'Vertex tool/function response denied' }
  let proposal
  try { proposal = JSON.parse(parts[0].text) } catch { return { valid: false, reason: 'Vertex proposal payload is not strict JSON' } }
  const validated = validateAgentProposal(proposal)
  if (!validated.valid) return validated
  return { valid: true, proposal, proposal_hash: validated.proposal_hash, response_fingerprint: `sha256:${sha256(Buffer.from(responseBytes))}` }
}
