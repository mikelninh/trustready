import { signEnvelopeWithSigner } from './legal-key-identity.mjs'

const RESTRICTED_GOOGLE_VIP = '199.36.153.4/30'
const REQUIRED_RESTRICTED_SERVICES = Object.freeze([
  'aiplatform.googleapis.com', 'storage.googleapis.com', 'dlp.googleapis.com', 'cloudkms.googleapis.com',
])

async function authToken(provider) {
  if (typeof provider !== 'function') throw new Error('GCP access token provider required')
  const token = await provider()
  if (typeof token !== 'string' || token.length < 16) throw new Error('GCP access token unavailable')
  return token
}

async function getJson({ fetch_impl, token_provider, url }) {
  const token = await authToken(token_provider)
  let response
  try {
    response = await fetch_impl(url, { method: 'GET', redirect: 'error', headers: { authorization: `Bearer ${token}`, accept: 'application/json' } })
  } catch {
    throw new Error('GCP network posture API unavailable')
  }
  if (!response?.ok) throw new Error(`GCP network posture API denied (${Number(response?.status) || 0})`)
  return response.json()
}

function isDenyAll(rule) {
  return rule?.direction === 'EGRESS' && Array.isArray(rule.destinationRanges) && rule.destinationRanges.includes('0.0.0.0/0') &&
    Array.isArray(rule.denied) && rule.denied.some((entry) => entry?.IPProtocol === 'all') && rule.disabled !== true
}

function isRestrictedVipAllow(rule) {
  return rule?.direction === 'EGRESS' && Array.isArray(rule.destinationRanges) && rule.destinationRanges.length === 1 && rule.destinationRanges[0] === RESTRICTED_GOOGLE_VIP &&
    Array.isArray(rule.allowed) && rule.allowed.length === 1 && rule.allowed[0]?.IPProtocol === 'tcp' &&
    Array.isArray(rule.allowed[0]?.ports) && rule.allowed[0].ports.length === 1 && rule.allowed[0].ports[0] === '443' && rule.disabled !== true
}

function dangerousHigherPriorityAllow(rule, denyPriority) {
  if (rule?.direction !== 'EGRESS' || rule.disabled === true || !Array.isArray(rule.allowed) || !Number.isInteger(rule.priority)) return false
  if (rule.priority >= denyPriority) return false
  return !isRestrictedVipAllow(rule)
}

export function evaluateGcpNetworkPosture({ firewalls, subnetwork, instances, perimeter, protected_resource }) {
  const rules = Array.isArray(firewalls?.items) ? firewalls.items : []
  const denyRules = rules.filter(isDenyAll).sort((a, b) => a.priority - b.priority)
  if (!denyRules.length) return { ready: false, reason: 'deny-all egress firewall missing' }
  const denyPriority = denyRules[0].priority
  const restricted = rules.find((rule) => isRestrictedVipAllow(rule) && rule.priority < denyPriority)
  if (!restricted) return { ready: false, reason: 'restricted.googleapis.com TCP/443 allow rule missing' }
  if (rules.some((rule) => dangerousHigherPriorityAllow(rule, denyPriority))) return { ready: false, reason: 'higher-priority egress allow bypass exists' }
  if (subnetwork?.privateIpGoogleAccess !== true) return { ready: false, reason: 'Private Google Access is not enabled' }

  const instanceRows = []
  for (const scoped of Object.values(instances?.items || {})) {
    for (const instance of scoped?.instances || []) instanceRows.push(instance)
  }
  if (instanceRows.some((instance) => (instance.networkInterfaces || []).some((nic) => Array.isArray(nic.accessConfigs) && nic.accessConfigs.length > 0))) {
    return { ready: false, reason: 'external IP detected on protected workload' }
  }

  const status = perimeter?.status
  if (!status || perimeter?.useExplicitDryRunSpec === true) return { ready: false, reason: 'VPC Service Controls perimeter is not enforced' }
  if (!Array.isArray(status.resources) || !status.resources.includes(protected_resource)) return { ready: false, reason: 'project is outside service perimeter' }
  const restrictedServices = new Set(status.restrictedServices || [])
  const missing = REQUIRED_RESTRICTED_SERVICES.filter((service) => !restrictedServices.has(service))
  if (missing.length) return { ready: false, reason: `service perimeter missing restricted services: ${missing.join(',')}` }

  return {
    ready: true,
    provider: 'gcp-vpc-service-controls',
    deny_by_default: true,
    only_restricted_google_apis: true,
    restricted_vip: RESTRICTED_GOOGLE_VIP,
    private_google_access: true,
    external_ip_count: 0,
    deny_rule: denyRules[0].name || null,
    allow_rule: restricted.name || null,
    perimeter_name: perimeter.name || null,
    protected_resource,
    restricted_services: [...restrictedServices].sort(),
  }
}

export function createGcpNetworkPostureCollector({ project_id, region, subnetwork, service_perimeter_name, protected_resource, fetch_impl = globalThis.fetch, token_provider }) {
  if (!project_id || !region || !subnetwork || !service_perimeter_name || !protected_resource) throw new TypeError('GCP network collector context required')
  const compute = 'https://compute.googleapis.com/compute/v1'
  const access = 'https://accesscontextmanager.googleapis.com/v1'
  return {
    backend: 'gcp-network-posture',
    async collect() {
      const [firewalls, subnet, instances, perimeter] = await Promise.all([
        getJson({ fetch_impl, token_provider, url: `${compute}/projects/${project_id}/global/firewalls` }),
        getJson({ fetch_impl, token_provider, url: `${compute}/projects/${project_id}/regions/${region}/subnetworks/${subnetwork}` }),
        getJson({ fetch_impl, token_provider, url: `${compute}/projects/${project_id}/aggregated/instances` }),
        getJson({ fetch_impl, token_provider, url: `${access}/${service_perimeter_name}` }),
      ])
      return evaluateGcpNetworkPosture({ firewalls, subnetwork: subnet, instances, perimeter, protected_resource })
    },
  }
}

export async function createSignedEgressEnforcementAttestation({ collector, signer, tenant_id, policy_version, release, now = new Date(), ttl_ms = 120_000 }) {
  const posture = await collector.collect()
  if (!posture.ready) return { ready: false, posture, attestation: null }
  const body = {
    schema: 'trustready-egress-enforcement-v1',
    tenant_id,
    policy_version,
    deny_by_default: true,
    only_gateway: true,
    release,
    network_provider: posture.provider,
    restricted_vip: posture.restricted_vip,
    perimeter_name: posture.perimeter_name,
    observed_at: now.toISOString(),
    expires_at: new Date(now.getTime() + ttl_ms).toISOString(),
  }
  return { ready: true, posture, attestation: await signEnvelopeWithSigner({ body, signer, purpose: 'egress_enforcement' }) }
}
