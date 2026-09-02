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
  try { return await response.json() } catch { throw new Error('GCP network posture response invalid') }
}

function targetScoped(rule) {
  if (Array.isArray(rule?.targetTags) && rule.targetTags.length) return true
  if (Array.isArray(rule?.targetServiceAccounts) && rule.targetServiceAccounts.length) return true
  if (rule?.params?.resourceManagerTags && Object.keys(rule.params.resourceManagerTags).length) return true
  return false
}

function isDenyAll(rule, protectedNetwork) {
  return rule?.network === protectedNetwork && !targetScoped(rule) && rule?.direction === 'EGRESS' &&
    Array.isArray(rule.destinationRanges) && rule.destinationRanges.includes('0.0.0.0/0') &&
    Array.isArray(rule.denied) && rule.denied.some((entry) => entry?.IPProtocol === 'all') && rule.disabled !== true
}

function isRestrictedVipAllow(rule, protectedNetwork) {
  return rule?.network === protectedNetwork && !targetScoped(rule) && rule?.direction === 'EGRESS' &&
    Array.isArray(rule.destinationRanges) && rule.destinationRanges.length === 1 && rule.destinationRanges[0] === RESTRICTED_GOOGLE_VIP &&
    Array.isArray(rule.allowed) && rule.allowed.length === 1 && rule.allowed[0]?.IPProtocol === 'tcp' &&
    Array.isArray(rule.allowed[0]?.ports) && rule.allowed[0].ports.length === 1 && rule.allowed[0].ports[0] === '443' && rule.disabled !== true
}

function dangerousHigherPriorityAllow(rule, denyPriority, protectedNetwork) {
  if (rule?.network !== protectedNetwork || rule?.direction !== 'EGRESS' || rule.disabled === true || !Array.isArray(rule.allowed) || !Number.isInteger(rule.priority)) return false
  if (rule.priority >= denyPriority) return false
  return !isRestrictedVipAllow(rule, protectedNetwork)
}

function protectedInstanceNics(instances, protectedNetwork, protectedSubnetwork) {
  const rows = []
  for (const scoped of Object.values(instances?.items || {})) {
    for (const instance of scoped?.instances || []) {
      for (const nic of instance.networkInterfaces || []) {
        const referencesProtected = nic.network === protectedNetwork || (protectedSubnetwork && nic.subnetwork === protectedSubnetwork)
        if (referencesProtected) rows.push({ instance: instance.name || null, nic })
      }
    }
  }
  return rows
}

export function evaluateGcpNetworkPosture({ firewalls, subnetwork, instances, perimeter, protected_resource }) {
  const protectedNetwork = subnetwork?.network
  const protectedSubnetwork = subnetwork?.selfLink || null
  if (typeof protectedNetwork !== 'string' || !protectedNetwork.includes('/global/networks/')) return { ready: false, reason: 'protected subnetwork network identity missing' }
  if (subnetwork?.privateIpGoogleAccess !== true) return { ready: false, reason: 'Private Google Access is not enabled' }

  const rules = Array.isArray(firewalls?.items) ? firewalls.items : []
  const denyRules = rules.filter((rule) => isDenyAll(rule, protectedNetwork)).sort((a, b) => a.priority - b.priority)
  if (!denyRules.length) return { ready: false, reason: 'network-wide deny-all egress firewall missing on protected VPC' }
  const denyPriority = denyRules[0].priority
  const restricted = rules.find((rule) => isRestrictedVipAllow(rule, protectedNetwork) && rule.priority < denyPriority)
  if (!restricted) return { ready: false, reason: 'network-wide restricted.googleapis.com TCP/443 allow rule missing on protected VPC' }
  if (rules.some((rule) => dangerousHigherPriorityAllow(rule, denyPriority, protectedNetwork))) return { ready: false, reason: 'higher-priority egress allow bypass exists on protected VPC' }

  const protectedNics = protectedInstanceNics(instances, protectedNetwork, protectedSubnetwork)
  for (const { nic } of protectedNics) {
    if (nic.network !== protectedNetwork) return { ready: false, reason: 'protected workload NIC network mismatch' }
    if (Array.isArray(nic.accessConfigs) && nic.accessConfigs.length > 0) return { ready: false, reason: 'external IP detected on protected workload' }
  }

  const status = perimeter?.status
  if (!status || perimeter?.useExplicitDryRunSpec === true) return { ready: false, reason: 'VPC Service Controls perimeter is not enforced' }
  if (!Array.isArray(status.resources) || !status.resources.includes(protected_resource)) return { ready: false, reason: 'project is outside service perimeter' }
  if ((Array.isArray(status.egressPolicies) && status.egressPolicies.length) || (Array.isArray(status.ingressPolicies) && status.ingressPolicies.length)) {
    return { ready: false, reason: 'unapproved VPC Service Controls ingress/egress escape policy present' }
  }
  const restrictedServices = new Set(status.restrictedServices || [])
  const missing = REQUIRED_RESTRICTED_SERVICES.filter((service) => !restrictedServices.has(service))
  if (missing.length) return { ready: false, reason: `service perimeter missing restricted services: ${missing.join(',')}` }
  const accessible = status.vpcAccessibleServices
  if (accessible && (accessible.enableRestriction !== true || !Array.isArray(accessible.allowedServices) || accessible.allowedServices.length !== 1 || accessible.allowedServices[0] !== 'RESTRICTED-SERVICES')) {
    return { ready: false, reason: 'VPC accessible services policy is broader than restricted services' }
  }

  return {
    ready: true,
    provider: 'gcp-vpc-service-controls',
    deny_by_default: true,
    only_restricted_google_apis: true,
    restricted_vip: RESTRICTED_GOOGLE_VIP,
    private_google_access: true,
    external_ip_count: 0,
    protected_network: protectedNetwork,
    protected_subnetwork: protectedSubnetwork,
    protected_workload_nics: protectedNics.length,
    deny_rule: denyRules[0].name || null,
    allow_rule: restricted.name || null,
    perimeter_name: perimeter.name || null,
    protected_resource,
    restricted_services: [...restrictedServices].sort(),
  }
}

export function createGcpNetworkPostureCollector({ project_id, region, subnetwork, service_perimeter_name, fetch_impl = globalThis.fetch, token_provider }) {
  if (!project_id || !region || !subnetwork || !service_perimeter_name) throw new TypeError('GCP network collector context required')
  const compute = 'https://compute.googleapis.com/compute/v1'
  const access = 'https://accesscontextmanager.googleapis.com/v1'
  const crm = 'https://cloudresourcemanager.googleapis.com/v3'
  return {
    backend: 'gcp-network-posture',
    async collect() {
      const [firewalls, subnet, instances, perimeter, project] = await Promise.all([
        getJson({ fetch_impl, token_provider, url: `${compute}/projects/${project_id}/global/firewalls` }),
        getJson({ fetch_impl, token_provider, url: `${compute}/projects/${project_id}/regions/${region}/subnetworks/${subnetwork}` }),
        getJson({ fetch_impl, token_provider, url: `${compute}/projects/${project_id}/aggregated/instances` }),
        getJson({ fetch_impl, token_provider, url: `${access}/${service_perimeter_name}` }),
        getJson({ fetch_impl, token_provider, url: `${crm}/projects/${project_id}` }),
      ])
      if (project?.projectId !== project_id || !/^projects\/\d+$/.test(project?.name || '')) return { ready: false, reason: 'deployed project identity could not be derived' }
      return evaluateGcpNetworkPosture({ firewalls, subnetwork: subnet, instances, perimeter, protected_resource: project.name })
    },
  }
}

export async function createSignedEgressEnforcementAttestation({ collector, signer, tenant_id, policy_version, release, now = new Date(), ttl_ms = 120_000 }) {
  if (!release || typeof release !== 'string') throw new TypeError('release identity required for egress enforcement')
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
    protected_network: posture.protected_network,
    restricted_vip: posture.restricted_vip,
    perimeter_name: posture.perimeter_name,
    protected_resource: posture.protected_resource,
    observed_at: now.toISOString(),
    expires_at: new Date(now.getTime() + ttl_ms).toISOString(),
  }
  return { ready: true, posture, attestation: await signEnvelopeWithSigner({ body, signer, purpose: 'egress_enforcement' }) }
}
