import { signEnvelopeWithSigner } from './legal-key-identity.mjs'
import { createGceRuntimeIdentityProvider, isTrustedGceRuntimeIdentityProvider } from './legal-gcp-runtime-identity.mjs'

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

function tail(value) {
  if (typeof value !== 'string' || !value) return null
  const parts = value.split('/').filter(Boolean)
  return parts.at(-1) || null
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

function effectiveShapeSafe(effective) {
  if (!effective || typeof effective !== 'object' || !Array.isArray(effective.firewalls) || !Array.isArray(effective.firewallPolicys)) return { safe: false, reason: 'effective firewall response incomplete or malformed' }
  for (const policy of effective.firewallPolicys) {
    if (!policy || typeof policy !== 'object' || !Array.isArray(policy.rules)) return { safe: false, reason: 'effective firewall policy collection malformed' }
  }
  return { safe: true }
}

function activePolicyRules(effective) {
  const rows = []
  for (const policy of effective.firewallPolicys) {
    for (const rule of policy.rules) if (rule?.disabled !== true) rows.push({ policy, rule })
  }
  return rows
}

function policyLayersSafe(effective) {
  const shape = effectiveShapeSafe(effective)
  if (!shape.safe) return shape
  for (const { policy, rule } of activePolicyRules(effective)) {
    const type = String(policy?.type || '')
    if (!type.startsWith('SYSTEM_')) return { safe: false, reason: `custom effective firewall policy present (${type || 'UNKNOWN'})` }
    if (rule?.direction === 'EGRESS' && String(rule?.action || '').toLowerCase() === 'allow') return { safe: false, reason: 'system firewall policy contains egress allow' }
  }
  return { safe: true }
}

function classicRulesSafe(effective, protectedNetwork) {
  const shape = effectiveShapeSafe(effective)
  if (!shape.safe) return shape
  const rules = effective.firewalls
  const denyRules = rules.filter((rule) => isDenyAll(rule, protectedNetwork)).sort((a, b) => a.priority - b.priority)
  if (!denyRules.length) return { safe: false, reason: 'network-wide deny-all egress firewall missing on protected VPC' }
  const denyPriority = denyRules[0].priority
  const restricted = rules.find((rule) => isRestrictedVipAllow(rule, protectedNetwork) && rule.priority < denyPriority)
  if (!restricted) return { safe: false, reason: 'network-wide restricted.googleapis.com TCP/443 allow rule missing on protected VPC' }
  if (rules.some((rule) => dangerousHigherPriorityAllow(rule, denyPriority, protectedNetwork))) return { safe: false, reason: 'higher-priority egress allow bypass exists on protected VPC' }
  return { safe: true, denyRule: denyRules[0], restrictedRule: restricted }
}

function validateExactWorkload({ workload, runtime_identity, protectedNetwork, protectedSubnetwork, project_id, expected_nic }) {
  if (!runtime_identity?.ready || runtime_identity.provider !== 'gce-local-metadata' || runtime_identity.metadata_flavor_verified !== true) return { safe: false, reason: 'network posture is not bound to authenticated local GCE runtime metadata' }
  if (runtime_identity.project_id !== project_id) return { safe: false, reason: 'runtime project identity mismatch' }
  if (workload?.name !== runtime_identity.instance_name || String(workload?.id || '') !== runtime_identity.instance_id) return { safe: false, reason: 'runtime instance identity does not match Compute API workload' }
  if (typeof workload?.zone !== 'string' || !workload.zone.endsWith(`/zones/${runtime_identity.zone}`)) return { safe: false, reason: 'runtime zone identity mismatch' }
  const nics = Array.isArray(workload?.networkInterfaces) ? workload.networkInterfaces : []
  if (nics.length !== 1) return { safe: false, reason: 'protected workload must have exactly one NIC' }
  const nic = nics[0]
  if (nic?.name !== expected_nic) return { safe: false, reason: 'expected workload NIC missing' }
  if (nic.network !== protectedNetwork || nic.subnetwork !== protectedSubnetwork) return { safe: false, reason: 'protected workload NIC network/subnetwork mismatch' }
  if (tail(nic.network) !== runtime_identity.network_name || tail(nic.subnetwork) !== runtime_identity.subnetwork_name) return { safe: false, reason: 'local runtime network identity does not match protected workload NIC' }
  if (Array.isArray(nic.accessConfigs) && nic.accessConfigs.length) return { safe: false, reason: 'external IPv4 detected on protected workload' }
  if (Array.isArray(nic.ipv6AccessConfigs) && nic.ipv6AccessConfigs.length) return { safe: false, reason: 'external IPv6 detected on protected workload' }
  if (nic.stackType !== 'IPV4_ONLY') return { safe: false, reason: 'protected workload NIC must be IPv4-only' }
  const serviceAccounts = Array.isArray(workload?.serviceAccounts) ? workload.serviceAccounts : []
  if (serviceAccounts.length !== 1 || serviceAccounts[0]?.email !== runtime_identity.service_account_email) return { safe: false, reason: 'runtime service account identity mismatch' }
  return { safe: true, nic }
}

export function evaluateGcpNetworkPosture({ effective_firewalls, regional_effective_firewalls, workload_effective_firewalls, subnetwork, workload, runtime_identity, perimeter, protected_resource, project_id, expected_nic = 'nic0' }) {
  const protectedNetwork = subnetwork?.network
  const protectedSubnetwork = subnetwork?.selfLink || null
  if (typeof protectedNetwork !== 'string' || !protectedNetwork.includes('/global/networks/')) return { ready: false, reason: 'protected subnetwork network identity missing' }
  if (subnetwork?.privateIpGoogleAccess !== true) return { ready: false, reason: 'Private Google Access is not enabled' }
  if (subnetwork?.stackType !== 'IPV4_ONLY') return { ready: false, reason: 'protected subnetwork must be explicitly IPv4-only' }

  for (const effective of [effective_firewalls, regional_effective_firewalls, workload_effective_firewalls]) {
    const layers = policyLayersSafe(effective)
    if (!layers.safe) return { ready: false, reason: layers.reason }
    const classic = classicRulesSafe(effective, protectedNetwork)
    if (!classic.safe) return { ready: false, reason: classic.reason }
  }
  const classic = classicRulesSafe(effective_firewalls, protectedNetwork)

  const exact = validateExactWorkload({ workload, runtime_identity, protectedNetwork, protectedSubnetwork, project_id, expected_nic })
  if (!exact.safe) return { ready: false, reason: exact.reason }

  const status = perimeter?.status
  if (!status || perimeter?.useExplicitDryRunSpec === true) return { ready: false, reason: 'VPC Service Controls perimeter is not enforced' }
  if (!Array.isArray(status.resources) || !status.resources.includes(protected_resource)) return { ready: false, reason: 'project is outside service perimeter' }
  if ((Array.isArray(status.egressPolicies) && status.egressPolicies.length) || (Array.isArray(status.ingressPolicies) && status.ingressPolicies.length)) {
    return { ready: false, reason: 'unapproved VPC Service Controls ingress/egress escape policy present' }
  }
  if (!Array.isArray(status.restrictedServices)) return { ready: false, reason: 'service perimeter restricted-services state missing' }
  const restrictedServices = new Set(status.restrictedServices)
  const missing = REQUIRED_RESTRICTED_SERVICES.filter((service) => !restrictedServices.has(service))
  if (missing.length) return { ready: false, reason: `service perimeter missing restricted services: ${missing.join(',')}` }
  const accessible = status.vpcAccessibleServices
  if (!accessible || accessible.enableRestriction !== true || !Array.isArray(accessible.allowedServices) || accessible.allowedServices.length !== 1 || accessible.allowedServices[0] !== 'RESTRICTED-SERVICES') {
    return { ready: false, reason: 'VPC accessible services must explicitly restrict access to RESTRICTED-SERVICES' }
  }

  return {
    ready: true,
    provider: 'gcp-vpc-service-controls',
    deny_by_default: true,
    only_restricted_google_apis: true,
    restricted_vip: RESTRICTED_GOOGLE_VIP,
    private_google_access: true,
    ipv4_only: true,
    external_ip_count: 0,
    protected_network: protectedNetwork,
    protected_subnetwork: protectedSubnetwork,
    protected_workload: runtime_identity.instance_name,
    protected_workload_instance_id: runtime_identity.instance_id,
    protected_workload_zone: runtime_identity.zone,
    protected_workload_nic: expected_nic,
    protected_service_account: runtime_identity.service_account_email,
    runtime_identity_provider: runtime_identity.provider,
    runtime_metadata_flavor_verified: true,
    deny_rule: classic.denyRule.name || null,
    allow_rule: classic.restrictedRule.name || null,
    perimeter_name: perimeter.name || null,
    protected_resource,
    restricted_services: [...restrictedServices].sort(),
    effective_policy_layers_checked: true,
  }
}

export function createGcpNetworkPostureCollector({ project_id, region, subnetwork, service_perimeter_name, workload_nic = 'nic0', fetch_impl = globalThis.fetch, token_provider, runtime_identity_provider = createGceRuntimeIdentityProvider() }) {
  if (!project_id || !region || !subnetwork || !service_perimeter_name || !workload_nic) throw new TypeError('GCP network collector context required')
  if (!isTrustedGceRuntimeIdentityProvider(runtime_identity_provider)) throw new TypeError('trusted local GCE runtime identity provider required')
  const compute = 'https://compute.googleapis.com/compute/v1'
  const access = 'https://accesscontextmanager.googleapis.com/v1'
  const crm = 'https://cloudresourcemanager.googleapis.com/v3'
  return {
    backend: 'gcp-network-posture',
    async collect() {
      const [subnet, perimeter, project, runtimeIdentity] = await Promise.all([
        getJson({ fetch_impl, token_provider, url: `${compute}/projects/${project_id}/regions/${region}/subnetworks/${subnetwork}` }),
        getJson({ fetch_impl, token_provider, url: `${access}/${service_perimeter_name}` }),
        getJson({ fetch_impl, token_provider, url: `${crm}/projects/${project_id}` }),
        runtime_identity_provider.collect(),
      ])
      if (!runtimeIdentity?.ready) return { ready: false, reason: runtimeIdentity?.reason || 'local GCE runtime identity unavailable' }
      if (runtimeIdentity.project_id !== project_id) return { ready: false, reason: 'local GCE runtime project differs from qualification project' }
      if (project?.projectId !== project_id || !/^projects\/\d+$/.test(project?.name || '')) return { ready: false, reason: 'deployed project identity could not be derived' }
      const networkName = typeof subnet?.network === 'string' ? subnet.network.split('/').pop() : null
      if (!networkName) return { ready: false, reason: 'protected network name could not be derived' }
      const networkRef = subnet.network
      const workloadZone = runtimeIdentity.zone
      const workloadInstance = runtimeIdentity.instance_name
      const [effective, regionalEffective, workload, workloadEffective] = await Promise.all([
        getJson({ fetch_impl, token_provider, url: `${compute}/projects/${project_id}/global/networks/${networkName}/getEffectiveFirewalls` }),
        getJson({ fetch_impl, token_provider, url: `${compute}/projects/${project_id}/regions/${region}/firewallPolicies/getEffectiveFirewalls?network=${encodeURIComponent(networkRef)}` }),
        getJson({ fetch_impl, token_provider, url: `${compute}/projects/${project_id}/zones/${workloadZone}/instances/${workloadInstance}` }),
        getJson({ fetch_impl, token_provider, url: `${compute}/projects/${project_id}/zones/${workloadZone}/instances/${workloadInstance}/getEffectiveFirewalls?networkInterface=${encodeURIComponent(workload_nic)}` }),
      ])
      return evaluateGcpNetworkPosture({
        effective_firewalls: effective,
        regional_effective_firewalls: regionalEffective,
        workload_effective_firewalls: workloadEffective,
        subnetwork: subnet,
        workload,
        runtime_identity: runtimeIdentity,
        perimeter,
        protected_resource: project.name,
        project_id,
        expected_nic: workload_nic,
      })
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
    protected_subnetwork: posture.protected_subnetwork,
    protected_workload: posture.protected_workload,
    protected_workload_instance_id: posture.protected_workload_instance_id,
    protected_workload_zone: posture.protected_workload_zone,
    protected_workload_nic: posture.protected_workload_nic,
    protected_service_account: posture.protected_service_account,
    runtime_identity_provider: posture.runtime_identity_provider,
    runtime_metadata_flavor_verified: posture.runtime_metadata_flavor_verified,
    ipv4_only: posture.ipv4_only,
    effective_policy_layers_checked: posture.effective_policy_layers_checked,
    restricted_vip: posture.restricted_vip,
    perimeter_name: posture.perimeter_name,
    protected_resource: posture.protected_resource,
    observed_at: now.toISOString(),
    expires_at: new Date(now.getTime() + ttl_ms).toISOString(),
  }
  return { ready: true, posture, attestation: await signEnvelopeWithSigner({ body, signer, purpose: 'egress_enforcement' }) }
}
