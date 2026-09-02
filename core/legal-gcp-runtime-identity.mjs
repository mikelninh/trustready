const METADATA_BASE = 'http://169.254.169.254/computeMetadata/v1'
const RUNTIME_IDENTITY_BRAND = Symbol('trustready.gce-runtime-identity-provider')
const TEST_RUNTIME_IDENTITY_BRAND = Symbol('trustready.test-gce-runtime-identity-provider')
const PRODUCTION_RUNTIME_IDENTITIES = new WeakSet()
const TEST_RUNTIME_IDENTITIES = new WeakSet()
const NATIVE_FETCH = typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : null

function tail(value) {
  if (typeof value !== 'string' || !value.trim()) return null
  const parts = value.trim().split('/').filter(Boolean)
  return parts.at(-1) || null
}

async function metadataText(fetch_impl, path) {
  let response
  try {
    response = await fetch_impl(`${METADATA_BASE}/${path}`, {
      method: 'GET',
      redirect: 'error',
      headers: { 'Metadata-Flavor': 'Google' },
    })
  } catch {
    throw new Error('GCE metadata server unavailable')
  }
  if (!response?.ok) throw new Error(`GCE metadata request denied (${Number(response?.status) || 0})`)
  const flavor = response.headers?.get?.('metadata-flavor')
  if (String(flavor || '').toLowerCase() !== 'google') throw new Error('GCE metadata response not authenticated by Metadata-Flavor')
  let value
  try { value = String(await response.text()).trim() } catch { throw new Error('GCE metadata response unreadable') }
  if (!value || value.length > 8192 || /[\r\n]/.test(value)) throw new Error('GCE metadata value invalid')
  return value
}

function buildProvider({ fetch_impl, test_only }) {
  if (typeof fetch_impl !== 'function') throw new TypeError('GCE metadata fetch implementation required')
  const provider = {
    [RUNTIME_IDENTITY_BRAND]: true,
    ...(test_only ? { [TEST_RUNTIME_IDENTITY_BRAND]: true } : {}),
    backend: 'gce-local-metadata',
    async collect() {
      let values
      try {
        values = await Promise.all([
          metadataText(fetch_impl, 'project/project-id'),
          metadataText(fetch_impl, 'instance/name'),
          metadataText(fetch_impl, 'instance/id'),
          metadataText(fetch_impl, 'instance/zone'),
          metadataText(fetch_impl, 'instance/network-interfaces/0/network'),
          metadataText(fetch_impl, 'instance/network-interfaces/0/subnetwork'),
          metadataText(fetch_impl, 'instance/service-accounts/default/email'),
        ])
      } catch (error) {
        return { ready: false, reason: error.message }
      }
      const [project_id, instance_name, instance_id, zone_ref, network_ref, subnetwork_ref, service_account_email] = values
      const zone = tail(zone_ref), network_name = tail(network_ref), subnetwork_name = tail(subnetwork_ref)
      if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(project_id)) return { ready: false, reason: 'GCE runtime project identity invalid' }
      if (!/^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$/.test(instance_name)) return { ready: false, reason: 'GCE runtime instance identity invalid' }
      if (!/^\d+$/.test(instance_id) || !zone || !network_name || !subnetwork_name) return { ready: false, reason: 'GCE runtime topology identity incomplete' }
      if (!/^[^@\s]+@[^@\s]+\.iam\.gserviceaccount\.com$/.test(service_account_email)) return { ready: false, reason: 'GCE runtime service account identity invalid' }
      return {
        ready: true,
        provider: 'gce-local-metadata',
        project_id,
        instance_name,
        instance_id,
        zone,
        network_name,
        subnetwork_name,
        service_account_email,
        metadata_endpoint: '169.254.169.254',
        metadata_flavor_verified: true,
      }
    },
  }
  Object.freeze(provider)
  if (test_only) TEST_RUNTIME_IDENTITIES.add(provider)
  else PRODUCTION_RUNTIME_IDENTITIES.add(provider)
  return provider
}

export function isTrustedGceRuntimeIdentityProvider(provider) {
  return PRODUCTION_RUNTIME_IDENTITIES.has(provider) || TEST_RUNTIME_IDENTITIES.has(provider)
}

export function isProductionGceRuntimeIdentityProvider(provider) {
  return PRODUCTION_RUNTIME_IDENTITIES.has(provider)
}

export function isTestGceRuntimeIdentityProvider(provider) {
  return TEST_RUNTIME_IDENTITIES.has(provider)
}

export function createGceRuntimeIdentityProvider() {
  if (typeof NATIVE_FETCH !== 'function') throw new TypeError('native fetch required for production GCE metadata identity')
  return buildProvider({ fetch_impl: NATIVE_FETCH, test_only: false })
}

export function createGceRuntimeIdentityProviderForTest({ fetch_impl }) {
  return buildProvider({ fetch_impl, test_only: true })
}
