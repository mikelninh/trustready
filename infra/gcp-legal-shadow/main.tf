locals {
  required_apis = toset([
    "aiplatform.googleapis.com",
    "accesscontextmanager.googleapis.com",
    "cloudkms.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "compute.googleapis.com",
    "dlp.googleapis.com",
    "dns.googleapis.com",
    "iam.googleapis.com",
    "serviceusage.googleapis.com",
    "storage.googleapis.com",
  ])

  restricted_services = [
    "accesscontextmanager.googleapis.com",
    "aiplatform.googleapis.com",
    "cloudkms.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "compute.googleapis.com",
    "dlp.googleapis.com",
    "storage.googleapis.com",
  ]

  hsm_keys = toset([
    "dlp-attestation",
    "egress-enforcement",
    "network-attestation",
    "evidence-manifest",
  ])

  gateway_project_roles = toset([
    "roles/aiplatform.user",
    "roles/browser",
    "roles/cloudkms.signerVerifier",
    "roles/compute.viewer",
    "roles/dlp.user",
    "roles/serviceusage.serviceUsageConsumer",
    "roles/storage.objectCreator",
    "roles/storage.objectViewer",
  ])
}

data "google_project" "current" {
  project_id = var.project_id
}

resource "google_project_service" "required" {
  for_each           = local.required_apis
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_compute_network" "legal" {
  name                    = "trustready-legal"
  project                 = var.project_id
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
  depends_on              = [google_project_service.required]
}

resource "google_compute_subnetwork" "legal" {
  name                     = "trustready-legal-${var.region}"
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.legal.id
  ip_cidr_range            = "10.88.0.0/24"
  stack_type               = "IPV4_ONLY"
  private_ip_google_access = true
}

# Network-wide rules: no target tags or target service accounts. This avoids a
# configuration that appears deny-by-default while silently missing workloads.
resource "google_compute_firewall" "allow_restricted_googleapis" {
  name      = "trustready-allow-restricted-googleapis"
  project   = var.project_id
  network   = google_compute_network.legal.name
  direction = "EGRESS"
  priority  = 1000

  destination_ranges = ["199.36.153.4/30"]
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_compute_firewall" "deny_all_egress" {
  name      = "trustready-deny-all-egress"
  project   = var.project_id
  network   = google_compute_network.legal.name
  direction = "EGRESS"
  priority  = 2000

  destination_ranges = ["0.0.0.0/0"]
  deny {
    protocol = "all"
  }
}

# Private DNS forces *.googleapis.com through restricted.googleapis.com.
resource "google_dns_managed_zone" "googleapis" {
  name        = "trustready-googleapis-private"
  project     = var.project_id
  dns_name    = "googleapis.com."
  description = "TrustReady Legal restricted Google APIs only"
  visibility  = "private"

  private_visibility_config {
    networks {
      network_url = google_compute_network.legal.id
    }
  }
}

resource "google_dns_record_set" "restricted_a" {
  name         = "restricted.googleapis.com."
  project      = var.project_id
  managed_zone = google_dns_managed_zone.googleapis.name
  type         = "A"
  ttl          = 300
  rrdatas      = ["199.36.153.4", "199.36.153.5", "199.36.153.6", "199.36.153.7"]
}

resource "google_dns_record_set" "googleapis_cname" {
  name         = "*.googleapis.com."
  project      = var.project_id
  managed_zone = google_dns_managed_zone.googleapis.name
  type         = "CNAME"
  ttl          = 300
  rrdatas      = ["restricted.googleapis.com."]
}

resource "google_service_account" "legal_gateway" {
  project      = var.project_id
  account_id   = "trustready-legal-gateway"
  display_name = "TrustReady Legal mandate-shadow gateway"
  depends_on   = [google_project_service.required]
}

resource "google_project_iam_member" "gateway_roles" {
  for_each = local.gateway_project_roles
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.legal_gateway.email}"
}

# The actual mandate-shadow sender is a dedicated VM with one private IPv4 NIC.
# Runtime qualification reads its identity from the local GCE metadata server
# and cross-checks instance ID, zone, network, subnet and service account against
# the Compute API before any network posture can become ready.
resource "google_compute_instance" "legal_gateway" {
  name                      = "trustready-legal-gateway"
  project                   = var.project_id
  zone                      = var.gateway_zone
  machine_type              = var.gateway_machine_type
  can_ip_forward            = false
  deletion_protection       = true
  allow_stopping_for_update = true

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 20
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.legal.id
    stack_type = "IPV4_ONLY"
    # Intentionally no access_config and no ipv6_access_config.
  }

  service_account {
    email  = google_service_account.legal_gateway.email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  metadata = {
    disable-legacy-endpoints = "true"
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  depends_on = [
    google_compute_firewall.allow_restricted_googleapis,
    google_compute_firewall.deny_all_egress,
    google_project_iam_member.gateway_roles,
  ]
}

resource "google_kms_key_ring" "legal" {
  name     = "trustready-legal"
  project  = var.project_id
  location = var.region
  depends_on = [google_project_service.required]
}

resource "google_kms_crypto_key" "attestors" {
  for_each = local.hsm_keys
  name     = each.value
  key_ring = google_kms_key_ring.legal.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket" "evidence" {
  name                        = var.evidence_bucket_name
  project                     = var.project_id
  location                    = upper(var.region)
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  retention_policy {
    retention_period = var.evidence_retention_seconds
    is_locked        = var.lock_evidence_bucket
  }

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_project_service.required]
}

resource "google_access_context_manager_service_perimeter" "legal" {
  parent = "accessPolicies/${var.access_policy_id}"
  name   = "accessPolicies/${var.access_policy_id}/servicePerimeters/trustready_legal"
  title  = "TrustReady Legal"

  status {
    resources           = ["projects/${data.google_project.current.number}"]
    restricted_services = local.restricted_services

    vpc_accessible_services {
      enable_restriction = true
      allowed_services   = ["RESTRICTED-SERVICES"]
    }
  }

  depends_on = [google_project_service.required]
}
