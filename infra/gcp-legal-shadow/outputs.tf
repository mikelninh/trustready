output "network_name" {
  value = google_compute_network.legal.name
}

output "subnetwork_name" {
  value = google_compute_subnetwork.legal.name
}

output "evidence_bucket" {
  value = google_storage_bucket.evidence.name
}

output "evidence_retention_locked" {
  value = google_storage_bucket.evidence.retention_policy[0].is_locked
}

output "service_perimeter_name" {
  value = google_access_context_manager_service_perimeter.legal.name
}

output "hsm_key_version_prefixes" {
  value = {
    for name, key in google_kms_crypto_key.attestors : name => key.id
  }
  description = "CryptoKey resources. Qualification resolves and pins the enabled HSM CryptoKeyVersion/public key separately."
}

output "qualification_profile" {
  value = {
    project_id             = var.project_id
    project_number         = var.project_number
    region                 = var.region
    subnetwork             = google_compute_subnetwork.legal.name
    service_perimeter_name = google_access_context_manager_service_perimeter.legal.name
    protected_resource     = "projects/${var.project_number}"
    evidence_bucket        = google_storage_bucket.evidence.name
  }
}
