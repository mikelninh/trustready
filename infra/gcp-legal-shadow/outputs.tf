output "network_name" {
  value = google_compute_network.legal.name
}

output "subnetwork_name" {
  value = google_compute_subnetwork.legal.name
}

output "gateway_instance_name" {
  value = google_compute_instance.legal_gateway.name
}

output "gateway_instance_id" {
  value = google_compute_instance.legal_gateway.instance_id
}

output "gateway_zone" {
  value = google_compute_instance.legal_gateway.zone
}

output "gateway_service_account" {
  value = google_service_account.legal_gateway.email
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
    project_id              = var.project_id
    project_number          = data.google_project.current.number
    region                  = var.region
    subnetwork              = google_compute_subnetwork.legal.name
    service_perimeter_name  = google_access_context_manager_service_perimeter.legal.name
    protected_resource      = "projects/${data.google_project.current.number}"
    gateway_instance_name   = google_compute_instance.legal_gateway.name
    gateway_instance_id     = google_compute_instance.legal_gateway.instance_id
    gateway_zone            = google_compute_instance.legal_gateway.zone
    gateway_service_account = google_service_account.legal_gateway.email
    evidence_bucket         = google_storage_bucket.evidence.name
  }
}
