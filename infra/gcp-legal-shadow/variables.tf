variable "project_id" {
  description = "Dedicated GCP project ID for the TrustReady Legal shadow environment."
  type        = string
}

variable "access_policy_id" {
  description = "Organization Access Context Manager policy ID. Required for an enforced VPC Service Controls perimeter."
  type        = string
}

variable "region" {
  description = "EU region for the pilot. Frankfurt is the default."
  type        = string
  default     = "europe-west3"
}

variable "gateway_zone" {
  description = "Single GCE zone for the dedicated TrustReady Legal shadow gateway workload."
  type        = string
  default     = "europe-west3-a"
}

variable "gateway_machine_type" {
  description = "Machine type for the dedicated mandate-shadow gateway."
  type        = string
  default     = "e2-small"
}

variable "evidence_bucket_name" {
  description = "Globally unique GCS bucket name for immutable TrustReady evidence."
  type        = string
}

variable "evidence_retention_seconds" {
  description = "Minimum immutable evidence retention period. Locking is irreversible."
  type        = number
  default     = 2592000
  validation {
    condition     = var.evidence_retention_seconds >= 2592000
    error_message = "Evidence retention must be at least 30 days."
  }
}

variable "lock_evidence_bucket" {
  description = "IRREVERSIBLE. Set true only after reviewing the plan; a locked retention policy cannot be shortened or removed."
  type        = bool
  default     = false
}
