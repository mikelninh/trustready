# TrustReady Legal — GCP Mandate Shadow Reference

This is the concrete reference infrastructure for the first real mandate-data **shadow** pilot. It is deliberately narrower than a generic cloud deployment.

## Security properties

- Region defaults to `europe-west3` (Frankfurt).
- VPC has no default subnets and Private Google Access is enabled.
- Egress is network-wide deny-by-default.
- The only explicit egress allow is TCP/443 to `199.36.153.4/30` (`restricted.googleapis.com`).
- Private DNS maps `*.googleapis.com` to `restricted.googleapis.com`.
- VPC Service Controls protects Vertex AI, Cloud KMS/HSM, Sensitive Data Protection and Cloud Storage and restricts VPC-accessible services.
- Four separate asymmetric signing keys use `EC_SIGN_P256_SHA256` with `HSM` protection.
- Evidence storage has uniform bucket-level access, public access prevention and a retention policy.
- `force_destroy = false` and Terraform `prevent_destroy` protect the evidence bucket and HSM keys.

## Important irreversible step

`lock_evidence_bucket` defaults to **false**.

When changed to `true` and applied, Google Cloud Bucket Lock permanently locks the bucket retention policy. It cannot subsequently be shortened, removed or unlocked. Do not enable it during experimentation. Review the project, bucket name and retention duration first, then apply the lock as a separate, deliberate production change.

## Provisioning sequence

1. Create a dedicated GCP project under the intended EU/organization controls.
2. Obtain its project number and the organization's Access Context Manager access-policy ID.
3. Use a globally unique evidence bucket name.
4. Run `terraform plan` with `lock_evidence_bucket=false`.
5. Apply and run the TrustReady infrastructure qualification against the real resources.
6. Confirm HSM, DLP, network and WORM posture is otherwise green.
7. Review the retention period and evidence bucket with Bao/security/legal reviewers.
8. Set `lock_evidence_bucket=true`, generate a fresh plan and review the irreversible change.
9. Apply the lock.
10. Re-run qualification. Only a live qualification whose HSM-signed result is itself stored in the locked bucket may support `CANDIDATE_FOR_REAL_MANDATE_SHADOW_PILOT`.

## What this does not claim

Committing this Terraform does **not** prove that the resources currently exist or are correctly deployed. Static configuration is E2-style evidence only. TrustReady intentionally requires live runtime/API evidence before production readiness.

The first pilot remains shadow-only: no autonomous mail, beA transmission, deadline mutation or case write.
