# TrustReady monetisation model

## Principle

Do not charge for opacity. Charge for useful work.

The verification model, profile versions, evidence states and manifest integrity checks should remain inspectable enough that buyers can independently understand a TrustReady result.

Revenue comes from collection depth, private evidence handling, remediation, monitoring, procurement automation and high-assurance workflows.

## Surfaces

### 1. Human web app
Acquisition and self-serve remediation.

Free:
- public GitHub repository scan
- evidence-backed score
- inspectable controls
- basic path to 100

Paid:
- private repository/evidence workspace
- historical scans and drift
- remediation actions
- trust centre / buyer pack
- questionnaire automation

### 2. REST API
For CI, platforms and procurement systems.

Recommended initial model:
- free developer key: 25 public scans/month
- Developer: EUR 49/month, 500 API units
- Team: EUR 249/month, 5,000 API units + private evidence + webhooks
- Enterprise: EUR 999+/month, negotiated limits + SSO/RBAC + retention controls + support

API units should reflect work rather than raw HTTP requests. A public scan might cost 1 unit; a private deep scan 5; a runtime proof 10; a questionnaire job 25+.

### 3. MCP
For agent clients and autonomous workflows.

Free tools:
- `scan_public_repository`
- `explain_control_gap`
- `verify_assurance_manifest`

Paid tools (planned):
- `scan_private_workspace`
- `generate_remediation_patch`
- `run_runtime_proof`
- `generate_buyer_pack`
- `answer_procurement_questionnaire`
- `monitor_assurance_drift`

Support two payment modes:
1. normal account/API-key credits for companies;
2. x402 per-call payments for autonomous agents.

Never allow a payment path to weaken evidence requirements or buy a higher score.

### 4. WebMCP
For browser agents operating while a human is on the TrustReady site.

WebMCP should primarily expose read-only scan/explanation tools and user-mediated remediation actions. Consequential actions such as connecting private sources, creating PRs, signing attestations or purchasing services require explicit user interaction/authority.

## Value ladder

### Free — TrustReady Scan
Goal: distribution.

Output:
- readiness score
- evidence graph
- blocking gaps
- shortest path to 100

### EUR 49/month — Developer
Goal: become part of the build loop.

Adds:
- private GitHub repositories
- 500 monthly API units
- scan history
- CI readiness gate
- change diff
- evidence expiry alerts

### EUR 249/month — Team
Goal: become part of the enterprise-sales loop.

Adds:
- team workspace
- private evidence uploads/connectors
- remediation PR generation
- buyer trust centre
- buyer pack
- webhooks/API
- authenticated control owners

### EUR 999+/month — Enterprise / Procurement
Goal: eliminate repetitive due diligence work.

Adds:
- questionnaire automation
- SSO/RBAC
- multi-product portfolio
- reviewer links
- custom profiles/framework mappings
- audit history
- retention/deletion settings
- procurement workflow integrations

### High-assurance / Government
Custom annual contract.

Adds:
- environment-specific runtime evidence
- four-eyes reviewer workflow
- signed attestations
- chain of custody
- independent manifest verification
- private/on-prem/VPC deployment where required
- qualified assurance/security reviewer workflow

TrustReady must not present this tier as replacing legal advice, formal certification, conformity assessment or public authority.

## Usage pricing / x402

Agent-native per-call pricing should be used for valuable completed work rather than tiny wrapper calls.

Illustrative starting points:
- public evidence scan: free or EUR 0.10 equivalent
- private/deep scan: EUR 1–3
- remediation package: EUR 5–20
- runtime proof job: EUR 2–20 depending on compute/complexity
- buyer pack refresh: EUR 5
- questionnaire job: EUR 10–50 depending on size

Subscriptions should include credits so normal companies have predictable bills. x402 provides a second rail for agents without requiring a subscription first.

## Commercial flywheel

```text
free public scan
  ↓
visible blockers
  ↓
customer wants to close gaps
  ↓
paid remediation / private evidence
  ↓
re-scan + before/after proof
  ↓
shareable buyer pack
  ↓
customer uses it in enterprise sale
  ↓
continuous monitoring subscription
  ↓
API/MCP embedded in build/procurement workflow
```

The core promise remains invariant through every tier:

> Money can buy more collection, remediation and assurance work. It can never buy a verified status without the required evidence.
