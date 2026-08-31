# TrustReady Trust Model

## Threat model

TrustReady assumes all of these can happen:

- a vendor overstates maturity
- a policy exists but is not implemented
- a repository README is outdated
- AI extraction misreads a document
- an evidence source changes after a scan
- a buyer sees only a curated subset
- a control is valid in staging but not production
- a human attestor is wrong or unauthorised
- a framework changes
- TrustReady itself has a bug

Therefore no single source, model output or score is authoritative.

## Evidence states

TrustReady uses explicit states:

- `not_observed` — no accepted evidence was available from connected sources
- `candidate` — heuristic/AI discovery suggests relevant evidence; no control credit
- `partial` — accepted evidence supports part of the control
- `verified` — accepted evidence satisfies the profile's deterministic rule
- `attested` — authorised human assertion satisfies an attestation-only requirement
- `stale` — previously accepted evidence is outside freshness policy
- `regressed` — previously accepted technical proof now fails
- `not_applicable` — applicability decision is recorded with rationale and authority
- `blocked` — material contradiction or unresolved high-severity finding prevents readiness

`candidate` evidence never contributes verified control credit.

## Evidence strength

Each evidence item has a strength class:

| Class | Example | Typical trust |
|---|---|---|
| E0 | model inference / keyword heuristic | discovery only |
| E1 | vendor-authored policy/document | assertion |
| E2 | repository/configuration/CI proof | technical evidence |
| E3 | deployment/runtime observation | environment evidence |
| E4 | signed authorised attestation | accountable assertion |
| E5 | independent audit/certification/test | external evidence |

A readiness profile specifies the minimum class or combination required for each control.

Example: a security policy (`E1`) can prove that a policy exists. It cannot by itself prove that MFA is enforced in production; that may require `E3` deployment evidence.

## Provenance contract

Every evidence record must include:

```json
{
  "evidence_id": "ev_...",
  "type": "browser_e2e",
  "source": "...",
  "subject": "production-app",
  "observed_at": "2026-08-31T12:00:00Z",
  "valid_until": "2026-09-30T12:00:00Z",
  "sha256": "...",
  "collector": "trustready-browser-v1",
  "collector_version": "1.0.0",
  "environment": "production",
  "sensitivity": "internal",
  "raw_available": true
}
```

Derived observations reference evidence IDs rather than copying unsupported prose.

## Control result contract

```json
{
  "control_id": "TR-GOV-001",
  "profile_id": "enterprise-ai-procurement-eu",
  "profile_version": "2026.08",
  "rule_id": "rule-human-oversight-v2",
  "rule_version": "2.0.0",
  "status": "verified",
  "evidence_ids": ["ev_123", "ev_456"],
  "observations": ["external action requires named human approval"],
  "unknowns": [],
  "expires_at": "2026-09-30T12:00:00Z",
  "reproducible": true
}
```

## Scoring

A headline readiness score is a convenience, not the primary assurance object.

The scoring model must satisfy:

- no credit from E0/candidate evidence
- weighted controls are profile-versioned
- blocking findings override a high score
- stale evidence loses verified status
- `not_applicable` never silently improves coverage; the rationale remains visible
- attestation-heavy readiness is visibly distinguishable from independently observed readiness

Every result also exposes:

- `coverage_pct`
- `verified_pct`
- `independent_evidence_pct`
- `attested_pct`
- `fresh_pct`
- `blocking_findings`

## Rule transparency

Every rule must be inspectable as code or declarative logic.

The system must be able to answer:

- Why did this control pass?
- Why did it fail?
- Which evidence changed the result?
- Which rule version was used?
- Can I reproduce it locally?

Opaque LLM judgement cannot be the only reason for a control result.

## Human attestation

Some facts cannot be proven from code, such as organisational responsibility or legal-role determinations.

Attestations require:

- authenticated identity
- role/authority
- exact statement
- scope/environment
- timestamp
- expiry
- signature or tamper-evident record

An attestation never gets presented as independent technical proof.

## Contradiction handling

When evidence conflicts, TrustReady does not choose the prettier answer.

Example:

- policy says external actions require approval
- runtime test shows an action executes without approval

Result: `blocked` or `regressed`, with both evidence sources visible.

Technical/runtime evidence normally outranks policy assertion for implementation claims.

## Reproducibility

A high-assurance scan pins:

- source revisions / evidence hashes
- control profile version
- rule bundle version
- collector versions
- scan configuration
- generated manifest hash

The open verifier validates manifest integrity and deterministic results without requiring access to TrustReady's SaaS.

## TrustReady's own assurance

TrustReady must dogfood itself.

Production releases should publish an assurance manifest containing at least:

- build commit
- dependency/SBOM evidence
- tests/evals
- scanner false-positive/false-negative benchmark
- security/privacy controls
- incident process
- change history for rules/profiles
- known limitations

Critical rule changes require review and regression tests. Historical scan results remain tied to their original rule/profile versions.
