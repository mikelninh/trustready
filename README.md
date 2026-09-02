# TrustReady 🛡️

**Turn “Can we trust this AI system?” into an inspectable evidence and remediation workflow.**

TrustReady is an engineering project for AI procurement and deployment readiness. It connects claims to evidence, identifies what is missing, explains why the gap matters and makes the path to closure explicit.

It does **not** issue a magic compliance score or certification.

> **Core principle:** TrustReady should still be useful if the buyer does not trust TrustReady.

## The workflow

```text
connect sources
   ↓
collect + hash evidence
   ↓
map evidence to controls
   ↓
run deterministic checks
   ↓
show supported / missing / stale / unknown
   ↓
prepare exact remediation
   ↓
re-scan
   ↓
produce an inspectable buyer / audit pack
```

## What every result should answer

For each control:

1. What is required?
2. Why does it matter?
3. What evidence was inspected?
4. What was actually observed?
5. What remains unknown?
6. How fresh is the evidence?
7. Can another reviewer reproduce the result?
8. What exact action closes the gap?

A `100/100` readiness result means **all controls in the selected profile have accepted evidence or explicit authorised attestation**. It does not mean universal legal compliance, certification, zero risk or government approval.

## Why this matters

Teams often have security docs, model cards, policies, test runs, architecture diagrams and procurement answers scattered across repositories and people.

TrustReady treats those as an evidence graph rather than a questionnaire:

`claim → control → evidence → observation → gap → remediation → re-check`

That creates a path from “we think we are ready” to **show me why**.

## Intended evidence layers

- governance and responsibility
- security controls
- privacy / data protection
- AI risk and model behaviour
- transparency and human oversight
- testing and evaluation
- operations / monitoring / rollback
- procurement and deployment evidence

## Framework mappings

The control model is designed to map to multiple frameworks without pretending to replace legal advice or formal certification, including:

- EU AI Act
- GDPR / data-protection evidence
- NIST AI RMF + GenAI Profile
- ISO/IEC 42001 mappings
- BSI-oriented AI/cloud assurance mappings where applicable
- customer-specific procurement requirements

## Current direction

The project is moving toward a reusable scanner + evidence contract that can be used through UI, API and machine-readable interfaces, with remediation and continuous evidence freshness as first-class concepts.

The strongest next validation is not a prettier score. It is whether an external buyer, auditor or security reviewer can reproduce the evidence trail and disagree with a result precisely.

## Boundary

TrustReady is an **engineering assurance layer**, not a certification body, regulator or substitute for qualified legal/security review.

Evidence can support a decision. **The system does not grant itself authority to approve deployment.**

## Go deeper

- [`docs/ENDGOAL.md`](docs/ENDGOAL.md)
- [`docs/TRUST_MODEL.md`](docs/TRUST_MODEL.md)

---

Built by [Michael Ninh](https://mikelninh.github.io/) in Berlin.
