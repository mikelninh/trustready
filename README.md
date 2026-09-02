# TrustReady 🛡️

**Control what AI may see, what it may do, and what can be proven afterwards.**

TrustReady is an evidence-first trust layer for AI systems. It connects claims to evidence, identifies what is missing, enforces deterministic boundaries outside the LLM and makes the path to closure inspectable.

It does **not** issue a magic compliance score or certification.

> **Core principle:** TrustReady should still be useful if the buyer does not trust TrustReady.

## Live Legal demos

- **Law-firm / Bao demo:** https://mikelninh.github.io/trustready/legal/
- **Bao shortcut:** https://mikelninh.github.io/trustready/bao/
- **Vietnamese-first client portal:** https://mikelninh.github.io/trustready/client/

These are public **synthetic** demonstrations only. They do not authorise real mandate data or claim production readiness. The client portal's demo file picker only changes local browser state; it does not transmit file contents.

## Two things live in this repository

### TrustReady Core

The reusable assurance and control infrastructure:

```text
claim / request
   ↓
identity + policy + evidence
   ↓
deterministic checks outside the LLM
   ↓
allow / deny / unknown
   ↓
immutable evidence + remediation
```

The scanner answers **“Can you prove this AI system is ready for this requirement?”**

The legal trust gateway answers **“May this sensitive data reach this AI service, may this action happen, and can the decision be evidenced?”**

### TrustReady Legal — first vertical proof

The strongest first wedge is **Vietnamese-first legal intake**:

```text
Vietnamese-speaking client
   ↓
clear checklist + missing-document upload
   ↓
completeness + formalities + contradictions
   ↓
one bundled follow-up instead of phone/email ping-pong
   ↓
German/bilingual structured matter for the law firm
   ↓
intake team resolves explicit open items
   ↓
Bao reviews original evidence + derived translation
   ↓
lawyer approves, requests correction or rejects
```

The current public browser demos use synthetic data only. Email, beA, case writes and other irreversible actions remain disabled.

The production-shaped portal security contract already covers opaque matter invitations, second-factor verification, tenant/matter-bound sessions, staff MFA/role separation, one-time upload capabilities, quarantine, malware-clean promotion, content hashes and database RLS. Those controls become production claims only after they are observed in the deployed environment.

Pilot success is deliberately measurable: **5 real workdays, at least 20 real work items, target ≥30 minutes net time saved per day, materially fewer calls/e-mails, zero unauthorised external actions, and Bao/team choose to keep using it.**

Useful entry points:
- [`docs/BAO_PRODUCTION_PILOT_PLAN.md`](docs/BAO_PRODUCTION_PILOT_PLAN.md)
- [`docs/CLIENT_PORTAL_SECURITY_ARCHITECTURE.md`](docs/CLIENT_PORTAL_SECURITY_ARCHITECTURE.md)
- [`docs/BAO_PILOT_RUNBOOK.md`](docs/BAO_PILOT_RUNBOOK.md)
- [`docs/LEGAL_EXTERNAL_REVIEW_REQUEST.md`](docs/LEGAL_EXTERNAL_REVIEW_REQUEST.md)
- [`core/legal-client-portal.mjs`](core/legal-client-portal.mjs)
- [`core/legal-client-portal.test.mjs`](core/legal-client-portal.test.mjs)
- [`infra/gcp-legal-shadow/pilot_schema.sql`](infra/gcp-legal-shadow/pilot_schema.sql)
- [Golden Shadow Pilot tracker #17](https://github.com/mikelninh/trustready/issues/17)

Check the local promotion gate with:

```bash
npm run readiness:bao
```

An environment flag alone cannot promote real mandate data or sending. The higher live/legal/independent verdicts must actually exist.

## Scanner workflow

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

For sensitive AI workflows it adds a second invariant:

`identity → data → policy → exact request → egress decision → human authority → evidence`

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

The control model is designed to map controls to multiple frameworks without pretending to replace legal advice or formal certification, including:

- EU AI Act
- GDPR / data-protection evidence
- NIST AI RMF + GenAI Profile
- ISO/IEC 42001 mappings
- BSI-oriented AI/cloud assurance mappings where applicable
- customer-specific procurement requirements

## Promotion boundary

TrustReady deliberately separates engineering proof from real-world authority:

```text
public synthetic demo
  ↓
production-shaped synthetic pilot
  ↓
engineering pre-audit
  ↓
qualified live environment
  ↓
authorised legal/privacy review
  ↓
independent security/evidence review
  ↓
real mandate shadow pilot
  ↓
measured pilot success
  ↓
separate release for narrowly typed human-approved actions
```

A lower stage cannot self-promote to a higher one.

TrustReady is an **engineering assurance layer**, not a certification body, regulator or substitute for qualified legal/security review. Evidence can support a decision. **The system does not grant itself authority to approve deployment.**

## Go deeper

- [`docs/ENDGOAL.md`](docs/ENDGOAL.md)
- [`docs/TRUST_MODEL.md`](docs/TRUST_MODEL.md)
- [`docs/LEGAL_PRODUCT_GOAL.md`](docs/LEGAL_PRODUCT_GOAL.md)
- [`docs/BAO_PRODUCTION_PILOT_PLAN.md`](docs/BAO_PRODUCTION_PILOT_PLAN.md)
- [`docs/CLIENT_PORTAL_SECURITY_ARCHITECTURE.md`](docs/CLIENT_PORTAL_SECURITY_ARCHITECTURE.md)
- [`docs/LEGAL_EXTERNAL_REVIEW_REQUEST.md`](docs/LEGAL_EXTERNAL_REVIEW_REQUEST.md)

---

Built by [Michael Ninh](https://mikelninh.github.io/) in Berlin.