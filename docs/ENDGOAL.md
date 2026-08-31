# TrustReady — End Goal

## North star

TrustReady becomes the **evidence and assurance layer for buying and deploying AI systems**.

A developer should be able to connect a repository and get useful gaps in minutes. A company should be able to answer buyer due-diligence from the same evidence. A public authority should be able to independently inspect and reproduce every material claim.

The product wins when a buyer can move from:

> “We cannot verify this AI vendor.”

To:

> “Here are the exact controls, proofs, limitations, owners, expiry dates and unresolved risks. We can make an informed procurement decision.”

## What the ideal product looks like

### 1. One input surface

Connect any combination of:

- public/private GitHub repositories
- deployed application URL
- cloud/deployment configuration
- policies and security documents
- subprocessors and model providers
- test/evaluation results
- incident-response records
- data-flow diagrams
- DPA/TOM/privacy documents
- external certifications/audit reports
- human attestations from named authorised roles

TrustReady never treats source absence as proof of control absence. It reports `not_observed` and asks for the missing evidence source.

### 2. Evidence graph, not questionnaire theatre

Every collected item becomes an immutable evidence record:

```text
source
→ exact observation
→ content hash
→ collection timestamp
→ validity / expiry
→ sensitivity classification
→ applicable controls
→ rule version
→ result
```

Evidence is separable from interpretation. Buyers can inspect the original source whenever permission allows.

### 3. Deterministic verification first

AI may:

- discover candidate evidence
- extract structured facts
- map documents to likely controls
- explain gaps in plain language
- draft remediation artefacts

AI may **not** award a verified control merely because text sounds convincing.

`verified` requires an accepted evidence type plus a deterministic rule or explicit authorised attestation according to the selected assurance profile.

### 4. Assurance profiles

The same product supports increasing assurance requirements.

#### L1 — Developer readiness

Purpose: fast self-service improvement.

Accepted evidence may include public repo artefacts, CI results, architecture docs and explicit project policies.

Output:
- readiness score
- top gaps
- generated remediation drafts
- public trust page

#### L2 — Enterprise procurement

Purpose: support vendor security / AI procurement reviews.

Adds:
- authenticated source collection
- named control owners
- model/subprocessor inventory
- deployment-specific proof
- privacy/security evidence
- evidence expiry
- buyer questionnaire mapping
- signed organisational attestations

Output:
- buyer pack
- questionnaire answer library
- trust centre
- machine-readable evidence manifest

#### L3 — Regulated / government assurance

Purpose: support high-assurance procurement and review; not replace legal authority or certification.

Adds:
- strict evidence provenance and chain of custody
- separation of vendor assertions from independently observed proof
- rule/version pinning
- reproducible scans
- signed attestations
- reviewer workflow and four-eyes approval
- audit log
- evidence freshness SLAs
- deployment/environment-specific controls
- formal exceptions and risk acceptance
- independent external evidence where required

Output:
- assurance dossier
- reviewer decision record
- unresolved-risk register
- signed/verifiable evidence manifest

### 5. No single magic score

TrustReady may show a headline score for usability, but underneath it must expose:

- coverage: how many applicable controls have evidence
- assurance: strength of the evidence
- freshness: whether evidence is current
- unresolved risk: material open findings
- attestation share: how much relies on human assertions
- independent-proof share: how much is externally or technically observed

Two systems with `90/100` can therefore be visibly different.

### 6. Gap-to-ready engine

After every scan, TrustReady generates the shortest safe path to readiness.

Each gap has:

```json
{
  "control": "TR-AI-004",
  "status": "partial",
  "missing": ["deployment placement proof"],
  "why_it_matters": "buyer cannot verify user-facing AI disclosure",
  "can_automate": true,
  "suggested_action": "add disclosure component and run browser assertion",
  "required_proof": ["browser_e2e", "screenshot_hash"],
  "owner_role": "product",
  "blocking": true
}
```

Automation can generate files, tests, disclosures, inventories, trust pages and questionnaire answers. It cannot self-attest legal conclusions, organisational practice or controls it cannot observe.

### 7. Continuous assurance

Readiness is not permanent.

TrustReady monitors:

- dependency/model/vendor changes
- policy changes
- expired attestations/certificates
- deployment changes
- failing CI/evals
- new subprocessors
- changed data flows
- new regulatory/control-profile versions

A previously verified control can become `stale` or `regressed` automatically.

### 8. Buyer verification without TrustReady

Every buyer pack has a machine-readable manifest containing:

- evidence hashes
- source identifiers
- timestamps
- rule IDs + versions
- profile version
- result calculation
- signatures where available

An open-source verifier should be able to reproduce manifest integrity locally.

This is the strongest product principle:

> **Do not ask the buyer to trust TrustReady. Give them enough evidence to verify TrustReady.**

## Product surfaces

### Free Scan

Paste GitHub/app URL → evidence coverage → gaps → top 3 actions.

Goal: acquisition and immediate developer value.

### TrustReady Workspace

Connect private sources, resolve gaps, assign owners, generate artefacts, approve attestations and continuously re-scan.

### Trust Center

Public/private shareable buyer view with current proofs, limitations and freshness.

### Questionnaire Autopilot

Upload buyer questionnaire → answer only from verified evidence → cite every answer → mark unknowns rather than inventing answers.

### Buyer / Government Review Portal

Reviewer can filter by framework, inspect proof, request evidence, challenge a control, record exception/risk acceptance and export a decision dossier.

### API / CLI / CI

Developers can fail a release when a blocking control regresses.

## Framework strategy

TrustReady owns a stable internal control ontology and maps external frameworks onto it.

External profiles are versioned separately, e.g.:

- EU AI Act / Commission guidance profile
- NIST AI RMF / GenAI profile
- ISO/IEC 42001 mapping
- BSI-oriented AI/cloud assurance mapping
- GDPR/privacy procurement mapping
- custom buyer questionnaire profile

Framework updates never silently rewrite historical scan results.

## What TrustReady must never claim

- “legally compliant” solely from automated scanning
- “government approved” without the relevant authority
- certification it has not been accredited to issue
- security of an environment it did not inspect
- operational practice from a policy document alone
- absence of risk because no evidence of risk was found

## End-state moat

The moat is not the checklist.

It is the growing system of:

1. precise control ontology
2. accepted evidence schemas
3. deterministic verification rules
4. framework mappings
5. remediation recipes
6. continuous evidence history
7. reproducible buyer proofs
8. real procurement outcomes showing which evidence actually clears reviews
