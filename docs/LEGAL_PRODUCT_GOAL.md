# TrustReady Legal — Product Goal

## One sentence

**Let law firms use AI for sensitive legal work without giving up control over mandate data, irreversible actions, or the evidence needed to explain what happened.**

TrustReady Legal is not a chatbot and not a replacement for a lawyer. It is a **trust and workflow layer** between the law firm, its systems and AI providers.

## The user-facing workflow

```text
incoming work
  ↓
resolve matter / context
  ↓
extract task + deadline + risk
  ↓
prepare a proposal or draft
  ↓
show evidence / uncertainty / source context
  ↓
lawyer approves, edits or rejects
  ↓
only an explicitly authorised action may execute
  ↓
produce an independently inspectable evidence trail
```

For the first Bao pilot the last execution step stays disabled. The product operates in **Shadow Mode**.

## What the pilot must prove

The first pilot is successful only if it proves both **utility** and **control**.

### Utility

- at least 20 real work items over 5 real workdays;
- materially useful matter assignment, task/deadline extraction and drafts;
- at least 30 minutes of measured net time saved per day as the target;
- Bao would choose to keep using it after the pilot.

### Control

- zero unauthorised external actions;
- no autonomous email, beA, case writes or irreversible workflow actions;
- sensitive AI egress is policy-controlled outside the LLM;
- the exact outbound request has immutable pre-send evidence;
- actual outcomes have post-send evidence when a send is permitted;
- the local product cannot self-declare legal compliance, independent assurance or real-mandate readiness.

## Product layers

### 1. TrustReady Protect

The deterministic security boundary:

- identity and matter authorisation;
- MFA / resource-version binding;
- data classification and DLP;
- provider / use-case / region policy;
- exact target + exact payload egress control;
- HSM-backed signatures;
- restricted transport;
- immutable pre-send intent and evidence storage;
- kill switches and fail-closed behaviour.

### 2. TrustReady Legal Workflow

The visible daily value:

- inbox / intake triage;
- matter resolution;
- task and deadline extraction;
- risk surfacing;
- draft generation;
- human approval, edit and rejection;
- measured time saved and acceptance rate.

### 3. TrustReady Verify + Evidence

The reason a lawyer, DPO, insurer or auditor can inspect the system:

- source/provenance display;
- claim-level uncertainty;
- temporal/jurisdiction checks where applicable;
- contradiction and deadline checks;
- signed decision/evidence records;
- reproducible evidence packs;
- explicit unknowns instead of invented assurance.

## What we are not building

- an autonomous lawyer;
- a system that silently sends mail or beA messages;
- a generic legal chatbot with unrestricted access to mandate data;
- a compliance badge that TrustReady awards to itself;
- a promise of zero hallucinations or zero security risk;
- a replacement for independent legal, privacy or security review.

## Long-term product

The reusable product is:

> **Bring your AI. Bring your Kanzleisoftware. TrustReady controls what it may see, what it may do, and what can be proven afterwards.**

The Bao pilot is the first vertical proof. Once the workflow and evidence model work in a real firm, the same TrustReady Core can sit in front of different AI providers and law-firm systems.

## Promotion ladder

```text
SYNTHETIC PRODUCT DEMO
  ↓
ENGINEERING PRE-AUDIT READY
  ↓
LIVE DEDICATED GCP ENVIRONMENT QUALIFIED
  ↓
AUTHORISED LEGAL / PRIVACY REVIEW COMPLETE
  ↓
INDEPENDENT SECURITY / EVIDENCE REVIEW COMPLETE
  ↓
REAL MANDATE SHADOW PILOT
  ↓
MEASURED PILOT SUCCESS
  ↓
HUMAN-APPROVED PRODUCTION ACTIONS (separate release)
```

A lower stage must never self-promote to a higher one.

## Current cut

Repository engineering and the synthetic product demo can be completed by the engineering team.

The following are deliberately external go-live gates rather than more repository feature work:

- provision and qualify the exact GCP deployment;
- deliberately lock the real WORM bucket;
- collect live operating evidence;
- execute provider/DPA/BRAO/GDPR assessment for the exact deployment;
- independent penetration/evidence review;
- connect the first real read-only work source with Bao's explicit authorisation;
- run the 5-day measured shadow pilot.
