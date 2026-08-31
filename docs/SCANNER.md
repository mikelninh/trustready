# TrustReady Scanner — Evidence Contract

The scanner is a discovery-and-verification pipeline, not a compliance oracle.

## Core rule

> Discovery can be probabilistic. Verification must be deterministic and inspectable.

A keyword, LLM inference, README claim or marketing page may help TrustReady **find** possible evidence. It cannot by itself upgrade a control to `verified` unless a versioned promotion rule accepts the required evidence class.

## Pipeline

```text
subject + selected assurance profile
        ↓
collect immutable/source evidence
        ↓
collect narrow external observations
        ↓
heuristic candidate discovery (E0)
        ↓
versioned deterministic promotion rules
        ↓
trust kernel evaluates minimum evidence strength
        ↓
verified / attested / partial / candidate / not_observed / stale / blocked
        ↓
explain exact gap + next proof
```

## Evidence lanes

### Public repository collector

Pins the scan to an immutable Git commit SHA and records:

- repository URL;
- source path;
- source revision;
- content SHA-256;
- observation timestamp;
- evidence validity window;
- collector version;
- promotion rule ID;
- promotion ruleset version.

It can establish repository-level E1/E2 evidence when a deterministic rule accepts a dedicated artifact.

It **cannot** prove deployment/runtime, legal, organisational or independent-audit controls merely from source code or documents.

### Public URL observer

Makes a narrow external HTTP observation and records the returned content hash and timestamp.

The first runtime rule verifies only explicit user-facing AI disclosure when the disclosure is actually visible in the observed page response.

The URL observer does not infer hidden configuration, tenant isolation, deletion behaviour, monitoring, incident response or other internal controls.

## Status semantics

- `verified` — accepted evidence meets the selected profile's deterministic rule and minimum evidence strength.
- `attested` — an attestation-only control has a valid authorised attestation.
- `partial` — relevant accepted evidence exists but is too weak for the selected profile.
- `candidate` — potential evidence was discovered heuristically; it earns no verified credit.
- `not_observed` — the selected collectors did not observe accepted evidence. This is **not proof that the control is absent**.
- `stale` — evidence existed but is outside its validity window.
- `blocked` — contradictory evidence exists or another explicit blocker prevents readiness.
- `not_applicable` — the versioned profile explicitly excludes the control for this subject/scope.

## Safety metric

The primary scanner release metric is **false verified rate**.

A false negative creates more review work. A false positive can cause a buyer to trust a control that is not actually proven. Therefore CI fails if any labelled negative case becomes `verified`.

The benchmark also reports:

- verified precision;
- verified recall;
- exact status agreement;
- per-control metrics;
- provenance completeness.

## What a reviewer can inspect

Every control result exposes:

1. control ID and title;
2. profile ID/version;
3. current status;
4. required minimum evidence strength;
5. whether independent/runtime proof is required;
6. evidence IDs and source links;
7. observation and expiry timestamps;
8. content hash;
9. deterministic promotion rule ID/version;
10. why the current evidence is or is not sufficient;
11. exact next proof needed;
12. remediation lane: automatable/documentable, runtime technical proof, accountable/legal attestation, or human/security review.

## Important boundary

A `100` score means all applicable controls in the **selected versioned profile** are satisfied by accepted evidence or authorised attestation at the scan time.

It does **not** mean:

- legal compliance is guaranteed;
- a regulator has approved the system;
- an ISO/BSI certification has been granted;
- the product is risk-free;
- all possible controls are covered;
- evidence remains valid forever.

TrustReady should make claims easier to challenge and reproduce, not harder.
