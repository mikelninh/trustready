# TrustReady Agent Security Proof — Founding Pilot

Status: **sell now**

## Offer

**€1,500 fixed price + VAT for the first 3 teams.**

Expected standard price after the founding cohort: **€3,500+ per scoped workflow**, depending on effect surface and integration complexity.

Duration: **7 calendar days after access and scope are confirmed.**

Scope: **one AI agent or automation workflow**, up to five consequential capabilities/effect paths, in an owned or explicitly authorized environment.

If discovery shows there is no meaningful consequential effect surface worth testing, the paid pilot does not start.

## The promise

We answer one concrete question:

> **Can this AI system reach a real effect it should not be able to reach — and can we prove that the boundary stops it without breaking legitimate work?**

The pilot produces reproducible before/after evidence instead of a generic security checklist.

## Deliverables

1. **Capability + effect map**
   - agent entrypoints
   - tools / APIs / executors
   - authority inputs
   - consequential effects
   - tenant / data / egress boundaries

2. **Named attack suite**
   - prompt / document / tool-result injection where relevant
   - cross-tenant or cross-scope attempts
   - missing authority / approval
   - protected-data or sensitive-egress attempts
   - execution-budget / excessive-agency cases where relevant

3. **Controlled baseline**
   - safe test-only mutation, synthetic vulnerable fixture, or existing reachable pre-boundary evidence
   - same named inputs as the protected run
   - no third-party or unauthorized targets

4. **Boundary implementation / hardening**
   - deterministic policy or capability guard
   - explicit authority propagation
   - fail-closed behavior before the real effect sink
   - patch or implementation recommendations, depending on access model

5. **Security Delta retest**
   - before vs after impact escapes
   - executor / network / write calls
   - holdout cases when the target permits a clean split
   - benign-control retention

6. **CI regression gate**
   - machine-readable proof artifact
   - fail-on-impact regression rule
   - exact target commit/revision

7. **Decision brief**
   - strongest evidence
   - remaining unknowns
   - what is not proven
   - recommended next security work

## Acceptance criteria

A completed pilot must:

- run the **same named attack inputs** against a weakened/baseline path and the real protected path;
- measure impact at the **effect boundary**, not just whether a prompt looked malicious;
- record **zero post-boundary critical impact escapes for the scoped release set**;
- retain legitimate benign behavior (target: **100%**, hard minimum for a publishable result: **90%**);
- record exact commit/revision identifiers;
- preserve an explicit truth boundary;
- fail closed if evidence is incomplete.

## What this is not

This pilot is **not**:

- a penetration test;
- a certification;
- a claim that prompt injection is solved;
- a guarantee that a production system has no unknown vulnerabilities;
- authorization to test systems the client does not own or control.

It is scoped, causal engineering evidence for the named agent/effect paths tested.

## Ideal customer

Best fit when an AI agent can do one or more of the following:

- send messages or emails;
- call customers;
- create / update / delete CRM or business records;
- trigger payments, claims, orders or financial decisions;
- run commands or code;
- access multiple tenants, cases or customers;
- call external APIs;
- publish content;
- move regulated or sensitive data;
- make legal, healthcare, insurance, compliance or financial workflow decisions.

## Poor fit

Do not sell the pilot when:

- the product is a text-only copilot with no consequential effects;
- the team will not provide a sandbox / owned test environment;
- the requested work depends on attacking third-party systems without explicit authorization;
- the customer expects a certification badge rather than engineering evidence;
- the team is unwilling to preserve explicit limitations and unknowns.

## Founding cohort target

Goal: **3 paid pilots**.

Success metric for the commercial experiment:

- 30 qualified targets
- 10 personalized outreaches
- 5 discovery calls
- 3 scoped proposals
- 1+ paid pilot within 30 days

## Proof we lead with

TrustReady Security Delta Benchmark v1:

- 4 real repositories / 4 architecture families
- 14 named attack cases
- measured impact escapes: **14 → 0**
- frozen holdouts: **6/6 contained**
- benign controls: **7/7 retained**

Truth boundary: the benchmark is controlled engineering evidence over named scenarios and exact revisions. It is not an estimate of real-world breach probability or a production-security certification.
