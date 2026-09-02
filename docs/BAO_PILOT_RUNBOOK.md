# Bao Golden Shadow Pilot — Runbook

## Purpose

Prove that TrustReady Legal can remove real administrative/legal-workflow friction **without** granting the AI autonomous authority over mandate data or irreversible actions.

This runbook begins only after the exact deployment has passed the required live operating, legal/privacy and independent review gates. Repository engineering alone does not authorise real mandate data.

## Pilot shape

- Duration: **5 real workdays**
- Minimum sample: **20 real work items**
- Mode: **read-only / proposal-only Shadow Mode**
- Human: Bao or another explicitly authorised lawyer reviews every proposal
- External execution: **disabled**
- Primary target: **≥30 minutes measured net time saved per day**
- Hard safety target: **0 unauthorised external actions**

## Workflow under test

```text
incoming work
  ↓
read-only intake
  ↓
resolve matter / flag unresolved
  ↓
extract task / deadline / risk
  ↓
prepare draft or internal proposal
  ↓
show source context + uncertainty
  ↓
Bao accepts / edits / rejects
  ↓
record privacy-minimised pilot metrics
```

No email, beA submission, case write, deadline write or task completion is executed by the pilot.

## Pre-flight — all required before first real item

### Deployment / operating evidence

- [ ] exact dedicated GCP legal-shadow deployment exists;
- [ ] authenticated runtime identity matches the intended project/workload;
- [ ] four purpose-separated HSM keys are live and verified;
- [ ] EU Sensitive Data Protection configuration is live and pinned;
- [ ] restricted Google API transport and effective firewall/VPC-SC evidence are live;
- [ ] exact evidence bucket is pinned to the gateway;
- [ ] irreversible WORM retention lock has been deliberately applied and verified;
- [ ] secrets manager sourcing/rotation evidence exists;
- [ ] incident kill-switch and credential-revocation drill completed;
- [ ] backup/restore evidence completed where applicable;
- [ ] current SBOM/vulnerability review completed;
- [ ] upload malware scanning is present if file uploads enter scope.

### Legal / privacy

- [ ] exact provider/model/use case identified;
- [ ] exact AVV/DPA reviewed;
- [ ] BRAO §43e assessment completed for the exact deployment;
- [ ] subprocessor chain documented;
- [ ] transfer assessment/safeguards completed where applicable;
- [ ] VVT / record of processing updated;
- [ ] DPIA/DSFA screening/result recorded;
- [ ] EU AI Act use-case classification recorded;
- [ ] pilot-user AI-literacy / operating instructions documented.

### Independent review

- [ ] independent security review/pentest completed against exact deployment;
- [ ] all critical/high findings remediated;
- [ ] independent legal/privacy review completed;
- [ ] evidence-pack verification completed from clean reviewer context;
- [ ] external final verdict authorises this exact Shadow Pilot scope.

### User / source connection

- [ ] Bao explicitly authorises the first read-only work source;
- [ ] least-privilege connector scopes documented;
- [ ] no write/send permissions granted to the pilot identity;
- [ ] first ten items can be revoked/paused immediately via kill switch;
- [ ] baseline workflow timing method agreed before measurement starts.

## Per-item review

For every item Bao should be able to answer in seconds:

1. Is the proposed matter assignment correct?
2. Is a task correctly identified?
3. Is a deadline/appointment present, absent or uncertain?
4. Is the risk level sensible?
5. Is the draft useful as-is, useful after edits, or rejected?
6. How long did review take?
7. Roughly how long would the same work have taken without TrustReady, using the pre-agreed baseline method?

## Privacy-minimised metrics

Use `core/legal-pilot-metrics.mjs`.

Allowed telemetry contains only:

- machine event id;
- hashed case reference (`sha256:...`), never the raw matter id;
- timestamp;
- bounded event type;
- measured review duration;
- agreed baseline duration;
- correctness boolean where required;
- bounded machine reason code.

Do **not** put names, email addresses, subject lines, message bodies, legal analysis, raw matter ids or free-text notes into pilot telemetry.

## Daily dashboard

Track:

- unique work items reviewed;
- accepted / edited / rejected proposals;
- useful rate = accepted + edited;
- measured total time saved;
- median review time;
- matter-assignment accuracy;
- deadline accuracy;
- blocked action attempts;
- autonomous external actions executed = **must remain 0**.

## Stop conditions

Immediately stop real-data processing if any of these occurs:

- an unauthorised external action is executed or appears possible;
- wrong-tenant / wrong-matter data is surfaced;
- an external AI request is possible without a valid pre-send immutable intent;
- WORM evidence, DLP, runtime identity, provider policy, HSM, network perimeter or kill-switch evidence becomes invalid/unavailable;
- raw mandate data appears in logs/telemetry where it is not authorised;
- a critical/high security finding is discovered;
- legal/privacy authorisation for the exact scope is withdrawn or materially changes.

Fail closed; do not continue the pilot merely to preserve a metric target.

## Day 5 decision

### Keep / expand only if

- ≥20 real work items processed;
- target net time saving is materially demonstrated (target ≥30 min/day);
- proposal usefulness is high enough that Bao wants it in the daily workflow;
- matter/deadline errors are understood and within the agreed pilot tolerance;
- zero unauthorised external actions;
- no unresolved critical/high safety issue;
- evidence trail is independently inspectable.

### If useful but not ready

Keep Shadow Mode and fix the measured bottleneck. Do not unlock action execution.

### If not useful

Stop. A technically secure system that does not save meaningful lawyer time is not the product we want.

## Separate future release: human-approved actions

Autonomous actions are **not** the next automatic step after a successful Shadow Pilot.

A later release may introduce narrowly typed human-approved actions only after:

- separate threat model and external review;
- exact-payload signed approval;
- recent step-up authentication;
- replay-safe durable claims;
- target/resource-version binding;
- per-action rollback/incident handling where possible;
- independent evidence that the action gateway is the only execution path.
