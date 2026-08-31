# TrustReady product flow

## What the user experiences

TrustReady is not a single magic score. The score is an index into an inspectable control graph.

```text
1. CONNECT
   GitHub / URL / evidence workspace
      ↓
2. SCAN
   collect immutable evidence + provenance
      ↓
3. READINESS RESULT
   score + verified / candidate / not observed / attestation-required
      ↓
4. GAP PLAN
   rank by buyer impact × blocking status × effort
      ↓
5. REMEDIATE
   E1/E2: safe documentable/technical evidence
   E3: runtime proof task / independent probe
   E4: authenticated accountable-human attestation
      ↓
6. RE-SCAN
   same profile + same rules; no manual score override
      ↓
7. BEFORE / AFTER
   show exactly which controls changed and the new evidence
      ↓
8. SHARE
   buyer-facing trust centre / assurance manifest / questionnaire answers
      ↓
9. CONTINUOUS TRUST
   evidence expiry + drift / regression re-checks
```

## Meaning of 100/100

100/100 means every control in the selected versioned readiness profile is satisfied by accepted evidence or, where the profile explicitly permits it, authorised attestation.

It does not mean universal legal compliance, formal certification, zero risk, or government approval.

## Remediation lanes

### Lane A — Build evidence (E1/E2)
TrustReady may prepare or generate an artifact, but the artifact earns credit only if a deterministic re-scan rule accepts it.

Examples:
- system purpose / intended users
- model/provider inventory
- limitations / prohibited uses
- data-flow document
- processor/subprocessor inventory
- vulnerability intake process
- eval evidence
- supply-chain provenance
- buyer assurance pack
- freshness manifest

### Lane B — Prove runtime behavior (E3)
Repository text cannot satisfy these controls. TrustReady creates an environment-bound proof task or probe.

Examples:
- approval bypass test
- deployed AI disclosure observation
- cross-tenant isolation probe
- deletion/retention verification
- incident exercise
- audit event + replay
- production monitoring observation
- restore/rollback drill

### Lane C — Obtain authorised attestation (E4)
TrustReady never self-attests organisational or legal conclusions.

Examples:
- AI provider/deployer role and risk classification
- named accountable control ownership

## UI contract

Every control row must expose:
- control ID and requirement
- current status
- points currently earned
- why it is or is not verified
- evidence inspected (source + revision/hash + freshness)
- exact next proof required
- remediation lane
- blocking/non-blocking status
- action CTA

The UI must never imply that `candidate` means verified, nor that `not observed` means a control does not exist in reality.

## Path to 100

The path is deterministic:

```text
current verified controls
+ accepted E1/E2 proof
+ verified E3 runtime evidence
+ authorised E4 attestations
= 100/100 for this profile
```

There is no manual “mark complete” that bypasses evidence requirements.
