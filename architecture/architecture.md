<!-- paos:reviewed=2026-09-01 -->
# Architecture

## System shape

```text
repositories · policies · configs · tests · attestations
                         ↓
               evidence collectors
                         ↓
              immutable evidence
          hash · timestamp · source · scope
                         ↓
            versioned control engine
                         ↓
        evidence graph + readiness state
                   ↙            ↘
          remediation engine   buyer/API view
                   ↘            ↙
                 re-scan / expiry
```

## Authority model

Deterministic control checks and accepted evidence define readiness state. AI may help discover, classify or explain evidence; it does not grant itself a pass.

## Evidence object

A decision-grade evidence item should preserve at least:

- source/location;
- collected timestamp/freshness;
- cryptographic/content fingerprint where appropriate;
- scope/project/tenant;
- rule/profile version used;
- observation/result;
- provenance for any authorised attestation.

## Framework layer

Controls may map to EU AI Act, GDPR-oriented evidence, NIST AI RMF/GenAI, ISO/IEC 42001, BSI-oriented mappings or customer-specific profiles. Framework mapping is a projection over evidence/control state, not independent certification.

## Decision reversibility

### GREEN

- new evidence extractors that preserve provenance;
- reversible UI/explanation changes;
- additional synthetic control fixtures;
- AI discovery improvements that do not change final authority.

### AMBER

- new accepted evidence type;
- rule/control semantic change;
- new external evidence processor/integration;
- profile scoring/weighting change;
- retention/freshness default change.

### RED

- evidence immutability/provenance model;
- identity/tenant boundary;
- definition of an accepted pass/attestation;
- claims of certification/legal compliance/government approval;
- destructive evidence history changes;
- stable buyer/API contracts that materially affect procurement decisions.

## Product truth

A readiness score is only a compact view over a selected profile. The evidence graph + rule version is the inspectable product truth.
