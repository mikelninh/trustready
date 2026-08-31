# Framework Mapping Strategy

TrustReady does not encode external standards directly into one permanent score. It maintains a stable internal control ontology and versioned external profiles.

## Why

Regulation, standards, guidance and buyer expectations evolve at different speeds. A scan must remain reproducible months or years later.

Every external profile therefore records:

- profile ID
- profile version
- effective / observed date
- source references
- mapping version
- controls included
- applicability logic
- evidence requirements
- known interpretation limitations

Historical scans always retain the exact profile and ruleset that produced them.

## Current reference families

### EU AI Act

Use for role/risk classification, transparency, governance and applicable provider/deployer obligations.

Important product rule: applicability and legal-role determinations are not silently automated into legal conclusions. TrustReady can gather facts and propose a classification, but higher-assurance profiles require authorised review/attestation where judgement is material.

Official reference family:
- https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai
- https://digital-strategy.ec.europa.eu/en/library/guidelines-transparency-obligations-providers-and-deployers-ai-systems

### NIST AI RMF + GenAI Profile

Use as a cross-sector risk-management mapping around governance, mapping, measurement and management of AI risk.

Official reference family:
- https://www.nist.gov/itl/ai-risk-management-framework
- https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence

NIST AI RMF 1.0 is under revision as of 2026, so the mapping must be explicitly versioned.

### ISO/IEC 42001

Use as an AI management-system mapping for organisational governance, risk, traceability and continual improvement.

TrustReady does not reproduce copyrighted standard text and does not claim ISO certification. Mappings should reference licensed organisational controls or public ISO descriptions as appropriate.

Official reference:
- https://www.iso.org/standard/42001

### BSI / German public-sector and cloud assurance

Use relevant BSI criteria as a security/AI assurance mapping where the deployment context makes them applicable, including AIC4/C5-oriented evidence and federal cloud minimum-standard expectations.

Official reference family:
- BSI AIC4 AI Cloud Service Compliance Criteria Catalogue
- BSI C5 / cloud assurance publications
- BSI minimum standards for external cloud services in federal administration

TrustReady does not equate a mapping result with a BSI audit or formal attestation.

### GDPR / privacy procurement

Use privacy evidence controls around processing purpose, data flows, processors/subprocessors, retention/deletion, data-subject handling and deployment-specific data protection artefacts.

Legal-basis/DPIA conclusions that require qualified judgement remain explicit human/legal-review items.

## Mapping rules

1. One internal control may map to many external framework items.
2. Framework mapping does not weaken the internal evidence requirement.
3. A profile can strengthen the minimum evidence class for a control.
4. A future mapping update creates a new profile version.
5. Source text and TrustReady interpretation remain visibly separate.
6. TrustReady must state whether a mapping is official, community-derived, expert-reviewed or internal.
7. Formal certification or conformity assessment remains outside TrustReady unless TrustReady later becomes appropriately accredited for a defined scheme.
