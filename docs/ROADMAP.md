# TrustReady Roadmap — Work Backwards From High Assurance

## End state: T5 — Independently Verifiable Assurance Network

TrustReady is trusted because buyers can verify its outputs independently.

Required:
- open manifest verifier
- signed, versioned evidence manifests
- deterministic public rule bundles
- independently benchmarked scanner accuracy
- external security review / penetration testing
- public methodology and change log
- reproducible framework mappings
- reviewer/auditor workflow
- continuous assurance with expiry/regression
- private evidence sharing with selective disclosure
- evidence/API interoperability

Exit proof:
A third party can receive a TrustReady dossier, verify integrity locally, reproduce deterministic control results and identify all remaining attested/unknown claims without contacting TrustReady.

---

## T4 — Government / Regulated Procurement Candidate

Required:
- L3 assurance profile
- four-eyes review for material attestations/exceptions
- deployment-specific evidence
- immutable audit trail
- evidence chain of custody
- strict tenant isolation and RBAC
- SSO/MFA for reviewers
- retention/deletion controls
- data residency options
- backup/restore and incident evidence
- formal risk acceptance / exception workflow
- exportable assurance dossier
- mapping to relevant EU/German assurance expectations

Exit proof:
Run 3–5 supervised procurement pilots with qualified public-sector/security reviewers. Track every challenged control, false positive, false negative and evidence request. No claim of government approval unless an authority explicitly grants it.

---

## T3 — Enterprise Procurement Product

Required:
- private GitHub + cloud + docs connectors
- model and subprocessor inventory
- buyer questionnaire import/export
- answer only from evidence
- named control owners
- authenticated attestations
- evidence freshness and expiry
- trust centre
- buyer sharing portal
- continuous monitoring
- payment + self-serve subscription

Exit proof:
A real vendor completes a security/AI buyer questionnaire materially faster, and the buyer accepts a substantial share of answers without rework.

---

## T2 — Evidence-First Self-Serve Product

Required:
- GitHub scan
- deployed URL scan
- internal control ontology v1
- deterministic verification rules
- evidence states + provenance
- gap prioritisation
- remediation generation
- re-scan loop
- downloadable buyer pack
- CLI/CI integration
- scanner benchmark suite

Exit proof:
Dogfood TrustReady on 5+ real projects and 20+ deliberately messy synthetic/OSS cases. Demonstrate that keyword-only text never becomes `verified` and that known missing controls are detected reliably.

---

## T1 — Trust Kernel (build now)

Required:
- canonical evidence schema
- control-result schema
- profile/rule versioning
- deterministic verifier
- score decomposition
- blocking/stale/regressed states
- manifest integrity hashing
- test fixtures proving fail-closed behavior
- methodology docs

Exit proof:
The same evidence + same rule bundle always gives the same result, and any evidence mutation changes the manifest hash.

---

## T0 — Positioning

Promise:

> Evidence-backed AI procurement readiness. Every claim inspectable. Every gap actionable.

Do not promise:
- automatic legal compliance
- certification without accreditation
- government approval
- zero risk

## Build order

1. **Trust Kernel** — schemas, deterministic verifier, manifest
2. **Dogfood Scanner** — own repos + known golden cases
3. **Remediation Loop** — automatically close safe gaps and re-scan
4. **Public Self-Serve Scan** — acquisition loop
5. **Private Workspace** — authenticated evidence and attestations
6. **Questionnaire Autopilot** — immediate enterprise ROI
7. **Continuous Monitor** — recurring revenue
8. **Government Review Mode** — stricter evidence + reviewer workflow
9. **Independent Verifier + external review** — credibility moat

## Metrics that matter

### Scanner quality
- false verified rate (most important: target near zero)
- false missing rate
- control precision/recall on labelled benchmark
- evidence citation correctness
- reproducibility rate

### Buyer value
- questionnaire completion time
- buyer rework rate
- evidence-request reduction
- procurement cycle-time reduction
- percentage of answers accepted without modification

### Assurance quality
- share of controls backed by E2/E3/E5 evidence
- stale evidence rate
- unresolved blocking findings
- number of challenged results overturned
- time from regression to detection

### Business
- scan → paid conversion
- paid → continuous-monitor conversion
- MRR
- buyer pack usage
- expansion from developer → enterprise → regulated tier
