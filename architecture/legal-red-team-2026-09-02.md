# Legal Trust Layer — Adversarial Security Review

Date: 2026-09-02
Scope: `core/legal-gateway.mjs`, Legal Trust Standard, Control Matrix and Evidence Pack.
Status: pre-production security review. No real mandate data is approved by this document.

## Executive result

The current branch is materially stronger than the architecture-only baseline:

- provider passports are Ed25519-signed and fail closed on tampering/expiry/untrusted signer;
- mandate-data egress requires explicit matter, provider, use case and processing region;
- use-case-specific field and payload-size limits are enforced by the gateway;
- obvious direct-identifier field names are denied unless a signed policy explicitly permits them;
- AVV/DPA, §43e, subprocessor and third-country safeguards can hard-block mandate egress;
- action approvals are Ed25519-signed, MFA-bound, actor/session/matter/action/payload-bound and expire within five minutes;
- approval consumption requires an atomic replay-protection implementation;
- evidence events are sequenced and hash-chained;
- signed evidence checkpoints and detached-signed evidence manifests prevent a bare recomputable hash from being treated as provenance.

Local adversarial tests: 10/10 pass.
Repository CI and dogfood workflows: pass on the implementation commit.

This is still **NOT READY FOR REAL MANDATE DATA** until the P0 runtime controls below are implemented and independently tested.

## Review lenses

The review used the following threat lenses:

- OWASP Top 10 for Agentic Applications 2026: Agent Goal Hijack, Tool Misuse, Identity & Privilege Abuse, Agentic Supply Chain Vulnerabilities, Unexpected Code Execution, Memory & Context Poisoning, Insecure Inter-Agent Communication, Cascading Failures, Human-Agent Trust Exploitation and Rogue Agents.
- NIST AI RMF / Generative AI Profile: privacy, information security, governance, testing/evaluation and lifecycle risk management.
- TrustReady Legal controls for BRAO §43a/§43e, StGB §203, GDPR and EU AI Act deployment governance.

## P0 — must be closed before real mandate data

### P0-1 — Runtime tenant + matter authorisation is not implemented here

`tenant_id` and `matter_id` are currently trusted request context. The gateway does not itself prove that the authenticated actor/service is authorised for that matter.

Required hardening:

- authenticated workload/user identity;
- tenant isolation enforced below application prompts/models;
- matter-level ABAC lookup at egress and action execution;
- cross-tenant and cross-matter negative tests;
- deny on policy-store outage or stale authorisation.

### P0-2 — Field names are not DLP

An allowed field such as `body_excerpt` can still contain a name, email address, IBAN, health data or another mandate secret. Top-level field filtering is therefore only a structural minimisation control.

Required hardening:

- recursive schema enforcement;
- content-level PII/secret/DLP inspection before egress;
- deterministic redaction/tokenisation where feasible;
- canary corpus including obfuscation, Unicode, base64/encoding and identifiers inside free text;
- Zone 4 default: external egress prohibited unless a separate high-assurance policy explicitly enables it.

### P0-3 — Network egress must enforce the provider decision

A signed passport and requested `region` do not prove where packets actually go.

Required hardening:

- outbound network deny-by-default;
- destination/endpoint allow-list bound to provider passport;
- TLS verification and private networking where available;
- provider/model/endpoint identity recorded;
- DNS/redirect/SSRF bypass tests;
- runtime evidence for configured processing region and retention/training settings.

### P0-4 — Key trust is not yet a production trust service

The module receives `trusted_keys` and private keys as function inputs. Production must not allow arbitrary callers to choose trust roots or access signing private keys.

Required hardening:

- KMS/HSM-backed signing;
- purpose-separated keys: provider-review, approval, evidence;
- key registry with purpose, tenant/scope, validity, rotation and revocation;
- fail closed on unknown/revoked/expired keys;
- no private signing key in app memory beyond managed signing calls;
- key-compromise drill.

### P0-5 — Approval must use action-specific schemas and real authorisation

The capability binds an arbitrary payload, but safety depends on that payload containing every action-relevant parameter. An executor must never use an unbound recipient, attachment, endpoint or mutation argument.

Required hardening:

- typed action registry (`send_email`, `beA_send`, `case_write`, etc.);
- canonical action-specific schemas containing all recipients, attachments and mutation parameters;
- authorisation re-check at issue and execute time;
- resource version/ETag binding to prevent TOCTOU;
- durable transaction state + idempotency;
- high-risk actions disabled in Bao shadow mode.

### P0-6 — Replay protection must not be caller-pluggable in production

The current kernel correctly fails when no `consume_nonce` implementation is supplied, but a careless integration could provide an unsafe always-true implementation.

Required hardening:

- production action service owns the replay store internally;
- database unique constraint / atomic compare-and-set;
- fail closed on datastore outage;
- concurrent race test with hundreds of identical capabilities;
- execution idempotency tied to capability/transaction ID.

### P0-7 — Prompt injection and tool-output injection are not yet runtime-enforced

The LLM is not the policy boundary, which is correct, but untrusted mail/doc/web content still needs explicit treatment before it influences tools, memory or human approvals.

Required hardening:

- mark retrieved/mail/document content as untrusted data;
- model cannot alter tool allow-lists, provider policy or approval requirements;
- no direct model-to-network/tool execution path;
- validate/sanitise model outputs before rendering/executing;
- adversarial prompt-injection corpus for mail, PDFs, OCR text, HTML/Markdown and retrieved web content.

### P0-8 — Evidence requires immutable/externally anchored storage

A signed checkpoint detects modification if the checkpoint and trusted key remain available. An attacker controlling the same storage could still delete both events and local checkpoint artifacts.

Required hardening:

- append-only/WORM evidence storage;
- periodic checkpoint export/anchor to a separately controlled security account or transparency service;
- retention lock;
- deletion/reorder/truncation alarms;
- independent restore/verification exercise.

## P1 — next hardening wave

### P1-1 — Strict canonical data model

The custom canonicaliser should reject non-JSON values, non-finite numbers, cycles and excessive nesting rather than silently representing edge-case JavaScript values. Adopt a strict canonical JSON scheme or equivalent reviewed encoding.

### P1-2 — Resource exhaustion / parser DoS

Add limits for object depth, key count, string length, event metadata and verification batch size before recursive processing.

### P1-3 — Tenant policy overlay

A global approved provider passport must not override a firm's local choice. Add tenant policy such as `external_ai=false`, provider deny-lists, allowed deployment profile and matter-level sensitivity overrides.

### P1-4 — Exact provider/model binding

Bind passport policy to provider legal entity + service + API endpoint + model/model family + material configuration. Treat material provider/subprocessor/config changes as review-invalidating events.

### P1-5 — Recent step-up authentication

For high-risk actions, require a recent, verifiable WebAuthn/passkey or other approved MFA assertion, not only an `mfa=true` claim supplied to the issuance function.

### P1-6 — Memory and context poisoning

Persistent agent memory is currently outside the gateway. Before enabling memory:

- provenance on every memory item;
- tenant/matter scope;
- untrusted memory quarantine;
- expiry/review rules;
- no policy/tool configuration sourced from model memory;
- poisoning regression tests.

### P1-7 — Agent/MCP/A2A supply chain

Before dynamic tools or MCP servers are enabled:

- signed/pinned tool registry;
- version/digest pinning;
- capability manifest;
- network scopes;
- SBOM/AIBOM;
- vulnerability review and revocation;
- no runtime installation from model-selected URLs/packages.

### P1-8 — Unexpected code execution

Default production agents must have no shell/eval/arbitrary-code capability. Any future code execution requires a separately sandboxed profile with no mandate-data/network access by default.

### P1-9 — Cascading failures

Add transaction/rate budgets, fan-out limits, bulk-operation caps, circuit breakers and kill switches so one bad inference cannot trigger a large workflow cascade.

### P1-10 — Human-agent trust exploitation

Approval UI must show the exact action diff, target/recipient, attachments, source evidence, uncertainty and why approval is required. Avoid generic `Approve` buttons that hide consequential changes.

### P1-11 — Rogue-agent invariants

Agents must never be able to change their own policy, keys, trust store, tool registry, audit controls, retention rules or approval requirements. Add explicit negative tests.

### P1-12 — Evidence privacy

Top-level event identifiers must be pseudonymous; event type/policy fields need schemas and size limits. Add corpus tests for accidental mandate content in logs and telemetry.

## Existing external review feedback addressed

The first PR review identified three P1 defects in the documentation baseline:

1. MFA evidence did not explicitly cover ordinary lawyer accounts with mandate access.
2. secret scans alone did not prove that a production secrets manager is actually used.
3. a bare evidence-manifest hash did not authenticate provenance.

The branch now updates LT-016/LT-017/LT-046 and the Evidence Pack to require runtime secrets-manager evidence, MFA coverage for every mandate-capable human account, and detached digital signatures with independently trusted signer identity.

## Gate decision

Current decision: **LIMITED / SYNTHETIC-SHADOW ONLY**.

Allowed:

- synthetic data;
- public/non-confidential data;
- local tests;
- read-only shadow workflows where no real mandate payload is transmitted to external AI.

Not allowed yet:

- external AI calls containing real mandate data;
- autonomous mail or beA sending;
- irreversible case-system writes;
- production persistent agent memory;
- dynamic/unreviewed MCP/tool installation.

The next hardening release should close P0-1 through P0-8 before Bao's first real-mandate pilot.
