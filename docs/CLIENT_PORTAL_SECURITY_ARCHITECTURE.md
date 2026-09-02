# TrustReady Legal — Client Portal Security Architecture

Status: **production design contract, not yet deployed or independently assured**.

The public GitHub Pages portal is a synthetic demo only and must not receive real client data.

## Product goal

Client:

`Vietnamese instructions → secure upload → completeness/formality feedback → one bundled follow-up`

Law firm:

`German/bilingual structured matter → missing items → source evidence → lawyer review → human approval`

The browser is never a trust boundary and never receives direct database credentials.

## Invitation and login

Recommended first-pilot flow:

1. Law firm creates a client invitation for one specific matter.
2. TrustReady generates a cryptographically random opaque invite token.
3. Invitation is delivered as a link or QR code.
4. Link/QR is **not authentication by itself** and contains no client name, matter number or other PII.
5. Invite token is short-lived, single-use and stored server-side only as a hash.
6. Client completes a second verification step using a code delivered to a previously verified phone number or another approved second channel.
7. Successful verification creates a server-side session bound to tenant + client + matter + permitted actions.
8. Browser receives only an opaque session identifier in a `Secure`, `HttpOnly`, appropriately `SameSite` cookie.
9. Session has idle/absolute expiry and can be revoked immediately by the firm.
10. Passkeys can be added later; a permanent password account is not required for the first pilot.

A QR code is therefore only a convenient transport for an invitation URL, never a substitute for authentication.

## Staff authentication

- Separate staff identity from client identity.
- MFA required.
- Roles: `intake_staff`, `lawyer`, later `firm_admin`.
- Least privilege.
- Lawyer-only approval remains separate from intake-team preparation.
- Sensitive approvals should require recent re-authentication.

Preferred later: firm SSO/OIDC plus phishing-resistant MFA/passkeys.

## Authorization and database boundary

The browser never connects directly to PostgreSQL or object storage using reusable credentials.

Every protected request executes server-side:

`authenticated session → tenant → role → matter → operation → resource version → allow/deny → audit`

Required invariants:

- Client sees only explicitly assigned matters.
- Staff sees only permitted firm/matter resources.
- Tenant and matter context is server-derived; hidden fields/query parameters alone are never trusted.
- PostgreSQL RLS or equivalent independently tested isolation provides defense in depth.
- Cross-tenant/IDOR negative tests are release blockers.
- Public or sequential matter IDs never grant authority.

## Secure document upload

Production flow:

1. Authenticated client selects a required document slot.
2. Backend verifies session + tenant + matter + slot.
3. Backend issues a one-time short-lived upload capability scoped to exactly one object, MIME set and maximum size.
4. File lands in a private quarantine bucket/prefix.
5. Backend verifies observed content type/size and safe filename metadata.
6. Malware scan runs before promotion.
7. Document receives SHA-256 content hash + provenance metadata.
8. Only clean files are promoted to the protected matter store.
9. Relational DB stores references/hash/status, not duplicate raw document bodies.
10. AI processing receives only the minimum permitted document/version for a declared purpose.

No public bucket, permanent browser cloud credential or shared upload key.

## Vietnamese ↔ German boundary

Never overwrite the Vietnamese source with the German translation.

Store separately:

- original source,
- extracted source facts with source locations,
- German translation,
- model/translation version,
- uncertainty/review flags.

Names, dates, deadlines, amounts, addresses, identifiers and legally material statements require source-linked review. The translation is a working aid, not the authoritative original.

## Storage and encryption

Pilot target:

- EU/Germany-hosted protected environment,
- private object storage,
- TLS in transit and encryption at rest,
- KMS/HSM-backed production keys,
- tenant/matter authorization independent of object names,
- tested backup/restore,
- defined retention/deletion,
- privacy-safe logs without raw document bodies or secrets.

For higher-assurance enterprise deployment, separate firm projects/buckets/databases can be supported rather than relying only on logical multi-tenancy.

## Audit evidence required before real mandate data

- authentication/MFA configuration,
- session expiry/revocation tests,
- tenant/matter authorization tests,
- IDOR/cross-tenant negative tests,
- upload MIME/size/malware negative tests,
- private-storage/public-access proof,
- encryption/KMS/HSM evidence,
- database isolation/RLS evidence,
- privacy-safe access logs,
- backup/restore evidence,
- deletion test,
- vulnerability scan,
- independent penetration test,
- legal/privacy review and processor/subprocessor documentation.

## Legal/privacy promotion boundary

Engineering does not certify legal compliance.

Before real mandate data:

- legal basis, transparency, purpose limitation, minimisation and retention must be documented,
- technical/organisational measures must be reviewed against actual risk,
- processor/subprocessor relationships and transfers must be documented,
- German lawyer confidentiality/service-provider requirements including BRAO §43e where applicable must be reviewed by qualified counsel,
- exact production deployment must receive independent security review.

## What is guaranteed today?

### Public demo

We can evidence now:

- synthetic content only,
- no backend/database,
- CSP `connect-src 'none'`,
- no form submission,
- local demo file selection uses only filename/status in our code,
- no `fetch`, XHR, WebSocket, Beacon, FileReader or file-content read API,
- no production send action.

### Production portal

**Not guaranteed yet.** This document and the executable security kernel define what must be built and observed. Production readiness is earned only after live deployment evidence + legal/privacy review + independent security assurance.