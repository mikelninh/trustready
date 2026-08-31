# TrustReady charge-ready runbook

## Launch objective

A stranger can:

1. run a free public repository scan;
2. choose Developer or Team;
3. pay through Stripe-hosted Checkout;
4. return to TrustReady;
5. have the paid Stripe subscription re-verified server-side;
6. receive a TrustReady API key;
7. consume paid REST/MCP capabilities against a durable monthly unit quota;
8. view usage/history and open Stripe Customer Portal;
9. have subscription cancellation/status changes remove paid entitlement through signed Stripe webhooks.

Payment never changes readiness scoring or evidence requirements.

## Plans

| Plan | Price | Included monthly units |
| --- | ---: | ---: |
| Developer | EUR 49/month | 500 |
| Team | EUR 249/month | 5,000 |

Initial capability costs:

| Capability | Units |
| --- | ---: |
| paid public scan + history | 1 |
| private repository scan | 5 |
| remediation pack | 10 |

The free `/public-scan` remains available without an account.

## Hosted backend

The initial backend is one Supabase Edge Function named `trustready`.

Production base URL after deployment:

`https://htffcvdopavknnylbowl.supabase.co/functions/v1/trustready`

Routes:

- `GET /` — launch/pricing UI
- `GET /health` — configuration/readiness health
- `POST /checkout` — create Stripe-hosted subscription Checkout
- `POST /claim` — verify paid Checkout + secure browser claim and issue/rotate API key
- `GET|POST /public-scan` — free public scan
- `POST /scan` — paid scan + history (Bearer TrustReady API key)
- `POST /private-scan` — paid private scan; also requires ephemeral `X-GitHub-Token`
- `POST /remediation` — paid scan-to-remediation pack
- `GET /account` — current plan, quota, usage and last 20 scans
- `POST /portal` — Stripe Customer Portal session
- `POST /webhook` — signed Stripe lifecycle webhook
- `POST /manifests/verify` — free manifest integrity verification
- `POST /mcp` — stateless MCP JSON-RPC endpoint

## Secrets required to turn checkout live

The code never stores these in Git.

Set in Supabase Edge Function secrets:

- `TRUSTREADY_STRIPE_SECRET_KEY=sk_live_...`
- `TRUSTREADY_STRIPE_WEBHOOK_SECRET=whsec_...`

Supabase supplies `SUPABASE_URL` and the backend key variables to the Edge Function automatically.

If Stripe secrets are missing, `/health` stays healthy but reports billing as unconfigured, and `/checkout` fails closed with `billing_not_configured`.

## Stripe webhook

Create one Stripe webhook endpoint pointing to:

`https://htffcvdopavknnylbowl.supabase.co/functions/v1/trustready/webhook`

Subscribe at minimum to:

- `checkout.session.completed`
- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`

The function verifies the raw body with `Stripe-Signature`, rejects timestamps outside a five-minute tolerance, records Stripe event IDs idempotently and reconciles paid entitlement from Stripe subscription state.

## Checkout claim security

A Stripe Checkout `session_id` is not sufficient to mint a TrustReady key.

Before redirecting to Stripe, TrustReady:

1. generates a random claim nonce;
2. stores only its SHA-256 hash with the Stripe session;
3. sets the raw nonce in a short-lived `HttpOnly; Secure; SameSite=Lax` cookie.

After Checkout, `/claim` requires:

- the same browser claim cookie;
- the matching Checkout session;
- matching email and plan metadata;
- Stripe session `complete`;
- Stripe subscription `active` or `trialing`.

The raw TrustReady API key is then returned to the user but only its SHA-256 hash is stored. Reclaiming from the same still-authorised browser rotates the previous key rather than creating duplicate access.

## API key and quota security

Raw API keys begin with `tr_live_` and are never stored.

The database function `trustready_consume_units` performs quota enforcement transactionally:

- hashes identify the API key;
- revoked keys fail;
- inactive subscriptions fail;
- usage is counted only inside the Stripe billing period;
- over-quota requests fail;
- `Idempotency-Key` prevents retry double-charging;
- raw private repository content and GitHub tokens are not written into scan history.

## Private repository beta

`/private-scan` and private remediation accept an `X-GitHub-Token` only for the duration of the request.

TrustReady does not persist or return the token. Scan history stores only a compact summary, repository URL, immutable source revision, profile/version, score and control statuses—not repository file contents.

A GitHub App/OAuth connection should replace user-supplied tokens in the mature product.

## Remediation integrity

Paid remediation generates work; it does not generate compliance.

E1/E2:
- TrustReady may prepare evidence templates and implementation tasks.
- generated templates intentionally contain placeholders.
- scanner rules explicitly refuse to promote placeholder files.

E3:
- TrustReady produces runtime proof tasks.
- repository text cannot satisfy the control.

E4:
- TrustReady produces an authenticated-attestation task.
- TrustReady never self-attests legal/organisational conclusions.

The score changes only after a re-scan sees accepted evidence or an authorised attestation.

## Database state

TrustReady is isolated in prefixed tables in the current Supabase project:

- `trustready_accounts`
- `trustready_api_keys`
- `trustready_usage_events`
- `trustready_scan_history`
- `trustready_stripe_events`
- `trustready_checkout_claims`

RLS is enabled. `anon` and `authenticated` receive explicit deny policies and table privileges are revoked. Server access uses the Supabase backend secret only.

## Release gates

Before merging/deploying:

1. all core tests pass;
2. scanner golden benchmark has zero false-verified cases;
3. generated placeholder remediation artifacts cannot increase a score;
4. hosted scanner/trust-kernel/commercial files exactly match tested core files;
5. hosted GitHub collector matches core collector except for its relative import path;
6. hosted profile is semantically identical to the versioned procurement profile;
7. Edge TypeScript parses;
8. Supabase security advisor is reviewed;
9. live `/health`, free scan, unauthorized paid request and billing-not-configured failure path are tested;
10. after Stripe secrets/webhook are configured, a real Checkout must be created and the returned subscription/claim flow verified before stating that TrustReady can accept payments.

## What remains intentionally outside v1

- a formal legal certification or conformity-assessment claim;
- automatic E4 attestation;
- score overrides;
- persistence of private source contents;
- GitHub App OAuth (ephemeral token beta first);
- sophisticated seat management / SSO;
- x402 settlement (can be added after the Stripe entitlement loop is proven).
