# TrustReady charge-ready sprint

## Customer flow

1. Visitor runs the free public browser scan.
2. Pricing offers Developer (€49/month) and Team (€249/month).
3. `POST /api/billing/checkout` creates a Stripe-hosted subscription Checkout Session. Stable Stripe Price IDs are used when configured; otherwise recurring inline `price_data` creates the €49/€249 subscription directly.
4. Stripe redirects successful customers to `/success.html?session_id=...`.
5. `GET /api/billing/activate` retrieves the Checkout Session from Stripe, requires an active/trialing subscription, and issues a short-lived HMAC-signed TrustReady API token.
6. Paid REST (`/api/v1/scan`) and remote MCP (`/api/mcp`) verify the token and re-check the Stripe subscription before doing work.
7. Cancellation/non-payment therefore removes paid access even if an old token still exists.
8. Each paid request emits a structured `trustready.api_unit` usage event to deployment logs.

## Security / trust boundaries

- No card data touches TrustReady; Checkout is hosted by Stripe.
- A frontend flag cannot unlock paid work.
- Tokens are signed server-side with `TRUSTREADY_TOKEN_SECRET` and expire after 24h.
- Paid requests re-check Stripe subscription state.
- Payment never changes evidence rules or verification thresholds.
- Stripe secrets are deployment environment variables, never committed.

## Plans

### Developer — €49/month
- 500 API-unit commercial allowance
- paid REST API + remote MCP entitlement
- private GitHub / CI history are the next capabilities added to the same plan

### Team — €249/month
- 5,000 API-unit commercial allowance
- paid REST API + remote MCP entitlement
- shared evidence/remediation/trust-centre capabilities are the next additions

## Current usage-meter state

Subscription entitlement is enforced now. Every paid REST/MCP request emits a structured unit event. Hard monthly quota enforcement is deliberately not claimed until a durable meter is connected (Stripe Billing meter, Postgres/Supabase, or equivalent). This does not block selling flat-rate subscriptions; it means overage/quota automation is the next billing hardening step.

## Required deployment environment

See `.env.example`.

Charge-ready requires:
- `STRIPE_SECRET_KEY`
- `TRUSTREADY_TOKEN_SECRET`
- `TRUSTREADY_APP_ORIGIN`

Optional but preferred later:
- `STRIPE_PRICE_DEVELOPER`
- `STRIPE_PRICE_TEAM`

Without stable Price IDs, Checkout uses recurring inline prices at the plan amounts encoded in the server-side plan registry.

## External blockers discovered on 2026-08-31

The connected live Stripe account available to this build session does not grant Checkout/Product mutation permissions, so the live charge path cannot be executed from this connector session. The application code no longer requires pre-created Product/Price objects, but the production deployment still needs a Stripe secret key with permission to create Checkout Sessions.

The connected Vercel team currently exposes no projects through the connector, so a public production origin is not yet established from this session. Deployment configuration is ready, but the repository must be imported/created in Vercel (or deployed on another Node-compatible host) and the environment variables set before real Checkout can run.

## Definition of charge-ready

We call the product charge-ready only when all are true:
- production site is reachable;
- live Stripe secret is configured with Checkout permission;
- checkout opens in live mode;
- a real/test subscription can activate;
- token issuance succeeds only for active/trialing subscriptions;
- paid REST request succeeds with valid entitlement and fails without it;
- remote MCP request is entitlement-gated;
- cancellation/payment failure removes access;
- CI remains green.
