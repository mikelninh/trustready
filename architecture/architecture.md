# TrustReady — Architecture

## System shape
`evidence sources → immutable evidence metadata → control/rule engine → evidence graph → gap/remediation engine → re-scan → buyer pack / trust centre / REST / MCP`

## Authority boundary
Models may help discover candidate evidence or explain gaps. They do not grant compliance, certification or procurement approval.

## Commercial surfaces
- public/free inspection path;
- paid REST/MCP capability boundary;
- Stripe-hosted checkout + signed entitlement tokens;
- usage/activation events.

## Hard-to-reverse choices
Evidence identity, hashing/freshness, rule versions, scoring semantics, tenant/entitlement boundaries and claim language are RED. UI presentation and non-authoritative explanation are more reversible.
