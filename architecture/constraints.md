<!-- paos:reviewed=2026-09-01 -->
# Constraints

## Evidence integrity

- every verified result must be traceable to evidence + control/rule version;
- evidence freshness/expiry remains visible;
- unknown stays unknown;
- AI-assisted discovery cannot silently create accepted evidence;
- authorised attestation is labelled separately from independently observed evidence;
- re-scan history preserves material before/after state.

## Score semantics

A `100/100` score means all controls in the **selected readiness profile** are backed by accepted evidence or explicit authorised attestation.

It does **not** mean:

- universal legal compliance;
- certification;
- zero risk;
- government approval;
- suitability for every deployment context.

## Framework claims

Mappings to legislation/standards are evidence organisation and readiness support. TrustReady does not replace lawyers, auditors, certifiers, security reviewers or procurement authority.

## Security / privacy

- connector access is least-privilege and source-scoped;
- secrets/private evidence are not exposed in buyer/public views by default;
- multi-project/tenant boundaries fail closed;
- evidence retention/deletion policy must not destroy the auditability of claims without making that consequence explicit.

## Product truth

- missing evidence does not equal failure unless the control defines it so;
- generated remediation does not equal remediated control;
- a clean repository scan does not equal organisational governance readiness;
- framework coverage does not equal formal certification;
- stale evidence cannot remain silently green.
