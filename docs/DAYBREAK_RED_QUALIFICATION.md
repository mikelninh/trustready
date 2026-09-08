# Daybreak Red Qualification Pack

## Status

**Candidate qualification evidence — not an OpenAI approval or entitlement.**

## Proposed use case

Use advanced cyber-capable models for **controlled vulnerability research and exploit validation on systems Michael owns or is explicitly authorized to test**, with TrustReady enforcing target scope and preserving evidence from exploit reproduction through patch validation.

Primary research questions:

- Can an AI-assisted security workflow reproduce a vulnerability inside an authorized test target?
- Can the same workflow validate that a patch closes the exploit path?
- Can target authority be enforced outside the model so an out-of-scope target never reaches an effect?
- Can each decision be reproduced from machine-readable evidence?

## Why this maps to Daybreak Red

OpenAI describes Daybreak Red / GPT-5.6 Cyber as a separately approved tier for advanced authorized workflows such as penetration testing, red teaming, exploit validation/development, exploit-chain validation, and controlled vulnerability research.

The requested use is intentionally narrow: **owned or explicitly authorized research targets only**, with no customer-facing access and no downstream redistribution of Daybreak capabilities.

## Existing evidence

TrustReady already focuses on deterministic authority boundaries and inspectable evidence. The controlled Red Lab adds the missing advanced-security research loop:

`authorization → bounded target → exploit-before-fix → patch → re-test → evidence`

The initial public proof is deliberately safer than a real penetration-testing target:

- synthetic `lab://` fixtures only;
- network disabled in the lab contract;
- exact target allowlist;
- external-target attempt blocked before effect;
- two exploit-before-fix / patch-after-fix golden cases;
- CI fails closed on evidence regression.

## Controls for a future approved Red workflow

1. **Authorization manifest per engagement** — owner, target, time window, allowed techniques, forbidden actions.
2. **Deny-by-default target gate** outside the model.
3. **Separate security workspace/project** used only for approved internal security work.
4. **Human review for scope expansion** and any consequential action.
5. **Immutable run evidence**: target, model, prompt/task class, effect, result, patch, re-test.
6. **No third-party sharing/proxying** of Trusted Access.
7. **No destructive actions by default**; explicit additional authorization would be required for any higher-impact test.
8. **Stop conditions** for unexpected data access, target ambiguity, scope mismatch, or unstable service behavior.

## Application-ready short answer

> I am requesting Daybreak Red for controlled vulnerability research and exploit validation on systems I own or am explicitly authorized to test. My TrustReady project enforces deterministic target/authority boundaries outside the model and records reproducible evidence from exploit reproduction through patch validation. The public qualification lab is synthetic and network-disabled by design; any real test target would require an explicit authorization manifest, deny-by-default target allowlist, human-reviewed scope, audit evidence, and stop conditions. I will not expose Trusted Access to third parties or use it for customer-facing traffic.

## Evidence commands

```bash
node --test red-lab/lab.test.mjs
node red-lab/run.mjs
cat red-lab/evidence/report.json
```
