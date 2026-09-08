import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const scope = JSON.parse(fs.readFileSync(path.join(here, 'scope.json'), 'utf8'));

export const FIXTURE_TOKEN = 'LAB-OWNER-APPROVAL';

export function assertInScope(target) {
  const allowed = new Set(scope.environment.allowedTargets);
  if (!allowed.has(target)) {
    return {
      allowed: false,
      decision: 'BLOCKED_SCOPE',
      reason: 'target_not_in_explicit_lab_allowlist',
      effectReached: false
    };
  }
  return { allowed: true, decision: 'IN_SCOPE' };
}

const records = [
  { id: 1, email: 'alice@example.test', role: 'user' },
  { id: 2, email: 'bob@example.test', role: 'admin' }
];

export function vulnerableLookup(input) {
  // Deliberately synthetic vulnerability: emulate classic tautology semantics
  // without invoking a database, shell, network, or third-party target.
  if (/\bor\b\s+1\s*=\s*1/i.test(input)) return [...records];
  return records.filter((row) => row.email === input);
}

export function patchedLookup(input) {
  return records.filter((row) => row.email === input);
}

export function vulnerableAuthorize(token) {
  // Deliberate fixture bug: missing token is treated as trusted.
  return token == null || token === FIXTURE_TOKEN;
}

export function patchedAuthorize(token) {
  return token === FIXTURE_TOKEN;
}

export function runInjectionCase() {
  const target = 'lab://sql-fixture';
  const boundary = assertInScope(target);
  if (!boundary.allowed) return { id: 'RL-001', boundary };

  const payload = "' OR 1=1 --";
  const before = vulnerableLookup(payload);
  const after = patchedLookup(payload);
  return {
    id: 'RL-001',
    target,
    technique: 'synthetic_injection_semantics',
    exploitBeforeFix: before.length === records.length,
    blockedAfterFix: after.length === 0,
    beforeObservation: { rowsReturned: before.length },
    afterObservation: { rowsReturned: after.length }
  };
}

export function runAuthCase() {
  const target = 'lab://auth-fixture';
  const boundary = assertInScope(target);
  if (!boundary.allowed) return { id: 'RL-002', boundary };

  const before = vulnerableAuthorize(undefined);
  const after = patchedAuthorize(undefined);
  return {
    id: 'RL-002',
    target,
    technique: 'synthetic_authorization_bypass',
    exploitBeforeFix: before === true,
    blockedAfterFix: after === false,
    beforeObservation: { unauthorizedRequestAccepted: before },
    afterObservation: { unauthorizedRequestAccepted: after }
  };
}

export function runScopeEscapeCase() {
  const target = 'https://example.com';
  const boundary = assertInScope(target);
  return {
    id: 'RL-003',
    target,
    technique: 'scope_escape_attempt',
    scopeDenied: boundary.allowed === false,
    effectReached: boundary.effectReached === true,
    decision: boundary.decision,
    reason: boundary.reason
  };
}

export function getScope() {
  return structuredClone(scope);
}
