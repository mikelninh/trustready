import test from 'node:test';
import assert from 'node:assert/strict';
import {
  assertInScope,
  runInjectionCase,
  runAuthCase,
  runScopeEscapeCase
} from './lab.mjs';

test('explicit lab targets are allowed', () => {
  assert.equal(assertInScope('lab://sql-fixture').allowed, true);
});

test('external targets are denied before any effect', () => {
  const result = assertInScope('https://example.com');
  assert.equal(result.allowed, false);
  assert.equal(result.decision, 'BLOCKED_SCOPE');
  assert.equal(result.effectReached, false);
});

test('RL-001 proves exploit-before-fix and patch-after-fix', () => {
  const result = runInjectionCase();
  assert.equal(result.exploitBeforeFix, true);
  assert.equal(result.blockedAfterFix, true);
  assert.equal(result.beforeObservation.rowsReturned, 2);
  assert.equal(result.afterObservation.rowsReturned, 0);
});

test('RL-002 proves auth-bypass-before-fix and patch-after-fix', () => {
  const result = runAuthCase();
  assert.equal(result.exploitBeforeFix, true);
  assert.equal(result.blockedAfterFix, true);
  assert.equal(result.beforeObservation.unauthorizedRequestAccepted, true);
  assert.equal(result.afterObservation.unauthorizedRequestAccepted, false);
});

test('RL-003 blocks out-of-scope target', () => {
  const result = runScopeEscapeCase();
  assert.equal(result.scopeDenied, true);
  assert.equal(result.effectReached, false);
});
