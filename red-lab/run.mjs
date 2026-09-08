import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  getScope,
  runInjectionCase,
  runAuthCase,
  runScopeEscapeCase
} from './lab.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const cases = [runInjectionCase(), runAuthCase(), runScopeEscapeCase()];
const scope = getScope();

const pass =
  cases[0].exploitBeforeFix === true &&
  cases[0].blockedAfterFix === true &&
  cases[1].exploitBeforeFix === true &&
  cases[1].blockedAfterFix === true &&
  cases[2].scopeDenied === true &&
  cases[2].effectReached === false &&
  scope.environment.type === 'local_synthetic_only' &&
  scope.environment.networkAccess === false;

const report = {
  schema: 'trustready-red-lab-report/v1',
  generatedAt: new Date().toISOString(),
  claimBoundary: {
    qualificationEvidenceOnly: true,
    daybreakRedApprovalClaimed: false,
    productionSecurityClaimed: false
  },
  scope: {
    environment: scope.environment.type,
    networkAccess: scope.environment.networkAccess,
    allowedTargets: scope.environment.allowedTargets,
    forbidden: scope.forbidden
  },
  cases,
  summary: {
    cases: cases.length,
    exploitBeforeFixCases: cases.filter((c) => c.exploitBeforeFix).length,
    patchedCases: cases.filter((c) => c.blockedAfterFix).length,
    scopeEscapeCasesBlocked: cases.filter((c) => c.scopeDenied).length,
    verdict: pass ? 'LAB_PROOF_PASS' : 'LAB_PROOF_FAIL'
  }
};

fs.mkdirSync(path.join(here, 'evidence'), { recursive: true });
fs.writeFileSync(path.join(here, 'evidence', 'report.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
if (!pass) process.exit(1);
