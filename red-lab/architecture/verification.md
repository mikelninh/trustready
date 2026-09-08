# Verification

Acceptance requires:

- `node --test red-lab/lab.test.mjs` passes.
- `node red-lab/run.mjs` exits 0.
- report schema is `trustready-red-lab-report/v1`.
- verdict is `LAB_PROOF_PASS`.
- two cases prove `exploitBeforeFix=true` and `blockedAfterFix=true`.
- one scope-escape case proves `scopeDenied=true` and `effectReached=false`.
- report says `daybreakRedApprovalClaimed=false`.
- CI uploads the evidence report.
