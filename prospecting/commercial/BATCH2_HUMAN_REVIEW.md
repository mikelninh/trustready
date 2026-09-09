# Commercial prospect batch 2 — human review

Truth boundary: public-source architecture review only. No third-party system was executed or tested. A TRUE source signal is not a confirmed vulnerability.

| Rank | Repository | Automated result | Human review | Outreach |
|---|---|---|---|---|
| 1 | AOrbitron/Eridanus | PROOF_GAP / 73 | Generic model-selected tool executor is visible, but review did not establish a buyer-relevant consequential production effect owned by a plausible customer. | NO |
| 2 | ADAMAMZAR/loop-engineering | PROOF_GAP / 68 | Contains direct tool execution examples, but also explicit safety harness / mutating-tool controls. Primarily an engineering/learning repo, not a strong buyer lead. | NO |
| 3 | rlarson20/Au | PROOF_GAP / 67 | TRUE source signal: model-selected tool can reach file editing without an independent dispatch-time authority gate. Individual/stale repo; weak buyer fit. | NO |
| 4 | sanbuphy/nanoAgent | PROOF_GAP / 67 | TRUE source signal: model selects execute_bash/write_file and dispatches directly from a registry; bash uses shell execution. Small individual repo; weak buyer fit. | NO |
| 5 | sanbuphy/nanoSkills | PROOF_GAP / 63 | TRUE-style file/action signal, but individual experimental repo and weak commercial fit. | NO |
| 6 | JoelKong/PersonalAgents | PROOF_GAP / 62 | Previously human-confirmed source signal for model-selected Gmail send effect. Repo is old and personal; weak buyer fit. | NO |
| 7 | TGiacinto/tuccia-assistant | PROOF_GAP / 62 | Previously human-confirmed source signal for model-selected Home Assistant actuation. Repo is old/personal; weak buyer fit. | NO |
| 8 | Doriandarko/make-it-heavy | PROOF_GAP / 62 | Previously human-confirmed source signal for model-selected write_file through dynamic tool mapping. Personal/older repo; weak buyer fit. | NO |
| 9 | oomol-lab/open-connector | ARCHITECTURE_UNCERTAIN / 55 | Strong company/product fit, but current bounded source review does not prove one unguarded model-selector-to-consequential-effect path. | NO |
| 10 | getomnico/omni | ARCHITECTURE_UNCERTAIN / 55 | Commercially relevant platform, but approval/intervention infrastructure exists and the reviewed path is not an outbound-grade gap. | NO |

## Result

41/41 repositories completed. The automated outreach queue remained empty, and human review agrees with that outcome.

The bottleneck is now **joint discovery**, not scanner precision: we need candidates where company/product ownership and a concrete consequential selector path are both present from the start.

## Next discovery gate

A candidate should enter commercial review only when discovery can establish all of:

1. active company/team-owned or clearly monetized product;
2. model-selected tool/action provenance;
3. consequential effect owned by that product (email/CRM/write/browser/shell/payment/etc.);
4. no independently visible authority gate on that exact path;
5. plausible technical buyer/contact.

Do not lower the score threshold merely to manufacture leads.
