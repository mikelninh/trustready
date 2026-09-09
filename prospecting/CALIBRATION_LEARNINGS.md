# TrustReady Prospect Security Signal — Calibration Learnings

## Goal

Find commercially useful, evidence-backed public-source security signals without overstating what passive source analysis can prove.

## Batch 1 — 5 mixed agent repos

Main learning: keyword-level repo scanning is useful for triage but too weak for outbound by itself.

Observed failure modes:
- tests/docs/examples contaminating evidence
- generic words such as `update`, `payment`, `publish` creating false effects
- provider adapters being confused with effect executors
- repo-wide controls being mistaken for controls on the actual dispatch path

Positive learning:
- `model-selected tool call -> concrete tool/handler dispatch sink` is much stronger than repo-wide co-occurrence.
- SuperAgentX provided the first human-reviewed source signal worth runtime validation.

## Batch 2 — 12 framework / MCP / orchestration repos

Classification before human review:
- 5 `PROOF_GAP`
- 5 `REVIEW_SIGNAL`
- 1 `ARCHITECTURE_UNCERTAIN`
- 1 `NO_ACTIONABLE_SIGNAL`

Calibration controls behaved correctly:
- SuperAgentX remained `PROOF_GAP`.
- browser-use did not regress to `PROOF_GAP` after excluding LLM provider-adapter paths.

New false-positive classes discovered:

### 1. Test-path matcher bug

The regex intended to exclude tests did not robustly cover plain `tests/` and `integration_tests/` variants. Any outbound-grade scanner must explicitly exclude:
- `test/`, `tests/`
- `__test__/`, `__tests__/`
- `integration_test/`, `integration_tests/`
- fixtures/examples/docs/playgrounds/evals/benchmarks

### 2. CamelCase / PascalCase controls

Frameworks can expose real authority controls under names such as `ApprovalRequired`, `ToolApproved`, `ToolDenied`, `requiresApproval`, etc. Snake-case-only regexes can miss them and falsely claim a local boundary is absent.

### 3. Framework semantics != application vulnerability

A framework may intentionally execute registered model-selected tools directly. That can be its documented API contract, with authorization delegated to the application/tool implementation. A direct dispatch path in an SDK is therefore a useful architecture signal, but not automatically a commercially useful security gap.

Framework repos are best used for scanner calibration. Application repos with real business effects are better sales prospects.

### 4. Sampling/model adapters

Paths such as LLM/model/provider/sampling handlers often parse, normalize or forward model tool calls. They are not necessarily the effect executor. Provider-adapter exclusion must be semantic, not only path-name based.

## Batch 3 — 8 application-style repos

Segments: email, support, SDR, sales/CRM, autonomous applications.

Automated result:
- 1 `PROOF_GAP`
- 3 `ARCHITECTURE_UNCERTAIN`
- 4 `NO_ACTIONABLE_SIGNAL`
- rejection before human review: 87.5%

Human review of the only `PROOF_GAP` (`capture0x/AdAgent`) found another false positive:
- `modules/agent/backends.py` normalizes model tool-call responses from Ollama.
- the HTTP POST in that file calls the local model backend; it is not the model-selected business/tool effect.
- therefore this is a provider/backend adapter, not evidence of a missing authority boundary at the real effect sink.

## Strongest current lesson

**Direct-dispatch detection must prove selection, not proximity.**

Do not classify `tool_choice/tool_calls` appearing near any function/HTTP call as a direct effect path.

Outbound-grade evidence should require one of these shapes:

1. `model_tool_call.name -> registry[model_tool_call.name] -> invoke(...)`
2. `model_tool_call.name -> getattr(handler, model_tool_call.name) -> invoke(...)`
3. `model_tool_call -> session.call_tool(model_selected_name, model_selected_args)`
4. equivalent AST/data-flow evidence that the model-selected tool identifier controls the effect sink.

A backend API request, serializer, parser, normalizer, schema converter, or model provider call must not qualify.

## Product / GTM implication

Optimize for precision, not lead volume.

Preferred funnel:
1. passive public-source triage
2. human review of exact model -> authority -> effect path
3. only then create a Security Signal draft
4. owned-CI validation (€750 target offer)
5. remediation + Security Delta proof (€1.5k–2.5k)
6. continuous monitoring (€299/mo target)

No automated outbound until the human-reviewed true-signal precision is strong enough.

## Next scanner upgrades

Priority order:
1. replace broad proximity regex with selector/data-flow aware dispatch detection
2. robust test/example/integration-test exclusion
3. expand control vocabulary across snake_case/camelCase/PascalCase
4. classify framework/SDK vs end-user application before lead scoring
5. explicitly recognize backend/provider/serializer/normalizer roles
6. add human labels: `TRUE_SIGNAL`, `FALSE_POSITIVE`, `UNCERTAIN`
7. convert reviewed repos into a growing regression benchmark
8. measure precision on the labeled benchmark before expanding outbound

## Definition of outbound-ready

Do not scale outreach until:
- >= 30 human-reviewed candidates
- >= 80% precision among automated `PROOF_GAP` classifications
- zero known provider-adapter/test-fixture regressions
- every outbound draft cites an exact revision and exact source path
- no passive-source result is described as an exploited or confirmed vulnerability
