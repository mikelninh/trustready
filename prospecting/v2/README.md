# TrustReady Prospect Engine v2

Selector/data-flow aware passive public-source triage for agentic applications.

## Core rule

`PROOF_GAP` requires evidence that a **model-selected tool/action identifier controls the real invocation sink**. Mere proximity between `tool_calls` and an HTTP/process/database call is not sufficient.

Accepted shapes include:
- `tool_call.function.name -> registry[name] -> invoke(...)`
- `tool_call.function.name -> getattr(handler, name) -> func(...)`
- `tool_call -> session.call_tool(model_selected_name, model_selected_args)`

The engine excludes tests/examples/docs and model/provider/serializer/parser/normalizer/backend roles from direct effect claims. Framework/SDK dispatch is downgraded to `REVIEW_SIGNAL` because authorization may intentionally be delegated to application-level handlers.

## Human labels

Every reviewed candidate should become one of:
- `TRUE_SIGNAL`
- `FALSE_POSITIVE`
- `UNCERTAIN`

Those labels form a growing regression benchmark. The key metric is precision among automated `PROOF_GAP` classifications, not raw finding volume.

## Outbound-ready gate

Do not scale outbound until:
- at least 30 human-reviewed candidates
- at least 80% precision among automated `PROOF_GAP`s
- zero known provider-adapter/test-fixture regressions
- every outreach candidate has exact revision + exact selector-to-sink source path

Passive analysis never claims exploitability or a confirmed vulnerability.
