# Architecture and Design Decisions

## Overview

AgentGuard is implemented as a synchronous mediation layer. It is independent of a specific LLM provider or agent framework and uses only the Python standard library. This keeps experiments reproducible and makes the security logic easy to inspect.

## Event lifecycle

1. `start_trace` stores the original user objective, permitted tools, and authorized destinations.
2. `observe` sends each event and prior `TraceState` to every configured detector.
3. Findings are aggregated into a risk score.
4. `MonitorPolicy` maps evidence to a risk level and intervention.
5. The event, assessment, and derived state are committed to the trace and audit store.
6. `can_execute` gates dispatch. Tool output is then returned through `record_tool_result`; `verify`, `confirm`, and `block` output decisions are all quarantined rather than returned to the model.

## Provider-to-tool runner

`MonitoredAgentRunner` supplies a provider with strict function schemas from `ToolSandbox`. Provider output remains data until the runner parses a `function_call`. The corresponding internal tool name and arguments pass through `preflight`; only an allowed decision reaches the sandbox. The sandbox result then passes through `record_tool_result`. Any result requiring verification, confirmation, or blocking is quarantined and is never appended as `function_call_output`, preventing the model from using suspicious content in its next turn.

`ReplayProvider` makes this loop deterministic for offline experiments. `OpenAIResponsesProvider` implements the same interface over the Responses API, so provider choice does not alter the enforcement boundary.

## Event model

Every `TraceEvent` includes:

- globally unique event ID and trace ID;
- monotonic step number and UTC timestamp;
- event kind and source;
- trusted, mixed, or untrusted provenance;
- content, tool name, arguments, and structured metadata.

The model deliberately avoids storing private chain-of-thought. An application may provide an observable plan or rationale as `agent_message`, but security decisions should rely on proposed actions and data provenance whenever possible.

## Detector separation

Detectors are side-effect-free functions over `(event, previous_trace_state)`. This enables ablation studies, independent testing, and future replacement with learned classifiers. Findings retain:

- category and human-readable title;
- severity and confidence;
- clipped or redacted evidence;
- remediation recommendation;
- critical override flag;
- mappings such as OWASP or MITRE ATLAS tags.

AgentGuard v2 adds two detector families without changing this interface. `StructuralInjectionDetector` identifies prerequisite-task hijacking, embedded authority claims, instruction-like containers, and return-to-original-task framing in untrusted data. `GoalAlignmentDetector` extracts coarse action families and flags an imperative or side-effecting tool that is not supported by the authenticated user objective. The latter is deliberately weak evidence on its own and becomes intervention-worthy primarily when corroborated by structural or tool-policy evidence.

Before lexical and structural matching, `normalize_security_text` decodes HTML entities, applies Unicode NFKC compatibility normalisation, removes common invisible formatting controls, and collapses whitespace. The transformation is bounded and never executes or recursively decodes attacker-controlled content.

## Stateful controls

### Taint tracking

Prompt-injected outputs are marked by event ID. Secret-like values are retained in memory for exact downstream overlap detection. Production deployments should store hashes or structured data labels rather than plaintext secrets in monitor memory.

### Error propagation

Tool errors and uncertain results append an unresolved provenance marker. Read-only operations may continue, but a reversible or irreversible side effect raises an error-propagation finding. Only an explicit `verification` event clears the error state.

### Capability and destination binding

The tool registry declares impact, capabilities, sensitive output, egress behaviour, and confirmation requirements. Each trace can narrow this registry further. A user-approved destination is exact-bound so a model cannot silently substitute another recipient.

## Policy profiles

| Profile | Log | Verify | Confirm | Block |
|---|---:|---:|---:|---:|
| Strict | 15 | 30 | 48 | 68 |
| Balanced | 20 | 38 | 58 | 78 |
| Permissive | 30 | 48 | 68 | 88 |

Critical evidence at confidence `≥ 0.75` blocks under all bundled profiles.

## Auditability

`JsonlAuditStore` stores one JSON object per line containing the original event and complete assessment. JSONL allows streaming, diffing, and import into common security analytics tools. Production hardening should add log signing, retention rules, access control, and sensitive-field redaction.

## API and dashboard

The standard-library `ThreadingHTTPServer` exposes:

- `GET /api/health`
- `GET /api/scenarios`
- `GET /api/agent-scenarios`
- `POST /api/run`
- `POST /api/agent-run`
- `POST /api/evaluate`
- `GET /api/traces`
- `GET /api/traces/{trace_id}`

The browser dashboard is a static HTML/CSS/JavaScript client. It performs no real tool actions and depends only on the local API.

## Extension points

- Implement `Detector.analyze` for a learned prompt-injection model or policy engine.
- Register real tools with `ToolRegistry.register`.
- Replace `JsonlAuditStore` with an authenticated database or SIEM sink.
- Wrap LangGraph, AutoGen, CrewAI, MCP, or a custom loop at their tool-dispatch boundary.
- Add graph-level provenance to relate individual output fields to downstream arguments.
- Calibrate risk scores with a labelled validation set using logistic regression or isotonic regression.

## Design trade-offs

1. **Deterministic rules over mandatory LLM judge:** reproducible, fast, and offline; weaker on paraphrases and context-dependent intent.
2. **Noisy-OR over maximum score:** captures corroboration; assumes partially independent findings even when rules overlap.
3. **Per-trace in-memory state:** simple prototype; not durable or horizontally scalable.
4. **Exact destination matching:** clear and safe; production systems need canonicalisation for addresses, domains, and identifiers.
5. **Synthetic sandbox:** ethically safe and repeatable; weaker external validity than a real agent operating over real applications.
6. **Benchmark-specific v2 rules:** structural rules improve the reused AgentDojo traces substantially, but an untouched InjecAgent base test yields zero intervention recall. The rules repair a known template and do not provide semantic generalisation.
