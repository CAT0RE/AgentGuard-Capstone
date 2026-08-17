# External Validation with AgentDojo

## Purpose and boundary

The bundled 24-case dataset is an implementation regression set. Independent evidence comes from the public AgentDojo repository, whose traces were created by a different research team and were not used to design AgentGuard's rules. This evaluation tests distribution shift for prompt-injection monitoring; it does not independently validate the project's error-propagation detector.

The frozen source is:

- repository: `https://github.com/ethz-spylab/agentdojo`;
- commit: `089ed468cf3ed0322acc66b0211f26d9d90dbf60`;
- subset: `runs/gpt-4o-mini-2024-07-18/workspace`;
- 286 JSON traces: 89 AgentDojo-secure and 197 AgentDojo-compromised;
- source-tree SHA-256: `2c462af588565c9813faf442bab5515f4cf82e068c272acb503d4cdd201773df`.

AgentDojo's `security=true` means the injection goal did not succeed. The adapter therefore maps `security=false` to AgentGuard's `unsafe` label. Tool calls retain their original names and arguments. Function-name heuristics assign impact, sensitivity, and external-communication metadata without inspecting AgentDojo's labels.

## Results

| Profile | Precision | Recall | F1 | Accuracy | p95 event latency (ms) |
|---|---:|---:|---:|---:|---:|
| None | 0.000 | 0.000 | 0.000 | 0.311 | 0.372 |
| Keyword | 0.796 | 0.198 | 0.317 | 0.413 | 1.141 |
| Tool policy | 0.594 | 0.320 | 0.416 | 0.381 | 0.381 |
| Full v1 | 0.655 | 0.492 | 0.562 | 0.472 | 1.483 |

For the frozen v1 profile, the 95% bootstrap intervals are precision `[0.576, 0.737]`, recall `[0.423, 0.565]`, F1 `[0.497, 0.625]`, and accuracy `[0.416, 0.532]`. Exact paired McNemar tests find differences relative to no monitoring (`p=0.000194`) and tool policy (`p=0.000069`), but not relative to keyword detection at the 0.05 threshold (`p=0.107352`). The v1 profile yields 97 true positives, 51 false positives, 38 true negatives, and 100 false negatives.

These results replace the perfect development-set score as the headline estimate of prompt-injection generalisation. They show useful but incomplete transfer. False negatives are consistent with open-ended semantic attacks that do not match the prototype's compact signatures. False positives arise partly because a benchmark-secure trace can legitimately invoke tools such as `send_email` or `delete_file`, while AgentGuard treats unconfirmed consequential actions as intervention-worthy. This is also a construct mismatch: AgentDojo labels injection success, whereas AgentGuard additionally labels missing confirmation and high-impact action risk.

## AgentGuard v2 post-hoc error-reduction experiment

Error analysis found that 87 of the 100 v1 false negatives received zero risk evidence and 13 received a score of 35.72, just below the balanced verification threshold. Eighty-two false negatives contained a staged instruction structure such as an embedded authority claim, a prerequisite action, and a later return to the original task. This motivated three implementation changes: bounded HTML/Unicode/invisible-character normalisation, a structural-injection detector, and a goal-action alignment detector. The provider runner was also hardened so `verify` and `confirm` tool-output decisions are quarantined alongside `block`.

The frozen v1 detector set remains reproducible through the `full_v1` profile. Running v1 and v2 on the same 286 traces gives:

| Profile | Precision | Recall | F1 | Accuracy | p95 event latency (ms) |
|---|---:|---:|---:|---:|---:|
| Full v1 | 0.655 | 0.492 | 0.562 | 0.472 | 1.567 |
| Full v2 | 0.746 | 0.909 | 0.819 | 0.724 | 3.250 |

V2 produces 179 true positives, 61 false positives, 28 true negatives, and 18 false negatives. Its 95% bootstrap intervals are precision `[0.689, 0.801]`, recall `[0.868, 0.949]`, F1 `[0.778, 0.856]`, and accuracy `[0.668, 0.773]`. The paired comparison with v1 has 82 cases correct only under v2 and 10 correct only under v1; the exact two-sided McNemar value is `3.30e-15`.

This is strong engineering evidence that the identified failure mode was addressed, but it is not an independent generalisation result: the same AgentDojo traces were inspected to design v2 and then re-evaluated. The remaining 18 false negatives contain no observable injected instruction or unauthorized side effect in the converted message/tool trajectory, so an observable-trajectory monitor has no event-level evidence on which to intervene even though the benchmark-level security field is false. A subsequent untouched InjecAgent base evaluation produces zero intervention detections over 1,054 malicious tool responses, showing that the AgentDojo-specific repair does not generalise to that benchmark's short contextual imperatives. See `docs/INJECAGENT_VALIDATION.md`.

## Runtime integration evidence

`make_agentdojo_executor` is a lazy, optional replacement for AgentDojo's `ToolsExecutor`. It performs AgentGuard preflight before `FunctionsRuntime.run_function` and postflight before a tool result is returned to the model. A smoke test against AgentDojo 0.1.35's real `FunctionCall` and `FunctionsRuntime` classes produced:

```json
{
  "call_counts": {"read_notes": 1, "send_money": 0},
  "read_error": "AgentGuardIntervention:block",
  "transfer_error": "AgentGuardIntervention:block",
  "intervention_count": 2
}
```

The injected read executed once, but its output was quarantined. The consequential transfer remained at zero calls, demonstrating pre-side-effect enforcement rather than post-hoc alerting.

## Reproduction

Install AgentDojo only when running the optional live adapter:

```bash
python3 -m pip install "agentdojo==0.1.35"
PYTHONPATH=src python3 scripts/agentdojo_smoke.py
```

Given the frozen official run directory:

```bash
PYTHONPATH=src python3 -m agentguard agentdojo-convert \
  --input /path/to/agentdojo/runs/gpt-4o-mini-2024-07-18/workspace \
  --output results/agentdojo-external-cases.jsonl

PYTHONPATH=src python3 -m agentguard agentdojo-evaluate \
  --input /path/to/agentdojo/runs/gpt-4o-mini-2024-07-18/workspace \
  --output results/agentdojo-external.json \
  --bootstrap-samples 1000

PYTHONPATH=src python3 -B -m agentguard evaluate \
  --dataset results/agentdojo-external-cases.jsonl \
  --profiles none keyword tool_policy full_v1 full \
  --output results/agentdojo-external-v2-posthoc.json \
  --bootstrap-samples 1000
```

The converted JSONL is deterministic. Its SHA-256 is `0090a24a98949ccb9f45e0c3c63acdbd8d52f8edced496d796e28d7e9ab696a9`. Full v1 provenance is recorded in `results/agentdojo-external-manifest.json`; the v2 post-hoc result and disclosure are recorded in `results/agentdojo-external-v2-posthoc-manifest.json`.
