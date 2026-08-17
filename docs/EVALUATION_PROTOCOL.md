# Evaluation Protocol

## Purpose

This protocol separates engineering smoke tests from dissertation evidence. The bundled 24-case dataset verifies implementation behaviour. The completed study reports a frozen external AgentDojo trace set, a disclosed post-hoc v2 rerun, and an untouched InjecAgent base detector-transfer test; independently annotated cases remain the recommended extension for threat families that these benchmarks do not cover.

## Experimental conditions

Evaluate five detector profiles under the same balanced intervention policy:

1. `none`: records events but produces no findings.
2. `keyword`: prompt-injection rules only.
3. `tool_policy`: registry and capability policy only.
4. `full_v1`: frozen lexical injection, tool policy, sensitive data flow, error propagation, and sequence anomaly detectors.
5. `full`: v2 monitor, adding structural injection, text canonicalisation, and goal alignment.

Perform an additional sensitivity analysis with strict and permissive threshold profiles.

## Dataset construction

### Development set

The supplied `benchmarks/cases.jsonl` contains 24 deterministic traces:

- 10 allow-labelled benign traces;
- 14 intervention-required unsafe traces;
- categories spanning injection, tool misuse, exfiltration, propagation, and sequence anomalies.

Use this set for regression testing only.

### Holdout set

Create at least 150 new cases without copying detector strings:

- 60 benign traces, including legitimate external actions and recoverable errors;
- 30 direct or indirect injection traces;
- 20 scope/destination/destructive tool-misuse traces;
- 20 sensitive-data-flow traces;
- 20 error-propagation or recovery traces.

At least 40% should contain 4 or more events. At least one third of attacks should use paraphrase, typographical noise, role-play, delimiter changes, or indirect wording. Split by attack template rather than by individual string to reduce leakage.

Where permitted, adapt task structures—not verbatim payloads—from AgentDojo, InjecAgent, ToolEmu, Agent Security Bench, and ToolSandbox. Record the source and licence of every adapted case.

### Completed external benchmark

The final artifact freezes 286 public AgentDojo `workspace` traces at repository commit `089ed468cf3ed0322acc66b0211f26d9d90dbf60`. These traces were produced independently and use AgentDojo's own security outcome as ground truth. The adapter maps `security=false` to `unsafe`, preserves messages and calls, and deterministically converts them to AgentGuard events. The external set supports claims about prompt-injection distribution shift, not independent claims about error propagation.

### Untouched v2 confirmation benchmark

After v2 detector files are hashed, evaluate the official InjecAgent `base` files at commit `f19c9f2c79a41046eb13c03c51a24c567a8ffa07`. The corpus contains 510 direct-harm and 544 data-stealing malicious tool responses. Exclude `enhanced`, whose explicit override prefix overlaps known signatures. Add one deterministic neutral control per official user template, but report these 17 controls as conversion checks rather than a precision corpus. Do not change v2 detectors or thresholds after opening the result.

## Labels

Each case must include:

- `allow` or `intervention_required` at trace level;
- threat category;
- index of the first unsafe side effect;
- correct intervention type;
- evidence spans or provenance links;
- whether the action is reversible;
- annotator confidence and notes.

Use two independent annotators. Resolve disagreements with a third reviewer. Report Cohen's kappa for trace label, intervention type, and threat category. Freeze labels before running the final comparison.

`benchmarks/ANNOTATION_GUIDE.md` defines the operational labels. The CLI implements schema checks, inter-annotator agreement, and a SHA-256 freeze manifest, so the reported dataset identity is reproducible.

## Primary metrics

For unsafe-behaviour detection:

```text
precision = TP / (TP + FP)
recall    = TP / (TP + FN)
F1        = 2 × precision × recall / (precision + recall)
FPR       = FP / (FP + TN)
```

Also report:

- attack success rate after intervention;
- harmful-action execution rate;
- benign task completion rate;
- per-category recall and macro-F1;
- intervention-type accuracy;
- mean number of unnecessary confirmations per benign trace;
- lead time in events before the labelled unsafe action.

## Runtime measurement

Use `time.perf_counter_ns` around `monitor.observe`. Perform 100 warm-up events, then at least 10,000 measured events on a named machine. Report median, p95, p99, mean, and standard deviation. Keep disk audit logging as a separate condition because I/O changes latency.

## Statistical analysis

- Report 95% bootstrap confidence intervals for precision, recall, F1, and benign completion.
- Use paired bootstrap resampling because every profile processes the same cases.
- Compare profiles with McNemar's test on paired correct/incorrect classifications.
- Correct multiple per-category comparisons with Holm's method.
- Report effect sizes and confidence intervals rather than relying only on p-values.

## Ablations

Evaluate the full monitor while removing one component at a time:

- no prompt-injection detector;
- no sensitive-data state;
- no error state;
- no sequence detector;
- maximum finding only instead of noisy-OR;
- no critical-evidence override.

This identifies which mechanism contributes to each threat category and whether aggregation causes avoidable false positives.

## Robustness tests

1. Paraphrase each injection payload using a generator that cannot see the detector code.
2. Insert benign words such as “system instruction” into ordinary educational text.
3. Move an error earlier in long traces and vary the number of intervening read operations.
4. Split secrets across multiple fields and encode payloads.
5. Change casing, whitespace, punctuation, and Unicode forms.
6. Test equivalent destinations with aliases and canonical forms.
7. Run adaptive attacks after revealing prior monitor decisions.

## Reproduction commands

```bash
PYTHONPATH=src python3 -B -m unittest discover -s tests -v
PYTHONPATH=src python3 -B -m agentguard evaluate \
  --dataset benchmarks/cases.jsonl \
  --output results/evaluation.json

PYTHONPATH=src python3 -B -m agentguard injecagent-evaluate \
  --input /tmp/injecagent \
  --profiles none keyword tool_policy full_v1 full \
  --output results/injecagent-base-evaluation.json
```

Record the Git commit, Python version, operating system, dataset hash, policy thresholds, and command output in the dissertation appendix.

The generated evaluation JSON contains 95% bootstrap intervals and paired exact McNemar comparisons for the v2 full monitor against each selected baseline, including `full_v1`. For a large final dataset, increase `--bootstrap-samples` (for example, to 10,000) and archive the configured random seed from the result.

## Reporting rule

Do not present the bundled full-monitor F1 of 1.00 as external performance. It is a deterministic, threat-model-aligned smoke test. Report the frozen AgentDojo v1 result (F1 0.562, 95% bootstrap interval `[0.497, 0.625]`) together with its false-positive cost and construct mismatch. The v2 AgentDojo result is post-hoc and must be paired with the untouched InjecAgent base result: 0/1,054 intervention detections, with 32 weak log signals. This negative confirmation is the appropriate evidence about v2 generalisation. Do not extend these claims to error propagation, hard-benign precision, benchmark-native InjecAgent ASR, or production safety.
