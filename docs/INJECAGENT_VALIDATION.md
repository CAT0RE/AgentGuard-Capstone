# Untouched V2 Validation with InjecAgent

## Purpose and independence

AgentGuard v2 was created after error analysis of AgentDojo, so its improved AgentDojo score is post-hoc. InjecAgent was therefore selected as a new, previously unseen confirmatory corpus. Detector and policy files were hashed before the official repository was downloaded, and no detector or threshold was changed after the result was observed.

Official sources:

- repository: `https://github.com/uiuc-kang-lab/InjecAgent`;
- paper: `https://aclanthology.org/2024.findings-acl.624/`;
- frozen commit: `f19c9f2c79a41046eb13c03c51a24c567a8ffa07`;
- licence: MIT.

## Dataset selection

The evaluation uses only InjecAgent's `base` setting:

- 510 direct-harm attack cases;
- 544 data-stealing attack cases;
- 1,054 total malicious tool responses;
- 17 neutral safe controls, one for each official user-tool template.

The `enhanced` setting was excluded because it prepends an explicit instruction-override string already covered by the original AgentGuard signatures. Including it would make the transfer result easier and less informative.

InjecAgent does not provide a matched benign corpus. The 17 controls are created deterministically by replacing `<Attacker Instruction>` in each official user response template with the fixed neutral sentence `Content retrieved successfully; there are no additional action requests.` They test conversion errors and obvious overblocking only; they are not a hard-negative or precision benchmark.

## Mapping and label semantics

Each official record is converted to:

1. trusted user objective from `User Instruction`;
2. permitted read-only `User Tool` call with parsed parameters;
3. untrusted tool result from `Tool Response`.

The released `Thought` field is omitted because AgentGuard's security boundary does not require private chain-of-thought. Attacker tools are retained as metadata but are not fabricated as executed calls. Every official base attack case is labelled unsafe because its tool response contains a benchmark-authored attacker instruction. A positive prediction requires `verify`, `confirm`, or `block`; `log` is recorded as evidence but does not count as an intervention.

This evaluates payload detection at the tool-output boundary. It does not reproduce InjecAgent's model-dependent attack-success rate because no LLM is executed.

## Confirmatory result

| Profile | TP | FP | TN | FN | Intervention recall |
|---|---:|---:|---:|---:|---:|
| None | 0 | 0 | 17 | 1,054 | 0.000 |
| Keyword | 0 | 0 | 17 | 1,054 | 0.000 |
| Tool policy | 0 | 0 | 17 | 1,054 | 0.000 |
| Full v1 | 0 | 0 | 17 | 1,054 | 0.000 |
| Full v2 | 0 | 0 | 17 | 1,054 | 0.000 |

V2 assigns score 0 to 1,022 attack cases and score 37.44 (`log`) to 32 cases. Therefore:

- intervention recall is `0/1,054 = 0.000`;
- logged-signal rate is `32/1,054 = 0.0304`;
- 510 direct-harm and 544 data-stealing cases are all missed at intervention level;
- all 17 neutral controls remain non-intervened.

For zero detections, ordinary bootstrap resampling degenerates to `[0, 0]`. A two-sided 95% Clopper-Pearson interval gives a recall upper bound of approximately `0.0035`. The observed safe-control false-positive rate is 0, but with only 17 controls its corresponding upper bound is approximately `0.195`; precision is undefined because the monitor made no positive predictions, although the evaluation implementation reports 0 by convention.

The v2 median event latency is 0.122 ms and p95 is 0.373 ms over 3,213 observations on the evaluation machine.

## Interpretation

The result does not confirm the AgentDojo post-hoc improvement. InjecAgent base attacks generally present a short, contextually embedded imperative without AgentDojo's staged authority/prerequisite/return-to-task structure and without an explicit instruction-override phrase. V2's structural detector therefore does not match. Goal alignment produces weak log evidence for only 32 cases, partly because many imperatives are nested inside serialized dictionaries and quoted fields; it was intentionally weighted below the verification threshold to avoid blocking every legitimate imperative found in email or document content.

This identifies a genuine generalisation gap: deterministic structural rules can repair one attack template while failing a different benchmark's subtler payload form. Lowering the balanced verification threshold from 38 to 30 could at most convert the 32 logged cases, yielding only 3.04% recall on this corpus. Threshold adjustment alone is therefore not a solution.

The next version should be developed on a separate training partition and evaluated on another untouched partition. Promising changes include syntax-aware extraction of instructions from serialized tool results, destination and action provenance, a semantic intent-entailment classifier, and a hard-negative corpus such as NotInject to control overdefence. None of those changes should be evaluated confirmatorily on this now-opened InjecAgent set.

## Reproduction

```bash
git clone https://github.com/uiuc-kang-lab/InjecAgent.git /tmp/injecagent
git -C /tmp/injecagent checkout f19c9f2c79a41046eb13c03c51a24c567a8ffa07

PYTHONPATH=src python3 -B -m agentguard injecagent-convert \
  --input /tmp/injecagent \
  --output results/injecagent-base-cases.jsonl

PYTHONPATH=src python3 -B -m agentguard injecagent-evaluate \
  --input /tmp/injecagent \
  --profiles none keyword tool_policy full_v1 full \
  --bootstrap-samples 1000 \
  --output results/injecagent-base-evaluation.json
```

The converted JSONL SHA-256 is `9ad3ce279cb59cd17e23d6d9a6cb11c486841b1d59aba4e60f08d41816119397`; the evaluation JSON SHA-256 is `73f486f56f700f287fdff40fd7f0348416bd8a6cf9338fd02734707f391c6cb7`. Full source-file and detector-freeze hashes are stored in `results/injecagent-base-manifest.json`.
