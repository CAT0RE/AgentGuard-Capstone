# Project Plan and Completion Record

The reproducible prototype, external prompt-injection evaluation, dissertation draft, and defence deck are complete. The schedule below remains a recommended programme workflow; rows marked external or institutional require supervisor confirmation rather than additional software implementation.

## Twelve-week schedule

| Week | Primary outcome | Exit criterion |
|---:|---|---|
| 1 | Supervisor scope review | Research questions, threat model, and success criteria approved |
| 2 | Literature matrix | At least 25 relevant primary sources coded by threat, control, and evaluation method |
| 3 | Benchmark specification | Label schema, authoring guide, and ethics constraints frozen |
| 4 | External dataset freeze | AgentDojo traces and untouched InjecAgent base inputs frozen with provenance and hashes |
| 5 | External evaluation | Frozen v1 profiles and disclosed v2 post-hoc profile run against AgentDojo labels |
| 6 | Error analysis | Confidence intervals, paired tests, false positives, and false negatives reported |
| 7 | Final implementation freeze | Unit tests pass; thresholds selected only on development data |
| 8 | Main experiment | Five profiles executed on frozen external traces; raw results archived |
| 9 | Robustness and ablation | Development ablations, AgentDojo shift, and negative InjecAgent confirmation complete |
| 10 | Analysis and figures | Confidence intervals, tests, plots, and failure analysis complete |
| 11 | Full dissertation draft | Every chapter and appendix ready for supervisor feedback |
| 12 | Revision and submission | Claims checked against evidence; artifact reproduced from clean environment |

## Definition of done

- Research questions map directly to reported experiments.
- A separate external set—not `benchmarks/cases.jsonl`—supports the prompt-injection headline claim.
- Dataset licences and origins are documented.
- External benchmark-native labels are used; human inter-annotator agreement is reserved for a future error-propagation holdout.
- Baselines, confidence intervals, paired tests, latency, and error analysis are included.
- The repository runs from the documented commands on a clean machine.
- No demonstration invokes a real destructive or external tool.
- Dissertation limitations explicitly distinguish smoke-test and holdout performance.

## Supervisor-dependent submission decisions

1. Required dissertation word count and formatting style.
2. Whether synthetic traces alone are acceptable or a real LLM agent must be evaluated.
3. Whether human annotation or an explanation-usability study requires ethics approval.
4. Minimum dataset size and expected statistical analysis.
5. Preferred reference style and artifact submission format.
