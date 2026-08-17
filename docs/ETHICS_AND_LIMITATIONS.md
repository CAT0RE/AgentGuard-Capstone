# Ethics, Safety, and Limitations

## Safe experimentation

The demonstration uses inert tool names and in-memory outputs. It does not send email, transfer money, execute shell commands, delete files, or contact external endpoints. Secrets and account identifiers are explicitly synthetic.

If the project later integrates a real model, keep all experiments inside an isolated test account and sandbox. Use fake credentials, deny network egress by default, impose strict monetary and request limits, and never evaluate destructive payloads against systems without written authorization.

## Data protection

- Do not place real personal email, student records, credentials, or proprietary documents in the benchmark.
- Redact evidence before persistence. The current prototype redacts matched secret evidence but retains raw events, so its audit log must not be used with production secrets.
- Define retention and deletion periods before collecting human-study or operational traces.
- Obtain institutional ethics approval if human participants rate explanations or provide interaction logs.

## Dual-use risk

Attack cases are necessary for evaluation but could guide misuse. Public artifacts should use obviously synthetic endpoints, avoid working malware or real credential formats, and emphasize defensive controls. More powerful adaptive attacks can be kept in a controlled appendix or private evaluation set where institutional policy requires it.

## Principal limitations

1. **Signature dependence:** regex rules can miss novel, multilingual, encoded, or context-sensitive injection.
2. **Mixed evaluation scope:** the bundled cases share assumptions with the implementation, while the external AgentDojo set covers prompt injection but not every AgentGuard threat family.
3. **Coarse taint:** values are tracked mainly by exact overlap and event-level metadata; transformations can evade it.
4. **Uncalibrated scores:** severity and confidence are expert-assigned, not empirical probabilities.
5. **Detector dependence:** overlapping findings violate the independence assumption of noisy-OR.
6. **Intent ambiguity:** a text description and fixed allowlist cannot represent every nuance of user authorization.
7. **In-memory state:** a restart loses traces and there is no multi-tenant isolation.
8. **Audit confidentiality:** raw event storage can create a second sensitive-data repository.
9. **No semantic model:** the offline prototype prioritizes reproducibility over broad semantic recall.
10. **No enforcement below the dispatcher:** a second unmonitored tool channel bypasses the framework.
11. **No hidden-reasoning access:** monitoring uses observable plans/messages and actions, not private chain-of-thought.
12. **No production hardening:** authentication, rate limits, log signing, canonical path enforcement, and OS sandboxing remain external requirements.
13. **Post-hoc detector development:** AgentDojo v1 false negatives informed the v2 structural rules. V2's score on the same traces demonstrates repaired behaviour but is not an untouched generalisation estimate.
14. **Sparse benign confirmation:** InjecAgent supplies attacks but no matched hard-benign corpus. The 17 neutral template controls cannot establish production precision or overdefence.

## Validity threats

### Construct validity

“Unsafe” can mean malicious intent, unacceptable impact, missing authorization, or simply the need for confirmation. The final dataset must label these separately and avoid treating every confirmation as a detector false positive.

### Internal validity

If case authors can inspect detector patterns, accidental test leakage is likely. Holdout authors and annotators should not see implementation details until labels are frozen.

### External validity

Email, file, web, shell, and banking abstractions do not capture every tool schema or organization policy. Results should not be generalized to autonomous production agents without domain-specific evaluation.

The AgentDojo comparison improves external validity because its traces and labels were produced independently. However, AgentDojo's security label measures whether an injection goal succeeded, whereas AgentGuard may also intervene for missing confirmation or consequential action risk. Some measured false positives therefore reflect construct mismatch as well as detector error.

### Conclusion validity

A small number of attacks can produce unstable rates. Use sufficient sample sizes, paired evaluation, confidence intervals, and error analysis. Do not select thresholds on the test set. The v2 paired result is statistically large on the reused traces, but its p-value does not remove adaptive-overfitting risk; a new template-separated holdout is necessary for confirmatory inference.

## Responsible claims

The dissertation should claim that the artifact demonstrates and evaluates a trajectory-aware monitoring architecture. It should not claim to “solve prompt injection,” guarantee safe LLM agents, or replace least-privilege access control and sandboxing.
