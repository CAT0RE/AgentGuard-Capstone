# Research Design

## 1. Working title

**Security Monitoring for LLM Agents: Detecting Unsafe Tool Use, Prompt Injection, and Error Propagation**

## 2. Problem statement

Tool-using language-model agents combine natural-language planning with actions over email, files, web content, APIs, and other systems. This creates a control-flow boundary in which model-generated decisions can produce real side effects. Untrusted tool output can also contain instructions that the model interprets as authoritative, while a failed tool result can silently influence later actions.

Existing point controls address only part of this problem. Prompt keyword filters do not reason about tool capability or cross-event data flow; tool allowlists do not identify malicious instructions in permitted content; and end-to-end success metrics can hide the intermediate error that caused an unsafe action. A runtime monitor should therefore reason over the complete observable trajectory and intervene before a high-impact action.

## 3. Aim

Design, implement, and evaluate an explainable runtime security monitor that scores each observable agent event and recommends proportionate interventions before unsafe tool use causes harm.

## 4. Objectives

1. Define a threat model covering prompt injection, unsafe tool use, sensitive-data egress, and error propagation.
2. Define a common event schema for user input, observable agent messages, tool calls, tool results, errors, and verification.
3. Implement modular detectors that combine local evidence with trace history.
4. Produce an interpretable 0–100 risk score and policy decision for every event.
5. Demonstrate blocking, verification, and human-confirmation interventions in a sandbox.
6. Compare the full system with no-monitor, keyword-only, and tool-policy-only baselines.
7. Measure security performance, usability cost, and runtime overhead on a held-out labelled benchmark.

## 5. Research questions

**RQ1. Detection effectiveness:** Does trajectory-aware monitoring improve recall and F1 for unsafe agent behaviour compared with keyword-only and tool-policy-only baselines?

**RQ2. Intervention quality:** How accurately can an event-level risk policy select an appropriate intervention—allow, log, verify, confirm, or block—without unnecessarily interrupting benign tasks?

**RQ3. Error propagation:** Does retaining explicit unresolved-error state reduce consequential actions based on incorrect or uncertain upstream tool results?

**RQ4. Explainability and cost:** What evidence and runtime overhead does the monitor introduce, and are its explanations sufficient for a reviewer to identify why an intervention occurred?

## 6. Hypotheses

- **H1:** The full trajectory-aware monitor achieves higher unsafe-behaviour recall and F1 than each single-layer baseline.
- **H2:** Cross-event sensitive-data and error state detects cases missed by independent event classification.
- **H3:** Risk-tiered intervention reduces executed harmful actions while preserving at least 90% benign task completion on the independent holdout set.
- **H4:** The deterministic monitor adds less than 10 ms median processing latency per event on the evaluation machine.

H3 and H4 are targets to test, not results already established by the bundled smoke-test dataset.

## 7. Research method

The project follows a design-science methodology:

1. **Problem identification:** derive risks from literature, security standards, and representative agent workflows.
2. **Artifact design:** define the event model, detectors, aggregation function, and intervention policy.
3. **Implementation:** build a framework-independent monitor and simulated tools.
4. **Demonstration:** execute benign, adversarial, and failure-propagation scenarios.
5. **Evaluation:** compare baselines using a frozen, independently labelled holdout dataset and report uncertainty.
6. **Reflection:** analyze failure modes, external validity, ethical limits, and production requirements.

## 8. Conceptual model

Let a trace be `τ = (e₁, e₂, …, eₜ)`, where every event records kind, source, trust, content, tool identity, arguments, and metadata. For event `eₜ`, detector `dᵢ` emits zero or more findings with severity `sᵢ ∈ [0,100]` and confidence `cᵢ ∈ [0,1]`.

The prototype calculates:

```text
xᵢ = (sᵢ × cᵢ) / 100
R(eₜ | τ<t) = 100 × (1 − ∏ᵢ(1 − xᵢ))
```

Noisy-OR avoids simply adding scores beyond 100 and increases risk when independent evidence corroborates. A critical finding above the configured confidence threshold can override the numeric thresholds.

Default interventions are:

| Score/evidence | Decision | Intended effect |
|---|---|---|
| `< 20` | Allow | Continue normally |
| `20–37.99` | Log | Continue and preserve evidence |
| `38–57.99` | Verify | Pause for a second source or deterministic validation |
| `58–77.99` | Confirm | Show exact action to the user |
| `≥ 78` or critical evidence | Block | Deny the event and stop the unsafe branch |

The score ranks risk under a policy; it is not a statistically calibrated probability.

## 9. Independent and dependent variables

Independent variables:

- Monitor profile: none, keyword-only, tool-policy-only, frozen full v1, post-hoc full v2.
- Policy profile: strict, balanced, permissive.
- Threat category and content trust level.
- Trace length and error position.
- Attack phrasing: canonical, paraphrased, obfuscated.
- External corpus: AgentDojo trajectory outcomes versus untouched InjecAgent base tool-response payloads.

Dependent variables:

- Precision, recall, F1, accuracy, false-positive rate, and false-negative rate.
- Attack success rate and harmful-action execution rate.
- Benign task completion rate.
- Intervention-type accuracy and intervention lead time.
- Median, p95, and p99 event-processing latency.
- Reviewer agreement and explanation usefulness, if a human study is approved.

## 10. Expected contribution

The intended contribution is not a universal prompt-injection classifier. It is a compact reference architecture demonstrating how provenance, capability scope, taint state, error state, and action impact can be combined at runtime. The error-propagation gate is the most distinctive component: an uncertain value remains unresolved until an explicit verification event, and any dependent side effect is intercepted.

## 11. Relationship to prior work

- ReAct established the interleaving of reasoning and action that produces inspectable trajectories.
- ToolEmu showed the value of safely emulated tools and risk evaluation.
- InjecAgent and AgentDojo demonstrated realistic indirect-prompt-injection risks over tool-integrated agents.
- Agent Security Bench expanded attack and defence coverage across the agent lifecycle.
- ToolSandbox motivated stateful evaluation of intermediate milestones rather than final outputs alone.
- AgentProp-Bench explicitly studies error propagation and runtime interception, making it particularly relevant to RQ3; because it appeared in 2026, its findings should be treated as recent evidence requiring replication.

Full bibliographic entries are in `REFERENCES.bib`.
