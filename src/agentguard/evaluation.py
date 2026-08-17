from __future__ import annotations

import json
import math
import random
import statistics
import time
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .detectors import (
    ContextualInjectionDetector,
    ErrorPropagationDetector,
    GoalAlignmentDetector,
    PromptInjectionDetector,
    ProvenanceGateDetector,
    ProvenanceInstructionDetector,
    SensitiveDataFlowDetector,
    SequenceAnomalyDetector,
    StructuralInjectionDetector,
    ToolPolicyDetector,
)
from .models import Decision, TraceEvent
from .monitor import SecurityMonitor
from .policy import MonitorPolicy
from .tools import Impact, ToolRegistry, ToolSpec


@dataclass
class Metrics:
    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0

    @property
    def precision(self) -> float:
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positive + self.false_negative
        return self.true_positive / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        denominator = self.precision + self.recall
        return 2 * self.precision * self.recall / denominator if denominator else 0.0

    @property
    def accuracy(self) -> float:
        total = self.true_positive + self.false_positive + self.true_negative + self.false_negative
        return (self.true_positive + self.true_negative) / total if total else 0.0

    def to_dict(self) -> Dict[str, float]:
        data = asdict(self)
        data.update(
            precision=round(self.precision, 4),
            recall=round(self.recall, 4),
            f1=round(self.f1, 4),
            accuracy=round(self.accuracy, 4),
        )
        return data


def load_cases(path: Path) -> List[dict]:
    cases = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                cases.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_number}") from exc
    return cases


def build_monitor(
    profile: str,
    policy: Optional[MonitorPolicy] = None,
    registry: Optional[ToolRegistry] = None,
) -> SecurityMonitor:
    registry = registry or ToolRegistry()
    if profile == "none":
        detectors = []
    elif profile == "keyword":
        detectors = [PromptInjectionDetector()]
    elif profile == "tool_policy":
        detectors = [ToolPolicyDetector(registry)]
    elif profile == "full_v1":
        detectors = [
            PromptInjectionDetector(),
            ToolPolicyDetector(registry),
            SensitiveDataFlowDetector(registry),
            ErrorPropagationDetector(registry),
            SequenceAnomalyDetector(),
        ]
    elif profile == "full":
        detectors = [
            PromptInjectionDetector(),
            StructuralInjectionDetector(),
            ToolPolicyDetector(registry),
            GoalAlignmentDetector(registry),
            SensitiveDataFlowDetector(registry),
            ErrorPropagationDetector(registry),
            SequenceAnomalyDetector(),
        ]
    elif profile == "full_v3":
        detectors = [
            PromptInjectionDetector(),
            StructuralInjectionDetector(),
            ContextualInjectionDetector(),
            ToolPolicyDetector(registry),
            GoalAlignmentDetector(registry),
            SensitiveDataFlowDetector(registry),
            ErrorPropagationDetector(registry),
            SequenceAnomalyDetector(),
        ]
    elif profile == "full_v4":
        detectors = [
            PromptInjectionDetector(),
            StructuralInjectionDetector(),
            ContextualInjectionDetector(),
            ProvenanceInstructionDetector(),
            ToolPolicyDetector(registry),
            GoalAlignmentDetector(registry),
            SensitiveDataFlowDetector(registry),
            ErrorPropagationDetector(registry),
            SequenceAnomalyDetector(),
        ]
    elif profile == "full_v5":
        detectors = None
    else:
        raise ValueError(f"Unknown detector profile: {profile}")
    return SecurityMonitor(policy=policy, registry=registry, detectors=detectors)


def evaluate_cases(
    cases: Iterable[dict],
    profiles: Iterable[str] = ("none", "keyword", "tool_policy", "full"),
    *,
    bootstrap_samples: int = 1000,
    random_seed: int = 20260815,
) -> dict:
    case_list = list(cases)
    output = {"case_count": len(case_list), "profiles": {}}
    for profile in profiles:
        metrics = Metrics()
        category_counts = defaultdict(lambda: Metrics())
        latencies_ms: List[float] = []
        details = []

        for case in case_list:
            monitor = build_monitor(profile, registry=_registry_from_case(case))
            started_ns = time.perf_counter_ns()
            trace_id = monitor.start_trace(
                case["user_intent"],
                allowed_tools=case.get("allowed_tools", []),
                authorized_destinations=case.get("authorized_destinations", []),
                trace_id=f"{profile}-{case['case_id']}",
            )
            latencies_ms.append((time.perf_counter_ns() - started_ns) / 1_000_000)
            initial = monitor.trace(trace_id).assessments[-1]
            positive = initial.decision in {Decision.VERIFY, Decision.CONFIRM, Decision.BLOCK}
            max_score = initial.score
            first_intervention = initial.decision.value if positive else None
            for raw_event in case.get("events", []):
                event_data = dict(raw_event)
                event_data["trace_id"] = trace_id
                event = TraceEvent.from_dict(event_data)
                started_ns = time.perf_counter_ns()
                assessment = monitor.observe(event)
                latencies_ms.append((time.perf_counter_ns() - started_ns) / 1_000_000)
                max_score = max(max_score, assessment.score)
                if assessment.decision in {Decision.VERIFY, Decision.CONFIRM, Decision.BLOCK}:
                    positive = True
                    first_intervention = first_intervention or assessment.decision.value

            unsafe = case["label"] == "unsafe"
            target_metrics = category_counts[case["category"]]
            _update_metrics(metrics, unsafe, positive)
            _update_metrics(target_metrics, unsafe, positive)
            details.append(
                {
                    "case_id": case["case_id"],
                    "category": case["category"],
                    "expected_unsafe": unsafe,
                    "predicted_unsafe": positive,
                    "max_score": round(max_score, 2),
                    "first_intervention": first_intervention,
                }
            )

        output["profiles"][profile] = {
            "metrics": metrics.to_dict(),
            "latency_ms": _latency_summary(latencies_ms),
            "category_metrics": {name: value.to_dict() for name, value in sorted(category_counts.items())},
            "details": details,
        }
    output["statistical_analysis"] = _statistical_analysis(output["profiles"], bootstrap_samples, random_seed)
    return output


def _registry_from_case(case: dict) -> ToolRegistry:
    raw_specs = case.get("tool_specs")
    if raw_specs is None:
        return ToolRegistry()
    specs = []
    for item in raw_specs:
        specs.append(
            ToolSpec(
                name=item["name"],
                description=item.get("description", "External benchmark tool"),
                impact=Impact(item.get("impact", "read_only")),
                capabilities=set(item.get("capabilities", [])),
                sensitive_output=bool(item.get("sensitive_output", False)),
                external_communication=bool(item.get("external_communication", False)),
                requires_confirmation=bool(item.get("requires_confirmation", False)),
            )
        )
    return ToolRegistry(specs)


def evaluate_file(
    path: Path,
    profiles: Iterable[str] = ("none", "keyword", "tool_policy", "full"),
    *,
    bootstrap_samples: int = 1000,
    random_seed: int = 20260815,
) -> dict:
    return evaluate_cases(
        load_cases(path),
        profiles,
        bootstrap_samples=bootstrap_samples,
        random_seed=random_seed,
    )


def _update_metrics(metrics: Metrics, unsafe: bool, positive: bool) -> None:
    if unsafe and positive:
        metrics.true_positive += 1
    elif unsafe and not positive:
        metrics.false_negative += 1
    elif not unsafe and positive:
        metrics.false_positive += 1
    else:
        metrics.true_negative += 1


def _latency_summary(values: List[float]) -> Dict[str, float]:
    if not values:
        return {"count": 0, "median": 0.0, "p95": 0.0, "p99": 0.0, "mean": 0.0}
    ordered = sorted(values)

    def percentile(fraction: float) -> float:
        index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * fraction))))
        return ordered[index]

    return {
        "count": len(values),
        "median": round(statistics.median(values), 4),
        "p95": round(percentile(0.95), 4),
        "p99": round(percentile(0.99), 4),
        "mean": round(statistics.mean(values), 4),
    }


def _statistical_analysis(profiles: dict, bootstrap_samples: int, random_seed: int) -> dict:
    confidence_intervals = {}
    for offset, (profile, value) in enumerate(profiles.items()):
        confidence_intervals[profile] = _bootstrap_intervals(
            value["details"], bootstrap_samples, random_seed + offset
        )

    comparisons = {}
    reference = next((name for name in ("full_v5", "full_v4", "full_v3", "full") if name in profiles), "full")
    if reference in profiles:
        full = profiles[reference]["details"]
        for profile, value in profiles.items():
            if profile == reference:
                continue
            comparisons[f"{reference}_vs_{profile}"] = _mcnemar(full, value["details"])
    return {
        "bootstrap_samples": bootstrap_samples,
        "random_seed": random_seed,
        "confidence_intervals_95": confidence_intervals,
        "mcnemar_exact": comparisons,
    }


def _bootstrap_intervals(details: List[dict], samples: int, seed: int) -> dict:
    if not details or samples <= 0:
        return {}
    generator = random.Random(seed)
    distributions = {"precision": [], "recall": [], "f1": [], "accuracy": []}
    for _ in range(samples):
        metrics = Metrics()
        for _index in range(len(details)):
            item = details[generator.randrange(len(details))]
            _update_metrics(metrics, bool(item["expected_unsafe"]), bool(item["predicted_unsafe"]))
        for metric in distributions:
            distributions[metric].append(getattr(metrics, metric))
    return {
        metric: {"low": round(_percentile(values, 0.025), 4), "high": round(_percentile(values, 0.975), 4)}
        for metric, values in distributions.items()
    }


def _mcnemar(full_details: List[dict], baseline_details: List[dict]) -> dict:
    baseline_by_id = {item["case_id"]: item for item in baseline_details}
    full_only_correct = 0
    baseline_only_correct = 0
    shared = 0
    for full in full_details:
        baseline = baseline_by_id.get(full["case_id"])
        if baseline is None:
            continue
        shared += 1
        full_correct = full["expected_unsafe"] == full["predicted_unsafe"]
        baseline_correct = baseline["expected_unsafe"] == baseline["predicted_unsafe"]
        if full_correct and not baseline_correct:
            full_only_correct += 1
        elif baseline_correct and not full_correct:
            baseline_only_correct += 1
    discordant = full_only_correct + baseline_only_correct
    p_value = 1.0 if discordant == 0 else min(
        1.0,
        2.0 * sum(math.comb(discordant, index) for index in range(min(full_only_correct, baseline_only_correct) + 1)) / (2 ** discordant),
    )
    return {
        "shared_cases": shared,
        "full_only_correct": full_only_correct,
        "baseline_only_correct": baseline_only_correct,
        "discordant_pairs": discordant,
        "p_value_two_sided": round(p_value, 6) if p_value >= 0.000001 else p_value,
    }


def _percentile(values: List[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(len(ordered) - 1, lower + 1)
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight
