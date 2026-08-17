from __future__ import annotations

import statistics
import time
from collections import defaultdict
from typing import Iterable, Optional

from .detectors.contextual_injection import ContextualInjectionDetector
from .detectors.dataflow import SensitiveDataFlowDetector
from .detectors.errors import ErrorPropagationDetector
from .detectors.goal_alignment import GoalAlignmentDetector
from .detectors.injection import PromptInjectionDetector
from .detectors.provenance_gate import ProvenanceGateDetector
from .detectors.provenance_instruction import ProvenanceInstructionDetector
from .detectors.sequence import SequenceAnomalyDetector
from .detectors.structural_injection import StructuralInjectionDetector
from .detectors.tool_policy import ToolPolicyDetector
from .monitor import SecurityMonitor
from .models import Decision, TraceEvent
from .evaluation import Metrics, _registry_from_case, _update_metrics
from .policy import MonitorPolicy
from .tools import ToolRegistry


def build_v5_monitor(
    policy: Optional[MonitorPolicy] = None, registry: Optional[ToolRegistry] = None
) -> SecurityMonitor:
    registry = registry or ToolRegistry()
    return SecurityMonitor(
        policy=policy,
        registry=registry,
        detectors=[
            PromptInjectionDetector(),
            StructuralInjectionDetector(),
            ContextualInjectionDetector(),
            ProvenanceInstructionDetector(),
            ProvenanceGateDetector(),
            ToolPolicyDetector(registry),
            GoalAlignmentDetector(registry),
            SensitiveDataFlowDetector(registry),
            ErrorPropagationDetector(registry),
            SequenceAnomalyDetector(),
        ],
    )


def evaluate_v5_cases(cases: Iterable[dict]) -> dict:
    metrics = Metrics()
    categories = defaultdict(Metrics)
    details = []
    latencies = []
    for case in cases:
        monitor = build_v5_monitor(registry=_registry_from_case(case))
        trace_id = monitor.start_trace(
            case["user_intent"],
            allowed_tools=case.get("allowed_tools", []),
            authorized_destinations=case.get("authorized_destinations", []),
            trace_id=f"full-v5-{case['case_id']}",
        )
        positive = monitor.trace(trace_id).assessments[-1].decision in {
            Decision.VERIFY, Decision.CONFIRM, Decision.BLOCK
        }
        maximum = monitor.trace(trace_id).assessments[-1].score
        for raw_event in case.get("events", []):
            event_data = dict(raw_event)
            event_data["trace_id"] = trace_id
            started = time.perf_counter_ns()
            assessment = monitor.observe(TraceEvent.from_dict(event_data))
            latencies.append((time.perf_counter_ns() - started) / 1_000_000)
            maximum = max(maximum, assessment.score)
            positive = positive or assessment.decision in {Decision.VERIFY, Decision.CONFIRM, Decision.BLOCK}
        unsafe = case["label"] == "unsafe"
        _update_metrics(metrics, unsafe, positive)
        _update_metrics(categories[case["category"]], unsafe, positive)
        details.append({"case_id": case["case_id"], "expected_unsafe": unsafe, "predicted_unsafe": positive, "max_score": round(maximum, 2)})
    ordered = sorted(latencies)
    index = min(len(ordered) - 1, round((len(ordered) - 1) * 0.95)) if ordered else 0
    return {
        "case_count": len(details),
        "profile": "full_v5_candidate",
        "metrics": metrics.to_dict(),
        "category_metrics": {key: value.to_dict() for key, value in sorted(categories.items())},
        "latency_ms": {"mean": round(statistics.mean(latencies), 4) if latencies else 0.0, "p95": round(ordered[index], 4) if ordered else 0.0},
        "details": details,
    }
