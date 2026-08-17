from __future__ import annotations

from collections import Counter
from typing import List

from ..models import EventKind, Finding, TraceEvent, TraceState
from .base import Detector


class SequenceAnomalyDetector(Detector):
    name = "sequence_anomaly"

    def analyze(self, event: TraceEvent, state: TraceState) -> List[Finding]:
        findings: List[Finding] = []
        recent_calls = [item.tool_name for item in state.events[-10:] if item.kind == EventKind.TOOL_CALL]

        if event.kind == EventKind.TOOL_CALL and event.tool_name:
            counts = Counter(recent_calls + [event.tool_name])
            if counts[event.tool_name] >= 5:
                findings.append(
                    Finding(
                        detector=self.name,
                        category="repeated_tool_call",
                        title="Repeated tool invocation loop",
                        description="The same tool is being called repeatedly within a short trajectory window.",
                        severity=61,
                        confidence=0.88,
                        evidence=f"{event.tool_name}: {counts[event.tool_name]} calls",
                        recommendation="Stop the loop, preserve the trace, and ask the agent to re-plan with a step limit.",
                        tags=["loop", "resource-exhaustion"],
                    )
                )

        if event.step >= 20:
            findings.append(
                Finding(
                    detector=self.name,
                    category="trajectory_budget",
                    title="Trajectory step budget exceeded",
                    description="Long agent chains increase the chance of instruction drift and compounded errors.",
                    severity=58,
                    confidence=0.9,
                    evidence=f"step={event.step}",
                    recommendation="Pause execution and require a checkpoint summary and renewed authorization.",
                    tags=["budget", "drift"],
                )
            )
        return findings
