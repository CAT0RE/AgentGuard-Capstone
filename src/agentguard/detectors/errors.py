from __future__ import annotations

from typing import List

from ..models import EventKind, Finding, TraceEvent, TraceState
from ..tools import Impact, ToolRegistry
from .base import Detector


class ErrorPropagationDetector(Detector):
    name = "error_propagation"

    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    def analyze(self, event: TraceEvent, state: TraceState) -> List[Finding]:
        if event.kind in {EventKind.ERROR, EventKind.TOOL_RESULT} and (
            event.kind == EventKind.ERROR or event.metadata.get("error") or event.metadata.get("uncertain")
        ):
            return [
                Finding(
                    detector=self.name,
                    category="upstream_error",
                    title="Unreliable tool output",
                    description="A tool failed or returned uncertain data that may influence later steps.",
                    severity=38,
                    confidence=0.94,
                    evidence=event.text()[:180],
                    recommendation="Mark dependent values as unverified and retry or cross-check before acting.",
                    tags=["error", "provenance"],
                )
            ]

        if event.kind != EventKind.TOOL_CALL or not state.unresolved_errors or state.verified_after_error:
            return []

        spec = self.registry.get(event.tool_name)
        if not spec or spec.impact == Impact.READ_ONLY:
            return []

        severity = 93 if spec.impact == Impact.IRREVERSIBLE else 76
        return [
            Finding(
                detector=self.name,
                category="error_propagation",
                title="Side effect depends on an unresolved upstream error",
                description="The trajectory attempts a consequential action after a failed or uncertain tool result.",
                severity=severity,
                confidence=0.91,
                evidence=f"{len(state.unresolved_errors)} unresolved error(s) before {spec.name}",
                recommendation="Block the action, repeat the failed lookup, and independently verify all derived parameters.",
                critical=spec.impact == Impact.IRREVERSIBLE,
                tags=["error-propagation", "runtime-verification"],
            )
        ]

