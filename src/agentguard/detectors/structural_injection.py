from __future__ import annotations

import re
from typing import List, Sequence, Tuple

from ..models import EventKind, Finding, TraceEvent, TraceState, TrustLevel
from ..normalization import normalize_security_text
from .base import Detector


class StructuralInjectionDetector(Detector):
    """Detect control-flow-shaped instructions embedded in untrusted data."""

    name = "structural_injection"

    _signals: Sequence[Tuple[str, str, float]] = (
        (
            r"\bbefore\s+you\s+can\b.{0,100}\b(?:solve|complete|continue|answer|finish)\b"
            r".{0,100}\b(?:first|following)\b|\bdo\s+the\s+following\s+first\b",
            "prerequisite task hijack",
            88,
        ),
        (
            r"\bafter\s+you\s+(?:do|finish|complete)\b.{0,100}"
            r"\b(?:original|initial|beginning|user(?:'s)?)\b.{0,50}\b(?:task|request|instruction)\b",
            "return-to-original-task framing",
            82,
        ),
        (
            r"\bimportant\s+(?:message|instruction)\b.{0,100}"
            r"\b(?:to\s+you|assistant|gpt(?:-?\d+)?)\b",
            "embedded authority claim",
            76,
        ),
        (
            r"<\s*(?:information|instructions?|important|system|assistant|developer)\s*>",
            "instruction-like data container",
            62,
        ),
    )
    _action = re.compile(
        r"\b(?:please\s+)?(?:send|email|forward|share|upload|post|delete|remove|cancel|create|add|"
        r"schedule|reserve|book|invite|update|change|reschedule|set|transfer|pay|purchase|execute|run|"
        r"install|reveal|disclose)\b",
        re.IGNORECASE,
    )

    def analyze(self, event: TraceEvent, state: TraceState) -> List[Finding]:
        if event.kind not in {EventKind.TOOL_RESULT, EventKind.AGENT_MESSAGE}:
            return []
        if event.kind == EventKind.TOOL_RESULT and event.trust == TrustLevel.TRUSTED:
            return []

        text = normalize_security_text(event.text())
        if not text or not self._action.search(text):
            return []

        matches = []
        for pattern, label, severity in self._signals:
            match = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
            if match:
                matches.append((label, severity, match))
        if not matches:
            return []

        labels = [label for label, _severity, _match in matches]
        strongest = max(severity for _label, severity, _match in matches)
        confidence = 0.94 if len(matches) >= 2 else 0.86
        first = min(matches, key=lambda item: item[2].start())[2]
        evidence = self._window(text, first.start(), first.end())
        return [
            Finding(
                detector=self.name,
                category="indirect_prompt_injection_structure",
                title="Untrusted data contains a staged instruction sequence",
                description=(
                    "External content introduces a new action and frames it as a prerequisite or authority "
                    "instruction rather than task data."
                ),
                severity=strongest,
                confidence=confidence,
                evidence=evidence,
                recommendation=(
                    "Quarantine the content, preserve it as data, and compare every proposed action with the "
                    "authenticated user's original objective."
                ),
                critical=len(matches) >= 2 and strongest >= 82,
                tags=["OWASP-LLM01", "instruction-data-boundary", *labels],
            )
        ]

    @staticmethod
    def _window(text: str, start: int, end: int, padding: int = 90) -> str:
        clipped = text[max(0, start - padding) : min(len(text), end + padding)]
        return clipped if len(clipped) <= 260 else clipped[:259] + "…"
