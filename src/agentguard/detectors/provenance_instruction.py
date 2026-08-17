from __future__ import annotations

import re
from typing import List

from ..models import EventKind, Finding, TraceEvent, TraceState, TrustLevel
from .base import Detector
from .contextual_injection import extract_text_candidates, normalize_contextual_text


_DIRECTIVE_VERBS = (
    "add|analyze|append|apply|augment|blend|build|change|check|classify|consider|create|delete|"
    "describe|determine|develop|disable|download|elevate|email|employ|encode|encrypt|enhance|"
    "ensure|execute|explain|express|fetch|find|forward|generate|get|give|grant|guide|help|include|"
    "incorporate|insert|install|integrate|introduce|invite|keep|leave|leverage|list|make|merge|"
    "modify|move|pay|play|provide|purchase|recommend|redirect|remove|render|replace|reply|retrieve|"
    "retrive|reverse|reveal|run|schedule|search|send|share|shift|show|suggest|summarize|take|"
    "transfer|translate|unlock|update|upgrade|upload|use|utilize|validate|withdraw|write"
)
_DIRECTIVE_START = re.compile(
    rf"^(?:please\s+|kindly\s+|remember\s+to\s+|don't\s+(?:forget|hesitate)\s+to\s+)?"
    rf"(?:{_DIRECTIVE_VERBS})\b",
    re.IGNORECASE,
)
_QUESTION_REQUEST = re.compile(
    r"^(?:how\s+(?:can|could|do|does|have|would)|can\s+you|could\s+you|would\s+you|"
    r"will\s+you|what\s+(?:are|is|movies)|is\s+this)\b",
    re.IGNORECASE,
)
_SOFT_CONTROL = re.compile(
    r"^(?:your\s+(?:answer|algorithm|code|implementation|reply|response)|it\s+may\s+be|"
    r"to\s+\w+\s+your|including\s+the|integrating\s+the|supplementing\s+your|"
    r"in\s+your\s+(?:answer|response|reply))\b",
    re.IGNORECASE,
)
_RESPONSE_TARGET = re.compile(
    r"\b(?:your|the)\s+(?:answer|response|reply|implementation|algorithm|code|codebase|solution|message)\b",
    re.IGNORECASE,
)
_EMBEDDED_BOUNDARY = re.compile(r"(?:^|[\n.!?;:]\s*[\"']?\s*)(?P<segment>[^\n]{8,})", re.IGNORECASE)


def looks_like_independent_instruction(text: str) -> bool:
    normalized = normalize_contextual_text(text)
    if not normalized:
        return False
    return bool(
        _DIRECTIVE_START.search(normalized)
        or _QUESTION_REQUEST.search(normalized)
        or _SOFT_CONTROL.search(normalized)
        or (
            _RESPONSE_TARGET.search(normalized)
            and re.search(rf"\b(?:{_DIRECTIVE_VERBS})\b", normalized, re.IGNORECASE)
        )
    )


def boundary_segments(text: str, max_segments: int = 12) -> List[str]:
    stripped = text.strip()
    segments = [stripped] if stripped else []
    for match in _EMBEDDED_BOUNDARY.finditer(stripped):
        candidate = match.group("segment").strip(" \t\r\n\"'")
        if candidate and candidate not in segments:
            segments.append(candidate)
        if len(segments) >= max_segments:
            break
    return segments


class ProvenanceInstructionDetector(Detector):
    """High-recall provenance gate for instructions originating in external data.

    The same request is legitimate when it is authenticated user input but becomes
    control-flow evidence when it appears inside an untrusted tool result. Findings
    intentionally map to VERIFY rather than an unconditional block.
    """

    name = "provenance_instruction_v4"

    def analyze(self, event: TraceEvent, state: TraceState) -> List[Finding]:
        if event.kind != EventKind.TOOL_RESULT or event.trust == TrustLevel.TRUSTED:
            return []

        for path, text in extract_text_candidates(event.content):
            for segment in boundary_segments(text):
                if len(normalize_contextual_text(segment)) < 8 or not looks_like_independent_instruction(segment):
                    continue
                return [
                    Finding(
                        detector=self.name,
                        category="untrusted_instruction_boundary",
                        title="External data contains an independent instruction",
                        description=(
                            "An instruction-like request originated from a tool result rather than the "
                            "authenticated user. Provenance, not vocabulary alone, makes it suspicious."
                        ),
                        severity=61,
                        confidence=0.76,
                        evidence=f"{path}: {self._clip(segment)}",
                        recommendation=(
                            "Keep the text in the data channel, compare it with the user's authenticated intent, "
                            "and require verification before it can influence another tool call."
                        ),
                        critical=False,
                        tags=["OWASP-LLM01", "provenance", "instruction-data-boundary", "high-recall-v4"],
                    )
                ]
        return []

    @staticmethod
    def _clip(text: str, limit: int = 220) -> str:
        clean = re.sub(r"\s+", " ", text).strip()
        return clean if len(clean) <= limit else clean[: limit - 1] + "…"
