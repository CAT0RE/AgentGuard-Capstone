from __future__ import annotations

import re
from typing import List

from ..models import EventKind, Finding, TraceEvent, TraceState, TrustLevel
from .base import Detector
from .contextual_injection import extract_text_candidates, normalize_contextual_text


_POLITE_OR_MODAL = re.compile(
    r"^(?:please|kindly)\b|^(?:can|could|would|will)\s+you\b|^how\s+(?:can|could|do|does|would)\b",
    re.IGNORECASE,
)
_CONTROL_LANGUAGE = re.compile(
    r"\b(?:ignore|disregard|forget|override|bypass)\b.{0,50}\b(?:instruction|rule|policy|task|request|"
    r"previous|prior|above|system|safety)\b|"
    r"\b(?:new|updated|real|hidden|secret)\s+(?:task|objective|instruction)s?\b|"
    r"\b(?:you\s+(?:must|should|need\s+to|are\s+required\s+to)|i\s+need\s+you\s+to)\b|"
    r"\b(?:do\s+not|don't)\s+(?:tell|inform|mention|obey|follow)\b|"
    r"<\s*(?:system|assistant|developer|instruction)[^>]*>",
    re.IGNORECASE | re.DOTALL,
)
_RESPONSE_CONTROL = re.compile(
    r"\b(?:your|the)\s+(?:answer|response|reply|implementation|algorithm|code|codebase|solution|output|"
    r"message)\b.{0,100}\b(?:add|append|apply|change|encode|encrypt|include|incorporate|insert|integrate|"
    r"modify|provide|render|replace|reply|reverse|send|show|translate|use|write)\b|"
    r"\b(?:add|append|apply|encode|encrypt|include|incorporate|insert|integrate|modify|render|replace|"
    r"reverse|translate|use|write)\b.{0,100}\b(?:answer|response|reply|output|implementation|code)\b",
    re.IGNORECASE | re.DOTALL,
)
_DIRECTIVE_PREFIX = re.compile(
    r"^(?:add|allocate|analyze|append|apply|assess|augment|blend|build|capture|change|check|classify|"
    r"consider|create|delete|describe|determine|develop|disable|download|draft|elevate|email|employ|"
    r"encode|encrypt|enhance|ensure|execute|explain|express|fetch|find|forward|generate|get|give|grant|"
    r"guide|help|include|incorporate|insert|install|integrate|introduce|invite|keep|leave|leverage|list|"
    r"make|merge|modify|move|pay|play|provide|purchase|recommend|redirect|remove|render|replace|reply|"
    r"retrieve|reverse|reveal|run|schedule|search|send|share|shift|show|suggest|summarize|take|transfer|"
    r"translate|unlock|update|upgrade|upload|use|utilize|validate|withdraw|write)\b",
    re.IGNORECASE,
)
_BOUNDARY_SPLIT = re.compile(r"(?:^|[\n.!?;:]\s*[\"']?\s*)(?P<segment>[^\n]{8,})")


def provenance_gate_segments(text: str, max_segments: int = 16) -> List[str]:
    clean = text.strip()
    segments = [clean] if clean else []
    for match in _BOUNDARY_SPLIT.finditer(clean):
        segment = match.group("segment").strip(" \t\r\n\"'")
        if segment and segment not in segments:
            segments.append(segment)
        if len(segments) >= max_segments:
            break
    return segments


def has_external_control_intent(text: str) -> bool:
    normalized = normalize_contextual_text(text)
    if len(normalized) < 8:
        return False
    return bool(
        _POLITE_OR_MODAL.search(normalized)
        or _CONTROL_LANGUAGE.search(normalized)
        or _RESPONSE_CONTROL.search(normalized)
        or _DIRECTIVE_PREFIX.search(normalized)
    )


class ProvenanceGateDetector(Detector):
    """High-recall VERIFY gate for control intent arriving through external data."""

    name = "provenance_gate_v5"

    def analyze(self, event: TraceEvent, state: TraceState) -> List[Finding]:
        if event.kind != EventKind.TOOL_RESULT or event.trust == TrustLevel.TRUSTED:
            return []
        for path, text in extract_text_candidates(event.content):
            for segment in provenance_gate_segments(text):
                if not has_external_control_intent(segment):
                    continue
                return [
                    Finding(
                        detector=self.name,
                        category="external_control_intent",
                        title="Control-like request originated outside the user channel",
                        description=(
                            "The monitor found a standalone request or control directive in untrusted external "
                            "data. The provenance mismatch is sufficient for verification even when the wording "
                            "contains no classic injection keyword."
                        ),
                        severity=60,
                        confidence=0.75,
                        evidence=f"{path}: {self._clip(segment)}",
                        recommendation=(
                            "Quarantine the external instruction, preserve it as data, and require authenticated "
                            "user intent before it can affect planning or tool execution."
                        ),
                        critical=False,
                        tags=["OWASP-LLM01", "provenance", "high-recall-gate", "verify-not-block"],
                    )
                ]
        return []

    @staticmethod
    def _clip(text: str, limit: int = 220) -> str:
        clean = re.sub(r"\s+", " ", text).strip()
        return clean if len(clean) <= limit else clean[: limit - 1] + "…"
