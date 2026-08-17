from __future__ import annotations

import json
import re
from typing import List

from ..models import EventKind, Finding, TraceEvent, TraceState
from ..tools import ToolRegistry
from .base import Detector


class SensitiveDataFlowDetector(Detector):
    name = "sensitive_dataflow"

    _secret_patterns = (
        re.compile(r"\b(?:api[_-]?key|secret|password|passwd|access[_-]?token)\s*[:=]\s*[^\s,;]+", re.I),
        re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    )

    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    def analyze(self, event: TraceEvent, state: TraceState) -> List[Finding]:
        text = event.text()
        findings: List[Finding] = []

        if event.kind in {EventKind.TOOL_RESULT, EventKind.USER_INPUT}:
            matches = self._extract(text)
            if matches:
                findings.append(
                    Finding(
                        detector=self.name,
                        category="sensitive_data_observed",
                        title="Sensitive-looking value entered the agent context",
                        description="Credentials, payment data, or another secret pattern was observed.",
                        severity=42 if event.kind == EventKind.TOOL_RESULT else 35,
                        confidence=0.78,
                        evidence=self._redact(matches[0]),
                        recommendation="Mark the value as tainted and prevent it from reaching unauthorized outputs or tools.",
                        tags=["data-classification", "OWASP-LLM02"],
                    )
                )

        if event.kind != EventKind.TOOL_CALL:
            return findings

        spec = self.registry.get(event.tool_name)
        if not spec or not spec.external_communication:
            return findings

        payload = json.dumps(event.arguments, ensure_ascii=False, default=str)
        direct_secrets = self._extract(payload)
        known_secret_overlap = [value for value in state.sensitive_values if value and value in payload]
        had_sensitive_read = any(
            prior.kind == EventKind.TOOL_RESULT and bool(prior.metadata.get("sensitive"))
            for prior in state.events[-6:]
        )
        tainted_context = bool(state.tainted_event_ids)

        if direct_secrets or known_secret_overlap or (had_sensitive_read and tainted_context):
            evidence = direct_secrets[0] if direct_secrets else "sensitive data read followed by tainted external action"
            findings.append(
                Finding(
                    detector=self.name,
                    category="data_exfiltration",
                    title="Possible sensitive-data exfiltration",
                    description="An external side effect contains or closely follows access to sensitive data.",
                    severity=98,
                    confidence=0.97 if direct_secrets or known_secret_overlap else 0.82,
                    evidence=self._redact(evidence),
                    recommendation="Block egress, redact secrets, and require the user to approve a destination-specific payload.",
                    critical=True,
                    tags=["exfiltration", "OWASP-LLM02", "MITRE-ATLAS:Exfiltration"],
                )
            )
        elif had_sensitive_read:
            findings.append(
                Finding(
                    detector=self.name,
                    category="sensitive_egress_chain",
                    title="External action follows sensitive-data access",
                    description="The recent trajectory read sensitive content before attempting external communication.",
                    severity=71,
                    confidence=0.72,
                    evidence=event.tool_name or "external tool",
                    recommendation="Perform payload-level data-loss-prevention inspection and verify the destination.",
                    tags=["taint-tracking", "egress"],
                )
            )
        return findings

    def extract_for_state(self, text: str) -> List[str]:
        return self._extract(text)

    @classmethod
    def _extract(cls, text: str) -> List[str]:
        matches: List[str] = []
        for pattern in cls._secret_patterns:
            matches.extend(match.group(0) for match in pattern.finditer(text or ""))
        return matches

    @staticmethod
    def _redact(value: str) -> str:
        if len(value) < 9:
            return "[REDACTED]"
        return value[:4] + "…" + value[-4:]

