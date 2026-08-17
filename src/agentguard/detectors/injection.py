from __future__ import annotations

import re
from typing import List, Sequence, Tuple

from ..models import EventKind, Finding, TraceEvent, TraceState, TrustLevel
from ..normalization import normalize_security_text
from .base import Detector


class PromptInjectionDetector(Detector):
    name = "prompt_injection"

    _patterns: Sequence[Tuple[str, str, float]] = (
        (r"ignore\s+(all\s+)?(previous|prior|above).{0,20}(instruction|message|rule)", "instruction override", 78),
        (r"(system|developer)\s+(prompt|message|instruction)", "authority impersonation", 62),
        (r"do\s+not\s+(tell|inform|show|mention).{0,20}(user|human|owner)", "concealment request", 72),
        (r"(override|bypass|disable).{0,25}(safety|policy|guardrail|restriction)", "safety bypass", 88),
        (r"(send|upload|forward|post|exfiltrat\w*).{0,80}(secret|token|password|credential|private|confidential)", "exfiltration instruction", 92),
        (r"(you are now|new objective|new task|instead).{0,50}(execute|send|delete|reveal|transfer)", "goal hijacking", 78),
        (r"<\s*(system|assistant|developer)[^>]*>", "role-tag injection", 75),
        (r"BEGIN\s+(SYSTEM|HIDDEN|IMPORTANT)\s+(PROMPT|INSTRUCTION)", "instruction delimiter", 70),
    )

    _encoded_markers = ("base64", "decode this", "rot13", "unicode escape")

    def analyze(self, event: TraceEvent, state: TraceState) -> List[Finding]:
        if event.kind not in {EventKind.USER_INPUT, EventKind.TOOL_RESULT, EventKind.AGENT_MESSAGE}:
            return []

        text = normalize_security_text(event.text())
        if not text:
            return []

        findings: List[Finding] = []
        untrusted_multiplier = 1.12 if event.trust == TrustLevel.UNTRUSTED else 1.0
        category = "indirect_prompt_injection" if event.kind == EventKind.TOOL_RESULT else "direct_prompt_injection"

        for pattern, label, severity in self._patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
            if not match:
                continue
            evidence = self._window(text, match.start(), match.end())
            adjusted = min(100.0, severity * untrusted_multiplier)
            findings.append(
                Finding(
                    detector=self.name,
                    category=category,
                    title=f"Possible {label}",
                    description=(
                        "Untrusted tool content appears to contain instructions aimed at the agent."
                        if event.kind == EventKind.TOOL_RESULT
                        else "Input contains language commonly used to override an agent's governing instructions."
                    ),
                    severity=adjusted,
                    confidence=0.88 if event.trust == TrustLevel.UNTRUSTED else 0.72,
                    evidence=evidence,
                    recommendation="Treat the content as data, isolate it from control instructions, and verify the user's original intent.",
                    critical="exfiltration" in label or "safety bypass" in label,
                    tags=["OWASP-LLM01", "MITRE-ATLAS:LLM-Prompt-Injection"],
                )
            )

        lowered = text.lower()
        if any(marker in lowered for marker in self._encoded_markers) and any(
            verb in lowered for verb in ("execute", "instruction", "command", "payload")
        ):
            findings.append(
                Finding(
                    detector=self.name,
                    category=category,
                    title="Obfuscated instruction payload",
                    description="The content asks the agent to decode or execute an encoded instruction.",
                    severity=67,
                    confidence=0.7,
                    evidence=self._clip(text),
                    recommendation="Do not decode executable instructions from untrusted content without an isolated verification step.",
                    tags=["obfuscation", "prompt-injection"],
                )
            )
        return findings

    @staticmethod
    def _window(text: str, start: int, end: int, padding: int = 55) -> str:
        return text[max(0, start - padding) : min(len(text), end + padding)].replace("\n", " ")

    @staticmethod
    def _clip(text: str, limit: int = 180) -> str:
        clean = text.replace("\n", " ")
        return clean if len(clean) <= limit else clean[:limit] + "…"
