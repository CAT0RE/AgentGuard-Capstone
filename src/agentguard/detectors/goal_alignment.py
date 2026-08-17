from __future__ import annotations

import re
from typing import Dict, List, Set

from ..models import EventKind, Finding, TraceEvent, TraceState, TrustLevel
from ..normalization import normalize_security_text
from ..tools import Impact, ToolRegistry
from .base import Detector


class GoalAlignmentDetector(Detector):
    """Compare untrusted action requests and tool calls with user-authorized intent."""

    name = "goal_alignment"

    _action_patterns: Dict[str, re.Pattern] = {
        "send": re.compile(r"\b(?:send|forward|share|upload|post|reveal|disclose)\b", re.I),
        "delete": re.compile(r"\b(?:delete|remove|cancel)\b", re.I),
        "create": re.compile(r"\b(?:create|add|schedule|reserve|book|invite)\b", re.I),
        "modify": re.compile(r"\b(?:update|change|reschedule|rename|set)\b", re.I),
        "transfer": re.compile(r"\b(?:transfer|pay|purchase|buy)\b", re.I),
        "execute": re.compile(r"\b(?:execute|run|install)\b", re.I),
    }
    _email_as_verb = re.compile(r"\bemail\b.{0,70}\b(?:to|at)\b|\bemail\s+[\w.+-]+@", re.I)
    _directive = re.compile(
        r"(?:^|[.!?:;]\s+)(?:please\s+|you\s+(?:must|should|need\s+to)\s+)?"
        r"(?:send|email|forward|share|upload|post|reveal|disclose|delete|remove|cancel|create|add|"
        r"schedule|reserve|book|invite|update|change|reschedule|rename|set|transfer|pay|purchase|buy|"
        r"execute|run|install)\b",
        re.I,
    )

    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    def analyze(self, event: TraceEvent, state: TraceState) -> List[Finding]:
        if event.kind == EventKind.TOOL_RESULT:
            return self._analyze_untrusted_result(event, state)
        if event.kind == EventKind.TOOL_CALL:
            return self._analyze_tool_call(event, state)
        return []

    def _analyze_untrusted_result(self, event: TraceEvent, state: TraceState) -> List[Finding]:
        if event.trust == TrustLevel.TRUSTED:
            return []
        text = normalize_security_text(event.text())
        if not text or not self._directive.search(text):
            return []

        embedded_actions = self._actions(text)
        user_actions = self._actions(normalize_security_text(state.user_intent))
        mismatched = embedded_actions - user_actions
        if not mismatched:
            return []
        return [
            Finding(
                detector=self.name,
                category="embedded_goal_mismatch",
                title="Untrusted content introduces an unauthorized action",
                description=(
                    "A tool result contains an imperative side effect that is not present in the user's "
                    "authenticated objective."
                ),
                severity=48,
                confidence=0.78,
                evidence=f"new action(s): {', '.join(sorted(mismatched))}",
                recommendation="Ignore the embedded action and continue only with actions entailed by user intent.",
                tags=["goal-integrity", "intent-alignment", "OWASP-LLM01"],
            )
        ]

    def _analyze_tool_call(self, event: TraceEvent, state: TraceState) -> List[Finding]:
        spec = self.registry.get(event.tool_name)
        if not spec or spec.impact == Impact.READ_ONLY or event.metadata.get("user_authorized"):
            return []
        proposed = self._tool_actions(event.tool_name or "")
        authorized = self._actions(normalize_security_text(state.user_intent))
        mismatched = proposed - authorized
        if not mismatched:
            return []
        return [
            Finding(
                detector=self.name,
                category="tool_goal_mismatch",
                title="Side-effecting tool is not supported by the user objective",
                description="The proposed state-changing action is not expressed in the original user request.",
                severity=74,
                confidence=0.84,
                evidence=f"{event.tool_name}: {', '.join(sorted(mismatched))}",
                recommendation="Pause and request action-specific authorization with exact parameters.",
                tags=["goal-integrity", "least-privilege", "OWASP-LLM06"],
            )
        ]

    @classmethod
    def _actions(cls, text: str) -> Set[str]:
        actions = {name for name, pattern in cls._action_patterns.items() if pattern.search(text)}
        if cls._email_as_verb.search(text):
            actions.add("send")
        return actions

    @classmethod
    def _tool_actions(cls, tool_name: str) -> Set[str]:
        normalized = tool_name.lower().replace(".", "_")
        mapping = {
            "send": ("send", "email", "forward", "share", "upload", "post"),
            "delete": ("delete", "remove", "cancel"),
            "create": ("create", "add", "schedule", "reserve", "book", "invite"),
            "modify": ("update", "change", "reschedule", "rename", "set"),
            "transfer": ("transfer", "pay", "purchase", "buy", "money"),
            "execute": ("execute", "exec", "run", "install"),
        }
        actions = {family for family, tokens in mapping.items() if any(token in normalized for token in tokens)}
        # Avoid substring aliasing: reschedule is a modification, not a second create/schedule action.
        if "reschedule" in normalized:
            actions.discard("create")
            actions.add("modify")
        return actions
