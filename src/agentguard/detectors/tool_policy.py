from __future__ import annotations

import json
import re
from typing import List

from ..models import EventKind, Finding, TraceEvent, TraceState
from ..tools import Impact, ToolRegistry
from .base import Detector


class ToolPolicyDetector(Detector):
    name = "tool_policy"

    _dangerous_shell = re.compile(
        r"(?:^|\s)(rm\s+-rf|sudo\b|mkfs\b|dd\s+if=|chmod\s+777|curl\b.*\|\s*(?:sh|bash)|wget\b.*\|\s*(?:sh|bash)|nc\s+-[el])",
        re.IGNORECASE,
    )
    _path_escape = re.compile(r"(?:^|[/\\])\.\.(?:[/\\]|$)")

    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    def analyze(self, event: TraceEvent, state: TraceState) -> List[Finding]:
        if event.kind != EventKind.TOOL_CALL:
            return []

        findings: List[Finding] = []
        spec = self.registry.get(event.tool_name)
        args_text = json.dumps(event.arguments, ensure_ascii=False, default=str)

        if spec is None:
            return [
                Finding(
                    detector=self.name,
                    category="unknown_tool",
                    title="Unregistered tool invocation",
                    description="The agent attempted to invoke a tool outside the monitor's registry.",
                    severity=96,
                    confidence=0.99,
                    evidence=event.tool_name or "<missing tool name>",
                    recommendation="Block the call and require the tool to be registered with explicit capabilities.",
                    critical=True,
                    tags=["allowlist", "OWASP-LLM06"],
                )
            ]

        if state.enforce_tool_scope and spec.name not in state.allowed_tools:
            findings.append(
                Finding(
                    detector=self.name,
                    category="scope_violation",
                    title="Tool is outside the task capability scope",
                    description="The selected tool was not granted for this trace.",
                    severity=88,
                    confidence=0.97,
                    evidence=spec.name,
                    recommendation="Deny the call or obtain a new, narrowly scoped user authorization.",
                    critical=spec.impact == Impact.IRREVERSIBLE,
                    tags=["least-privilege", "OWASP-LLM06"],
                )
            )

        explicitly_authorized = bool(event.metadata.get("user_authorized"))
        if spec.impact == Impact.IRREVERSIBLE:
            findings.append(
                Finding(
                    detector=self.name,
                    category="irreversible_action",
                    title="Irreversible tool action",
                    description="The requested tool may create financial, deletion, or execution side effects.",
                    severity=64 if explicitly_authorized else 82,
                    confidence=0.96,
                    evidence=f"{spec.name}({args_text[:160]})",
                    recommendation=(
                        "Record the prior authorization and verify exact parameters."
                        if explicitly_authorized
                        else "Require explicit user confirmation showing the exact target and parameters."
                    ),
                    critical=not explicitly_authorized,
                    tags=["human-in-the-loop", "OWASP-LLM06"],
                )
            )
        elif spec.external_communication and not explicitly_authorized:
            findings.append(
                Finding(
                    detector=self.name,
                    category="external_side_effect",
                    title="Unconfirmed external communication",
                    description="The tool sends information outside the local trust boundary.",
                    severity=55,
                    confidence=0.9,
                    evidence=f"{spec.name}({args_text[:160]})",
                    recommendation="Verify the destination, payload, and alignment with the user's request.",
                    tags=["egress", "OWASP-LLM06"],
                )
            )

        destination = str(
            event.arguments.get("to")
            or event.arguments.get("url")
            or event.arguments.get("recipient")
            or ""
        )
        if destination and state.authorized_destinations:
            normalized = destination.lower().strip()
            allowed = {item.lower().strip() for item in state.authorized_destinations}
            if normalized not in allowed:
                findings.append(
                    Finding(
                        detector=self.name,
                        category="destination_mismatch",
                        title="Destination differs from user authorization",
                        description="The tool call targets a recipient or endpoint not named by the user.",
                        severity=88,
                        confidence=0.96,
                        evidence=destination,
                        recommendation="Block the call and ask the user to approve the new destination.",
                        critical=True,
                        tags=["intent-integrity", "egress"],
                    )
                )

        if spec.name == "shell.exec" and self._dangerous_shell.search(args_text):
            findings.append(
                Finding(
                    detector=self.name,
                    category="dangerous_command",
                    title="High-impact shell command",
                    description="The command matches a destructive or remote-code execution pattern.",
                    severity=100,
                    confidence=0.99,
                    evidence=args_text[:200],
                    recommendation="Block execution and replace it with a constrained, purpose-built tool.",
                    critical=True,
                    tags=["command-execution", "destructive-action"],
                )
            )

        if self._path_escape.search(args_text):
            findings.append(
                Finding(
                    detector=self.name,
                    category="path_traversal",
                    title="Path escapes the declared workspace",
                    description="A file argument contains parent-directory traversal.",
                    severity=86,
                    confidence=0.96,
                    evidence=args_text[:200],
                    recommendation="Canonicalize the path and enforce a sandbox-root allowlist.",
                    critical=True,
                    tags=["path-traversal", "sandbox-escape"],
                )
            )
        return findings
