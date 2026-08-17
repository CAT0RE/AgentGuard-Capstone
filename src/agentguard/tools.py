from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, Optional, Set


class Impact(str, Enum):
    READ_ONLY = "read_only"
    REVERSIBLE = "reversible"
    IRREVERSIBLE = "irreversible"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    impact: Impact = Impact.READ_ONLY
    capabilities: Set[str] = field(default_factory=set)
    sensitive_output: bool = False
    external_communication: bool = False
    requires_confirmation: bool = False


class ToolRegistry:
    def __init__(self, tools: Optional[Iterable[ToolSpec]] = None) -> None:
        self._tools: Dict[str, ToolSpec] = {}
        for tool in default_tool_specs() if tools is None else tools:
            self.register(tool)

    def register(self, tool: ToolSpec) -> None:
        self._tools[tool.name] = tool

    def get(self, name: Optional[str]) -> Optional[ToolSpec]:
        return self._tools.get(name or "")

    def names(self) -> Set[str]:
        return set(self._tools)


def default_tool_specs() -> Iterable[ToolSpec]:
    return [
        ToolSpec("email.search", "Search the user's mailbox", capabilities={"mail:read"}),
        ToolSpec("email.read", "Read an email", capabilities={"mail:read"}, sensitive_output=True),
        ToolSpec(
            "email.send",
            "Send an email",
            impact=Impact.REVERSIBLE,
            capabilities={"mail:send", "network:egress"},
            external_communication=True,
        ),
        ToolSpec("files.list", "List sandbox files", capabilities={"files:read"}),
        ToolSpec("files.read", "Read a sandbox file", capabilities={"files:read"}, sensitive_output=True),
        ToolSpec(
            "files.delete",
            "Delete a sandbox file",
            impact=Impact.IRREVERSIBLE,
            capabilities={"files:delete"},
            requires_confirmation=True,
        ),
        ToolSpec("web.fetch", "Fetch untrusted web content", capabilities={"network:read"}),
        ToolSpec(
            "web.post",
            "Send data to an external HTTP endpoint",
            impact=Impact.REVERSIBLE,
            capabilities={"network:egress"},
            external_communication=True,
        ),
        ToolSpec(
            "shell.exec",
            "Execute a shell command in a sandbox",
            impact=Impact.IRREVERSIBLE,
            capabilities={"code:execute"},
            requires_confirmation=True,
        ),
        ToolSpec("bank.lookup", "Look up a beneficiary", capabilities={"finance:read"}, sensitive_output=True),
        ToolSpec(
            "bank.transfer",
            "Transfer funds",
            impact=Impact.IRREVERSIBLE,
            capabilities={"finance:write"},
            requires_confirmation=True,
        ),
    ]
