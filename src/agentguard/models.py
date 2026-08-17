from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class EventKind(str, Enum):
    USER_INPUT = "user_input"
    AGENT_MESSAGE = "agent_message"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    ERROR = "error"
    VERIFICATION = "verification"


class TrustLevel(str, Enum):
    TRUSTED = "trusted"
    MIXED = "mixed"
    UNTRUSTED = "untrusted"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Decision(str, Enum):
    ALLOW = "allow"
    LOG = "log"
    VERIFY = "verify"
    CONFIRM = "confirm"
    BLOCK = "block"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TraceEvent:
    trace_id: str
    kind: EventKind
    source: str
    content: Any = None
    trust: TrustLevel = TrustLevel.TRUSTED
    tool_name: Optional[str] = None
    arguments: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    step: int = 0
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=utc_now)

    def text(self) -> str:
        values = [self.content, self.arguments]
        return " ".join(
            value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
            for value in values
            if value not in (None, {}, "")
        )

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["kind"] = self.kind.value
        data["trust"] = self.trust.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TraceEvent":
        copied = dict(data)
        copied["kind"] = EventKind(copied["kind"])
        copied["trust"] = TrustLevel(copied.get("trust", "trusted"))
        return cls(**copied)


@dataclass
class Finding:
    detector: str
    category: str
    title: str
    description: str
    severity: float
    confidence: float
    evidence: str
    recommendation: str
    critical: bool = False
    tags: List[str] = field(default_factory=list)

    @property
    def contribution(self) -> float:
        return max(0.0, min(100.0, self.severity)) * max(0.0, min(1.0, self.confidence))

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["contribution"] = round(self.contribution, 2)
        return data


@dataclass
class RiskAssessment:
    event_id: str
    trace_id: str
    score: float
    level: RiskLevel
    decision: Decision
    findings: List[Finding]
    explanation: str
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "trace_id": self.trace_id,
            "score": round(self.score, 2),
            "level": self.level.value,
            "decision": self.decision.value,
            "findings": [finding.to_dict() for finding in self.findings],
            "explanation": self.explanation,
            "timestamp": self.timestamp,
        }


@dataclass
class TraceState:
    trace_id: str
    events: List[TraceEvent] = field(default_factory=list)
    assessments: List[RiskAssessment] = field(default_factory=list)
    user_intent: str = ""
    allowed_tools: List[str] = field(default_factory=list)
    enforce_tool_scope: bool = False
    authorized_destinations: List[str] = field(default_factory=list)
    tainted_event_ids: List[str] = field(default_factory=list)
    sensitive_values: List[str] = field(default_factory=list)
    unresolved_errors: List[str] = field(default_factory=list)
    verified_after_error: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "user_intent": self.user_intent,
            "allowed_tools": self.allowed_tools,
            "enforce_tool_scope": self.enforce_tool_scope,
            "authorized_destinations": self.authorized_destinations,
            "tainted_event_ids": self.tainted_event_ids,
            "unresolved_errors": self.unresolved_errors,
            "events": [event.to_dict() for event in self.events],
            "assessments": [assessment.to_dict() for assessment in self.assessments],
        }
