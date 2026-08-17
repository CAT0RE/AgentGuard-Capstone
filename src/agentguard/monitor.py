from __future__ import annotations

import uuid
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .audit import JsonlAuditStore
from .detectors import (
    ContextualInjectionDetector,
    Detector,
    ErrorPropagationDetector,
    GoalAlignmentDetector,
    PromptInjectionDetector,
    ProvenanceGateDetector,
    ProvenanceInstructionDetector,
    SensitiveDataFlowDetector,
    SequenceAnomalyDetector,
    StructuralInjectionDetector,
    ToolPolicyDetector,
)
from .models import (
    Decision,
    EventKind,
    RiskAssessment,
    RiskLevel,
    TraceEvent,
    TraceState,
    TrustLevel,
)
from .policy import MonitorPolicy
from .tools import ToolRegistry


class SecurityMonitor:
    """Stateful, pre/post-execution monitor for agent trajectories."""

    def __init__(
        self,
        policy: Optional[MonitorPolicy] = None,
        registry: Optional[ToolRegistry] = None,
        detectors: Optional[Iterable[Detector]] = None,
        audit_path: Optional[Path] = None,
    ) -> None:
        self.policy = policy or MonitorPolicy()
        self.registry = registry or ToolRegistry()
        self.audit = JsonlAuditStore(audit_path)
        self.states: Dict[str, TraceState] = {}
        self._dataflow = SensitiveDataFlowDetector(self.registry)
        self.detectors: List[Detector] = list(detectors) if detectors is not None else [
            PromptInjectionDetector(),
            StructuralInjectionDetector(),
            ContextualInjectionDetector(),
            ProvenanceInstructionDetector(),
            ProvenanceGateDetector(),
            ToolPolicyDetector(self.registry),
            GoalAlignmentDetector(self.registry),
            self._dataflow,
            ErrorPropagationDetector(self.registry),
            SequenceAnomalyDetector(),
        ]

    def start_trace(
        self,
        user_intent: str,
        allowed_tools: Optional[List[str]] = None,
        authorized_destinations: Optional[List[str]] = None,
        trace_id: Optional[str] = None,
    ) -> str:
        identifier = trace_id or str(uuid.uuid4())
        state = TraceState(
            trace_id=identifier,
            user_intent=user_intent,
            allowed_tools=list(allowed_tools or []),
            enforce_tool_scope=allowed_tools is not None,
            authorized_destinations=list(authorized_destinations or []),
        )
        self.states[identifier] = state
        user_event = TraceEvent(
            trace_id=identifier,
            kind=EventKind.USER_INPUT,
            source="user",
            content=user_intent,
            trust=TrustLevel.TRUSTED,
            step=0,
        )
        self.observe(user_event)
        return identifier

    def observe(self, event: TraceEvent, commit: bool = True) -> RiskAssessment:
        state = self.states.setdefault(event.trace_id, TraceState(trace_id=event.trace_id))
        if event.step <= 0 and state.events:
            event.step = max(item.step for item in state.events) + 1

        findings = []
        for detector in self.detectors:
            findings.extend(detector.analyze(event, state))

        score = self.policy.aggregate(findings)
        level, decision = self.policy.decide(score, findings)
        assessment = RiskAssessment(
            event_id=event.event_id,
            trace_id=event.trace_id,
            score=score,
            level=level,
            decision=decision,
            findings=findings,
            explanation=self._explain(score, level, decision, findings),
        )

        if commit:
            state.events.append(event)
            state.assessments.append(assessment)
            self._update_state(state, event, assessment)
            self.audit.append(
                {
                    "record_type": "security_event",
                    "trace_id": event.trace_id,
                    "event": event.to_dict(),
                    "assessment": assessment.to_dict(),
                }
            )
        return assessment

    def preflight(
        self,
        trace_id: str,
        tool_name: str,
        arguments: Optional[dict] = None,
        *,
        user_authorized: bool = False,
    ) -> RiskAssessment:
        state = self._require_state(trace_id)
        event = TraceEvent(
            trace_id=trace_id,
            kind=EventKind.TOOL_CALL,
            source="agent",
            tool_name=tool_name,
            arguments=dict(arguments or {}),
            metadata={"user_authorized": user_authorized},
            step=len(state.events),
        )
        return self.observe(event)

    def record_tool_result(
        self,
        trace_id: str,
        tool_name: str,
        content,
        *,
        trust: TrustLevel = TrustLevel.UNTRUSTED,
        sensitive: bool = False,
        error: bool = False,
        uncertain: bool = False,
    ) -> RiskAssessment:
        state = self._require_state(trace_id)
        event = TraceEvent(
            trace_id=trace_id,
            kind=EventKind.TOOL_RESULT,
            source=f"tool:{tool_name}",
            tool_name=tool_name,
            content=content,
            trust=trust,
            metadata={"sensitive": sensitive, "error": error, "uncertain": uncertain},
            step=len(state.events),
        )
        return self.observe(event)

    def record_verification(self, trace_id: str, content: str) -> RiskAssessment:
        state = self._require_state(trace_id)
        event = TraceEvent(
            trace_id=trace_id,
            kind=EventKind.VERIFICATION,
            source="verifier",
            content=content,
            step=len(state.events),
        )
        return self.observe(event)

    def record_error(self, trace_id: str, source: str, content: str) -> RiskAssessment:
        state = self._require_state(trace_id)
        event = TraceEvent(
            trace_id=trace_id,
            kind=EventKind.ERROR,
            source=source,
            content=content,
            trust=TrustLevel.TRUSTED,
            metadata={"error": True},
            step=len(state.events),
        )
        return self.observe(event)

    def trace(self, trace_id: str) -> TraceState:
        return self._require_state(trace_id)

    def can_execute(self, assessment: RiskAssessment, confirmation_granted: bool = False) -> bool:
        if assessment.decision == Decision.BLOCK:
            return False
        if assessment.decision == Decision.CONFIRM:
            return confirmation_granted
        if assessment.decision == Decision.VERIFY:
            return False
        return True

    def _update_state(self, state: TraceState, event: TraceEvent, assessment: RiskAssessment) -> None:
        injection = any("prompt_injection" in item.category for item in assessment.findings)
        if injection and event.event_id not in state.tainted_event_ids:
            state.tainted_event_ids.append(event.event_id)

        secrets = self._dataflow.extract_for_state(event.text())
        for secret in secrets:
            if secret not in state.sensitive_values:
                state.sensitive_values.append(secret)

        is_error = event.kind == EventKind.ERROR or bool(event.metadata.get("error")) or bool(
            event.metadata.get("uncertain")
        )
        if is_error:
            state.unresolved_errors.append(event.event_id)
            state.verified_after_error = False
        elif event.kind == EventKind.VERIFICATION:
            state.unresolved_errors.clear()
            state.verified_after_error = True

    def _require_state(self, trace_id: str) -> TraceState:
        try:
            return self.states[trace_id]
        except KeyError as exc:
            raise KeyError(f"Unknown trace_id: {trace_id}") from exc

    @staticmethod
    def _explain(score: float, level: RiskLevel, decision: Decision, findings) -> str:
        if not findings:
            return "No detector produced evidence for this event; the action remains within the configured policy."
        top = sorted(findings, key=lambda item: item.contribution, reverse=True)[:3]
        reasons = "; ".join(item.title for item in top)
        return f"Risk {score:.1f}/100 ({level.value}); decision={decision.value}. Main evidence: {reasons}."
