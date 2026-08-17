"""AgentDojo 0.1.35 trace and runtime integration.

The trace conversion functions have no AgentDojo dependency. The runtime factory
imports AgentDojo lazily so the core AgentGuard package remains Python 3.9+
compatible and dependency-free.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from ..evaluation import evaluate_cases
from ..models import Decision, EventKind, TraceEvent, TrustLevel
from ..monitor import SecurityMonitor
from ..policy import MonitorPolicy
from ..tools import Impact, ToolRegistry, ToolSpec


_IRREVERSIBLE_PREFIXES = (
    "cancel_",
    "delete_",
    "remove_",
    "send_money",
    "set_balance",
    "set_iban",
    "transfer_",
    "update_password",
)
_SIDE_EFFECT_PREFIXES = (
    "add_",
    "append_",
    "create_",
    "download_",
    "invite_",
    "post_",
    "reserve_",
    "reschedule_",
    "schedule_",
    "send_",
    "share_",
    "update_",
)
_EXTERNAL_TOKENS = ("email", "message", "post", "send", "share", "invite", "money", "transaction")
_SENSITIVE_TOKENS = ("balance", "email", "file", "iban", "inbox", "password", "transaction", "user_info")


def infer_agentdojo_tool_spec(name: str, description: str = "") -> ToolSpec:
    """Infer conservative security metadata from an AgentDojo function name."""
    normalized = name.lower()
    irreversible = normalized.startswith(_IRREVERSIBLE_PREFIXES)
    side_effect = irreversible or normalized.startswith(_SIDE_EFFECT_PREFIXES)
    external = side_effect and any(token in normalized for token in _EXTERNAL_TOKENS)
    sensitive = not side_effect and any(token in normalized for token in _SENSITIVE_TOKENS)
    impact = Impact.IRREVERSIBLE if irreversible else Impact.REVERSIBLE if side_effect else Impact.READ_ONLY
    capabilities = {"agentdojo:write" if side_effect else "agentdojo:read"}
    if external:
        capabilities.add("network:egress")
    return ToolSpec(
        name=name,
        description=description or "AgentDojo benchmark tool",
        impact=impact,
        capabilities=capabilities,
        sensitive_output=sensitive,
        external_communication=external,
        requires_confirmation=irreversible,
    )


def agentdojo_log_to_case(log: Dict[str, Any], source: str = "") -> dict:
    """Convert one AgentDojo TraceLogger JSON object to an AgentGuard case."""
    messages = log.get("messages")
    if not isinstance(messages, list):
        raise ValueError("AgentDojo log must contain a messages list")
    if "security" not in log:
        raise ValueError("AgentDojo log must contain the benchmark security result")

    user_intent = _first_user_text(messages)
    tools: Dict[str, ToolSpec] = {}
    events: List[dict] = []
    skipped_initial_user = False
    step = 1
    for message in messages:
        role = message.get("role")
        if role == "system":
            continue
        if role == "user" and not skipped_initial_user:
            skipped_initial_user = True
            continue
        if role == "user":
            events.append(_event_dict(EventKind.USER_INPUT, "user", _content_text(message.get("content")), step))
            step += 1
        elif role == "assistant":
            text = _content_text(message.get("content"))
            if text:
                events.append(_event_dict(EventKind.AGENT_MESSAGE, "agentdojo:assistant", text, step))
                step += 1
            for raw_call in message.get("tool_calls") or []:
                name, args = _tool_call_parts(raw_call)
                tools[name] = infer_agentdojo_tool_spec(name)
                event = TraceEvent(
                    trace_id="external",
                    kind=EventKind.TOOL_CALL,
                    source="agentdojo:assistant",
                    tool_name=name,
                    arguments=args,
                    trust=TrustLevel.MIXED,
                    step=step,
                )
                events.append(_without_trace(event.to_dict()))
                step += 1
        elif role == "tool":
            raw_call = message.get("tool_call") or {}
            name, _args = _tool_call_parts(raw_call)
            if not name:
                name = str(message.get("name") or "unknown_tool")
            tools[name] = infer_agentdojo_tool_spec(name)
            event = TraceEvent(
                trace_id="external",
                kind=EventKind.TOOL_RESULT,
                source=f"agentdojo:tool:{name}",
                tool_name=name,
                content=_content_text(message.get("content")),
                trust=TrustLevel.UNTRUSTED,
                metadata={"error": bool(message.get("error")), "agentdojo_error": message.get("error")},
                step=step,
            )
            events.append(_without_trace(event.to_dict()))
            step += 1

    suite = str(log.get("suite_name", "unknown"))
    user_task = str(log.get("user_task_id", "unknown"))
    injection_task = str(log.get("injection_task_id") or "none")
    attack = str(log.get("attack_type") or "none")
    case_id = f"agentdojo-{suite}-{user_task}-{attack}-{injection_task}"
    label = "safe" if bool(log["security"]) else "unsafe"
    category = "prompt_injection" if injection_task != "none" else "benign_utility"
    return {
        "case_id": case_id,
        "category": category,
        "label": label,
        "user_intent": user_intent,
        "allowed_tools": sorted(tools),
        "authorized_destinations": [],
        "tool_specs": [_tool_spec_dict(spec) for spec in sorted(tools.values(), key=lambda item: item.name)],
        "events": events,
        "external_metadata": {
            "source": source,
            "benchmark": "AgentDojo",
            "agentdojo_package_version": log.get("agentdojo_package_version"),
            "pipeline_name": log.get("pipeline_name"),
            "utility": log.get("utility"),
            "security": log.get("security"),
            "duration": log.get("duration"),
        },
    }


def convert_agentdojo_logs(input_path: Path) -> List[dict]:
    """Load a TraceLogger file or recursively load all JSON files in a run directory."""
    paths = [input_path] if input_path.is_file() else sorted(input_path.rglob("*.json"))
    cases = []
    for path in paths:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            cases.append(agentdojo_log_to_case(raw, str(path)))
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid AgentDojo trace {path}: {exc}") from exc
    if not cases:
        raise ValueError(f"No AgentDojo JSON traces found under {input_path}")
    return cases


def evaluate_agentdojo_logs(
    input_path: Path,
    profiles: Iterable[str] = ("none", "keyword", "tool_policy", "full"),
    bootstrap_samples: int = 1000,
) -> dict:
    """Evaluate AgentGuard against AgentDojo's security labels."""
    result = evaluate_cases(convert_agentdojo_logs(input_path), profiles, bootstrap_samples=bootstrap_samples)
    result["dataset"] = {
        "name": "AgentDojo external traces",
        "input": str(input_path),
        "label_semantics": "unsafe = AgentDojo security result is false",
    }
    return result


def make_agentdojo_executor(
    monitor: Optional[SecurityMonitor] = None,
    policy: Optional[MonitorPolicy] = None,
    allowed_tools: Optional[Sequence[str]] = None,
    authorized_destinations: Optional[Sequence[str]] = None,
    quarantine_interventions: Sequence[Decision] = (Decision.VERIFY, Decision.CONFIRM, Decision.BLOCK),
    tool_output_formatter=None,
):
    """Create an AgentDojo ToolsExecutor with pre-execution monitoring.

    AgentDojo is imported only when this factory is called. Calls assigned an
    intervention in ``quarantine_interventions`` are not executed. Risky tool
    outputs are recorded but replaced with a security notice before the LLM sees
    them.
    """
    try:
        from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
        from agentdojo.agent_pipeline.tool_execution import ToolsExecutor, tool_result_to_str
        from agentdojo.types import ChatToolResultMessage, text_content_block_from_string
    except ImportError as exc:
        raise RuntimeError("AgentDojo integration requires `pip install agentdojo==0.1.35`") from exc

    formatter = tool_output_formatter or tool_result_to_str
    quarantined = set(quarantine_interventions)

    class AgentGuardToolsExecutor(BasePipelineElement):
        name = "agentguard_tools_executor"

        def __init__(self):
            self.monitor = monitor
            self.delegate = ToolsExecutor(formatter)

        def query(self, query, runtime, env=None, messages=(), extra_args=None):
            extra = dict(extra_args or {})
            if not messages or messages[-1].get("role") != "assistant" or not messages[-1].get("tool_calls"):
                return query, runtime, env, messages, extra

            if self.monitor is None:
                registry = ToolRegistry([])
                for function in runtime.functions.values():
                    registry.register(infer_agentdojo_tool_spec(function.name, getattr(function, "description", "")))
                self.monitor = SecurityMonitor(policy=policy, registry=registry)
            else:
                for function in runtime.functions.values():
                    self.monitor.registry.register(
                        infer_agentdojo_tool_spec(function.name, getattr(function, "description", ""))
                    )

            trace_id = extra.get("agentguard_trace_id")
            if trace_id is None:
                scope = list(allowed_tools) if allowed_tools is not None else sorted(runtime.functions)
                trace_id = self.monitor.start_trace(
                    query,
                    allowed_tools=scope,
                    authorized_destinations=list(authorized_destinations or []),
                )
                extra["agentguard_trace_id"] = trace_id
            interventions = list(extra.get("agentguard_interventions", []))
            results = []
            for tool_call in messages[-1]["tool_calls"]:
                assessment = self.monitor.preflight(trace_id, tool_call.function, dict(tool_call.args))
                if assessment.decision in quarantined:
                    results.append(_blocked_message(ChatToolResultMessage, text_content_block_from_string, tool_call, assessment))
                    interventions.append(assessment.to_dict())
                    continue

                one_call_message = dict(messages[-1])
                one_call_message["tool_calls"] = [tool_call]
                delegated_messages = [*messages[:-1], one_call_message]
                _q, runtime, env, output_messages, _extra = self.delegate.query(
                    query, runtime, env, delegated_messages, extra
                )
                result_message = output_messages[-1]
                postflight = self.monitor.record_tool_result(
                    trace_id,
                    tool_call.function,
                    _content_text(result_message.get("content")),
                    trust=TrustLevel.UNTRUSTED,
                    sensitive=bool(self.monitor.registry.get(tool_call.function).sensitive_output),
                    error=bool(result_message.get("error")),
                )
                if postflight.decision in quarantined:
                    result_message = _blocked_message(
                        ChatToolResultMessage, text_content_block_from_string, tool_call, postflight, executed=True
                    )
                    interventions.append(postflight.to_dict())
                results.append(result_message)
            extra["agentguard_interventions"] = interventions
            return query, runtime, env, [*messages, *results], extra

    return AgentGuardToolsExecutor()


def _blocked_message(message_type, text_block, tool_call, assessment, executed: bool = False):
    action = "output quarantined" if executed else "execution blocked"
    content = f"AgentGuard {action}: {assessment.explanation}"
    return message_type(
        role="tool",
        content=[text_block(content)],
        tool_call_id=tool_call.id,
        tool_call=tool_call,
        error=f"AgentGuardIntervention:{assessment.decision.value}",
    )


def _first_user_text(messages: Sequence[dict]) -> str:
    for message in messages:
        if message.get("role") == "user":
            return _content_text(message.get("content"))
    raise ValueError("AgentDojo log has no user message")


def _content_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                value = block.get("content", block.get("text", ""))
            else:
                value = getattr(block, "content", str(block))
            if value:
                parts.append(str(value))
        return "\n".join(parts)
    return json.dumps(content, ensure_ascii=False, default=str)


def _tool_call_parts(raw_call: Any):
    if isinstance(raw_call, dict):
        name = raw_call.get("function", raw_call.get("name", ""))
        args = raw_call.get("args", raw_call.get("arguments", {}))
    else:
        name = getattr(raw_call, "function", getattr(raw_call, "name", ""))
        args = getattr(raw_call, "args", getattr(raw_call, "arguments", {}))
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            args = {"raw": args}
    return str(name), dict(args or {})


def _event_dict(kind: EventKind, source: str, content: str, step: int) -> dict:
    event = TraceEvent(trace_id="external", kind=kind, source=source, content=content, step=step)
    return _without_trace(event.to_dict())


def _without_trace(event: dict) -> dict:
    copied = dict(event)
    copied.pop("trace_id", None)
    # AgentDojo logs do not provide per-event identifiers or timestamps. Omitting
    # generated values keeps converted JSONL byte-for-byte reproducible.
    copied.pop("event_id", None)
    copied.pop("timestamp", None)
    return copied


def _tool_spec_dict(spec: ToolSpec) -> dict:
    return {
        "name": spec.name,
        "description": spec.description,
        "impact": spec.impact.value,
        "capabilities": sorted(spec.capabilities),
        "sensitive_output": spec.sensitive_output,
        "external_communication": spec.external_communication,
        "requires_confirmation": spec.requires_confirmation,
    }
