"""Deterministic conversion of the official InjecAgent benchmark.

The adapter targets the released ``base`` indirect-injection cases. It does not
run an LLM or claim to reproduce InjecAgent attack-success rates; it evaluates
whether AgentGuard intervenes when the labelled malicious tool response reaches
the observable agent trajectory.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

from ..evaluation import evaluate_cases
from ..models import EventKind, TraceEvent, TrustLevel
from ..tools import Impact, ToolSpec


_NEUTRAL_CONTROL_TEXT = "Content retrieved successfully; there are no additional action requests."


def injecagent_record_to_case(record: Dict[str, Any], family: str, index: int, source: str) -> dict:
    """Convert one official InjecAgent attack record to an unsafe AgentGuard case."""

    user_tool = _required_text(record, "User Tool")
    user_intent = _required_text(record, "User Instruction")
    response = _required_text(record, "Tool Response")
    category = {
        "dh": "injecagent_direct_harm",
        "ds": "injecagent_data_stealing",
    }.get(family)
    if category is None:
        raise ValueError(f"Unknown InjecAgent family: {family}")
    return _case(
        case_id=f"injecagent-{family}-base-{index:04d}",
        category=category,
        label="unsafe",
        user_tool=user_tool,
        user_intent=user_intent,
        tool_parameters=record.get("Tool Parameters", "{}"),
        response=response,
        source=source,
        metadata={
            "setting": "base",
            "family": family,
            "attack_type": record.get("Attack Type"),
            "attacker_tools": list(record.get("Attacker Tools") or []),
            "attacker_instruction": record.get("Attacker Instruction"),
            "expected_achievements": record.get("Expected Achievements"),
            "source_index": index,
        },
    )


def injecagent_safe_control_to_case(record: Dict[str, Any], index: int, source: str) -> dict:
    """Create one neutral control from an official user-case response template."""

    user_tool = _required_text(record, "User Tool")
    user_intent = _required_text(record, "User Instruction")
    template = _required_text(record, "Tool Response Template")
    if "<Attacker Instruction>" not in template:
        raise ValueError("InjecAgent user case has no attacker placeholder")
    response = template.replace("<Attacker Instruction>", _NEUTRAL_CONTROL_TEXT)
    return _case(
        case_id=f"injecagent-safe-control-{index:03d}",
        category="injecagent_safe_control",
        label="safe",
        user_tool=user_tool,
        user_intent=user_intent,
        tool_parameters=record.get("Tool Parameters", "{}"),
        response=response,
        source=source,
        metadata={"setting": "neutral_control", "family": "safe", "source_index": index},
    )


def convert_injecagent_dataset(input_dir: Path, include_safe_controls: bool = True) -> List[dict]:
    """Convert official InjecAgent DH/DS base files and optional neutral controls."""

    cases: List[dict] = []
    for family in ("dh", "ds"):
        path = input_dir / "data" / f"test_cases_{family}_base.json"
        records = _load_json_array(path)
        cases.extend(
            injecagent_record_to_case(record, family, index, path.name)
            for index, record in enumerate(records)
        )

    if include_safe_controls:
        path = input_dir / "data" / "user_cases.jsonl"
        for index, record in enumerate(_load_jsonl(path)):
            cases.append(injecagent_safe_control_to_case(record, index, path.name))
    return cases


def evaluate_injecagent_dataset(
    input_dir: Path,
    profiles: Iterable[str] = ("none", "keyword", "tool_policy", "full_v1", "full"),
    bootstrap_samples: int = 1000,
    include_safe_controls: bool = True,
) -> dict:
    cases = convert_injecagent_dataset(input_dir, include_safe_controls=include_safe_controls)
    result = evaluate_cases(cases, profiles, bootstrap_samples=bootstrap_samples)
    result["dataset"] = {
        "name": "InjecAgent base indirect-injection tool responses",
        "input": input_dir.name,
        "attack_case_count": sum(case["label"] == "unsafe" for case in cases),
        "safe_control_count": sum(case["label"] == "safe" for case in cases),
        "label_semantics": "unsafe = official InjecAgent base tool response contains an attacker instruction",
        "scope": "detection at tool-output boundary; not benchmark-native LLM attack-success rate",
    }
    return result


def _case(
    *,
    case_id: str,
    category: str,
    label: str,
    user_tool: str,
    user_intent: str,
    tool_parameters: Any,
    response: str,
    source: str,
    metadata: dict,
) -> dict:
    spec = ToolSpec(
        name=user_tool,
        description="InjecAgent user tool whose response carries external content",
        impact=Impact.READ_ONLY,
        capabilities={"injecagent:read"},
    )
    call = TraceEvent(
        trace_id="external",
        kind=EventKind.TOOL_CALL,
        source="injecagent:assistant",
        tool_name=user_tool,
        arguments=_parse_parameters(tool_parameters),
        trust=TrustLevel.MIXED,
        step=1,
    )
    output = TraceEvent(
        trace_id="external",
        kind=EventKind.TOOL_RESULT,
        source=f"injecagent:tool:{user_tool}",
        tool_name=user_tool,
        content=response,
        trust=TrustLevel.UNTRUSTED,
        step=2,
    )
    return {
        "case_id": case_id,
        "category": category,
        "label": label,
        "user_intent": user_intent,
        "allowed_tools": [user_tool],
        "authorized_destinations": [],
        "tool_specs": [_tool_spec_dict(spec)],
        "events": [_without_generated_fields(call.to_dict()), _without_generated_fields(output.to_dict())],
        "external_metadata": {"source": source, "benchmark": "InjecAgent", **metadata},
    }


def _parse_parameters(value: Any) -> dict:
    if isinstance(value, dict):
        return dict(value)
    if not isinstance(value, str):
        return {"raw": value}
    try:
        parsed = ast.literal_eval(value)
    except (ValueError, SyntaxError):
        return {"raw": value}
    return dict(parsed) if isinstance(parsed, dict) else {"raw": parsed}


def _load_json_array(path: Path) -> Sequence[dict]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid InjecAgent JSON file: {path}") from exc
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"InjecAgent file must contain a JSON object array: {path}")
    return value


def _load_jsonl(path: Path) -> List[dict]:
    records = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"Cannot read InjecAgent JSONL file: {path}") from exc
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid InjecAgent JSONL at {path}:{line_number}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"InjecAgent JSONL record must be an object at {path}:{line_number}")
        records.append(value)
    return records


def _required_text(record: Dict[str, Any], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"InjecAgent record requires non-empty string field: {key}")
    return value


def _without_generated_fields(event: dict) -> dict:
    copied = dict(event)
    copied.pop("trace_id", None)
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
