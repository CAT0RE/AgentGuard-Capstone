from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from .models import EventKind, TrustLevel


VALID_LABELS = {"safe", "unsafe"}
VALID_INTERVENTIONS = {"allow", "log", "verify", "confirm", "block"}


def validate_dataset(path: Path, require_annotations: bool = False) -> dict:
    errors: List[str] = []
    warnings: List[str] = []
    cases = _read_jsonl(path, errors)
    identifiers = Counter(str(case.get("case_id", "")) for case in cases)

    for index, case in enumerate(cases, 1):
        prefix = f"line {index} ({case.get('case_id', '<missing>')})"
        _require_string(case, "case_id", prefix, errors)
        _require_string(case, "category", prefix, errors)
        _require_string(case, "user_intent", prefix, errors)
        if case.get("label") not in VALID_LABELS:
            errors.append(f"{prefix}: label must be one of {sorted(VALID_LABELS)}")
        if not isinstance(case.get("allowed_tools", []), list):
            errors.append(f"{prefix}: allowed_tools must be an array")
        if not isinstance(case.get("events", []), list):
            errors.append(f"{prefix}: events must be an array")
            continue

        for event_index, event in enumerate(case.get("events", [])):
            event_prefix = f"{prefix}, event {event_index}"
            if event.get("kind") not in {item.value for item in EventKind}:
                errors.append(f"{event_prefix}: invalid event kind {event.get('kind')!r}")
            if event.get("trust", "trusted") not in {item.value for item in TrustLevel}:
                errors.append(f"{event_prefix}: invalid trust level {event.get('trust')!r}")
            if not isinstance(event.get("source"), str) or not event.get("source"):
                errors.append(f"{event_prefix}: source is required")
            if event.get("kind") == EventKind.TOOL_CALL.value and not event.get("tool_name"):
                errors.append(f"{event_prefix}: tool_call requires tool_name")

        if require_annotations:
            _validate_annotation_fields(case, prefix, errors)
        elif case.get("label") == "unsafe" and "first_unsafe_event" not in case:
            warnings.append(f"{prefix}: final-study case should label first_unsafe_event")

    for identifier, count in identifiers.items():
        if not identifier:
            continue
        if count > 1:
            errors.append(f"duplicate case_id {identifier!r} appears {count} times")

    return {
        "path": str(path),
        "valid": not errors,
        "case_count": len(cases),
        "class_counts": dict(sorted(Counter(case.get("label", "<missing>") for case in cases).items())),
        "category_counts": dict(sorted(Counter(case.get("category", "<missing>") for case in cases).items())),
        "errors": errors,
        "warnings": warnings,
    }


def freeze_dataset(path: Path, manifest_path: Path, require_annotations: bool = True) -> dict:
    validation = validate_dataset(path, require_annotations=require_annotations)
    if not validation["valid"]:
        raise ValueError("Dataset validation failed:\n" + "\n".join(validation["errors"]))
    content = path.read_bytes()
    manifest = {
        "schema_version": "1.0",
        "dataset_file": path.name,
        "sha256": hashlib.sha256(content).hexdigest(),
        "bytes": len(content),
        "frozen_at": datetime.now(timezone.utc).isoformat(),
        "validation": validation,
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return manifest


def annotation_agreement(path_a: Path, path_b: Path) -> dict:
    errors_a: List[str] = []
    errors_b: List[str] = []
    records_a = _read_jsonl(path_a, errors_a)
    records_b = _read_jsonl(path_b, errors_b)
    if errors_a or errors_b:
        raise ValueError("Invalid annotation JSONL:\n" + "\n".join(errors_a + errors_b))
    by_a = {str(item.get("case_id")): item for item in records_a}
    by_b = {str(item.get("case_id")): item for item in records_b}
    shared = sorted(set(by_a) & set(by_b))
    if not shared:
        raise ValueError("Annotation files have no shared case_id values")

    fields = ("label", "category", "intervention_type")
    agreement = {}
    for field in fields:
        pairs = [(str(by_a[case_id].get(field, "")), str(by_b[case_id].get(field, ""))) for case_id in shared]
        agreement[field] = _cohen_kappa(pairs)
    return {
        "annotator_a": str(path_a),
        "annotator_b": str(path_b),
        "shared_cases": len(shared),
        "missing_from_a": sorted(set(by_b) - set(by_a)),
        "missing_from_b": sorted(set(by_a) - set(by_b)),
        "agreement": agreement,
    }


def _validate_annotation_fields(case: dict, prefix: str, errors: List[str]) -> None:
    intervention = case.get("intervention_type")
    if intervention not in VALID_INTERVENTIONS:
        errors.append(f"{prefix}: intervention_type must be one of {sorted(VALID_INTERVENTIONS)}")
    if case.get("label") == "unsafe":
        first = case.get("first_unsafe_event")
        if not isinstance(first, int) or first < 0 or first >= len(case.get("events", [])):
            errors.append(f"{prefix}: unsafe case requires a valid zero-based first_unsafe_event")
    confidence = case.get("annotation_confidence")
    if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        errors.append(f"{prefix}: annotation_confidence must be between 0 and 1")


def _require_string(case: dict, field: str, prefix: str, errors: List[str]) -> None:
    if not isinstance(case.get(field), str) or not case.get(field):
        errors.append(f"{prefix}: {field} must be a non-empty string")


def _read_jsonl(path: Path, errors: List[str]) -> List[dict]:
    records: List[dict] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        errors.append(f"cannot read {path}: {exc}")
        return records
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"{path}:{line_number}: invalid JSON ({exc.msg})")
            continue
        if not isinstance(value, dict):
            errors.append(f"{path}:{line_number}: each line must be a JSON object")
            continue
        records.append(value)
    return records


def _cohen_kappa(pairs: Iterable[Tuple[str, str]]) -> Dict[str, float]:
    values = list(pairs)
    total = len(values)
    observed = sum(left == right for left, right in values) / total
    left_counts = Counter(left for left, _right in values)
    right_counts = Counter(right for _left, right in values)
    categories = set(left_counts) | set(right_counts)
    expected = sum((left_counts[item] / total) * (right_counts[item] / total) for item in categories)
    kappa = 1.0 if expected == 1.0 and observed == 1.0 else (observed - expected) / (1.0 - expected)
    return {"observed_agreement": round(observed, 4), "expected_agreement": round(expected, 4), "kappa": round(kappa, 4)}
