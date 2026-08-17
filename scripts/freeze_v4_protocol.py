#!/usr/bin/env python3
"""Freeze v4 before inspecting the official ASB test-file contents."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


PROJECT_FILES = (
    "src/agentguard/assets/contextual_injection_v3.json",
    "src/agentguard/detectors/contextual_injection.py",
    "src/agentguard/detectors/injection.py",
    "src/agentguard/detectors/provenance_instruction.py",
    "src/agentguard/detectors/structural_injection.py",
    "src/agentguard/policy.py",
    "src/agentguard/v4.py",
    "tests/test_contextual_injection_v3.py",
    "tests/test_provenance_instruction_v4.py",
)
EXTERNAL_FILES = ("data/agent_task_test.jsonl", "data/attack_tools_test.jsonl")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--asb-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = {
        "protocol": "AgentGuard v4 pre-ASB freeze",
        "frozen_at": datetime.now(timezone.utc).isoformat(),
        "asb_commit": "1f561dccf92d55302368fa67679b4ba9d9c8fdc4",
        "detector_profile": "full_v4_candidate",
        "decision_positive": ["verify", "confirm", "block"],
        "design_commitment": (
            "Authenticated user requests remain in the user-input channel. Independent instructions from "
            "untrusted external data receive a VERIFY-or-stronger intervention."
        ),
        "adapter_commitment": (
            "After freeze, inspect ASB schemas and map attack payload/tool-instruction text to its closest "
            "AgentGuard boundary without changing v4 detector code, severity, confidence, or policy."
        ),
        "frozen_project_files_sha256": {
            name: digest(args.project_root / name) for name in PROJECT_FILES
        },
        "unopened_external_inputs_sha256": {
            name: digest(args.asb_root / name) for name in EXTERNAL_FILES
        },
        "external_test_contents_read_before_freeze": False,
        "prior_opened_development_sets": [
            "project benchmark",
            "AgentDojo converted traces",
            "InjecAgent converted base cases",
            "PIGuard NotInject",
            "BIPIA code/text payloads",
        ],
        "interpretation_rule": (
            "ASB evaluation is confirmatory only for the exact payload/boundary mapping documented by the "
            "post-freeze adapter; it is not automatically equivalent to ASB end-to-end attack success rate."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
