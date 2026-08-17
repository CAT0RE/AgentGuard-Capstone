#!/usr/bin/env python3
"""Freeze v5 before inspecting WASP attack and utility records."""

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
    "src/agentguard/detectors/provenance_gate.py",
    "src/agentguard/detectors/structural_injection.py",
    "src/agentguard/policy.py",
    "src/agentguard/v5.py",
    "tests/test_provenance_gate_v5.py",
)
EXTERNAL_FILES = (
    "webarena_prompt_injections/configs/croissant/attacks_in_webarena_format.jsonl",
    "webarena_prompt_injections/configs/croissant/utility_in_webarena_format.jsonl",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--wasp-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = {
        "protocol": "AgentGuard v5 pre-WASP freeze",
        "frozen_at": datetime.now(timezone.utc).isoformat(),
        "wasp_commit": "ffee6f41fde76acd14bd792db442479c506260c2",
        "detector_profile": "full_v5_candidate",
        "decision_positive": ["verify", "confirm", "block"],
        "design_commitment": (
            "Standalone control intent from an untrusted tool/web observation triggers VERIFY; trusted user "
            "requests are not evidence for this provenance detector; deterministic authorization remains the "
            "blocking authority."
        ),
        "adapter_commitment": (
            "After freeze, inspect WASP attack/utility schemas. Map web-observation text to untrusted tool "
            "results, preserve attack vs utility labels, and do not alter v5 detectors or policy."
        ),
        "frozen_project_files_sha256": {
            name: digest(args.project_root / name) for name in PROJECT_FILES
        },
        "unopened_external_inputs_sha256": {
            name: digest(args.wasp_root / name) for name in EXTERNAL_FILES
        },
        "external_contents_read_before_freeze": False,
        "prior_opened_development_sets": [
            "project benchmark",
            "AgentDojo converted traces",
            "InjecAgent converted base cases",
            "PIGuard NotInject",
            "BIPIA",
            "ASB",
        ],
        "metric_commitment": "Report confusion matrix, precision, recall, specificity, F1, accuracy, and Wilson 95% intervals.",
        "known_limitation": "Boundary detection is not WASP end-to-end model attack success rate.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
