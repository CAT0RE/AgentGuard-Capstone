#!/usr/bin/env python3
"""Hash the v3 implementation and unopened external-test inputs before evaluation."""

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
    "src/agentguard/detectors/structural_injection.py",
    "src/agentguard/evaluation.py",
    "src/agentguard/monitor.py",
    "src/agentguard/policy.py",
    "scripts/train_v3_contextual_detector.py",
)
EXTERNAL_FILES = ("BIPIA_code.json", "BIPIA_text.json")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--external-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    manifest = {
        "protocol": "AgentGuard v3 pre-BIPIA freeze",
        "frozen_at": datetime.now(timezone.utc).isoformat(),
        "detector_profile": "full_v3",
        "decision_positive": ["verify", "confirm", "block"],
        "unit_of_analysis": "one benchmark payload embedded as one untrusted tool result",
        "adapter_commitment": (
            "Map the benchmark payload field to an untrusted document.read result; preserve explicit labels; "
            "do not modify detector features, weights, thresholds, or policy after inspecting BIPIA."
        ),
        "frozen_project_files_sha256": {
            name: digest(args.project_root / name) for name in PROJECT_FILES
        },
        "unopened_external_inputs_sha256": {
            name: digest(args.external_dir / name) for name in EXTERNAL_FILES
        },
        "external_inputs_read_before_freeze": False,
        "known_input_hashes_from_download_only": {
            "BIPIA_code.json": "892545c5aaec0645b1ded65dc7816b3d70e9ef4eadcba2301a7a3db93676b6e0",
            "BIPIA_text.json": "75750e7b4e8b34e8f9d88d89b357aeaaf02bd07f9e493ccd37eda74a0cd7c7f8",
        },
        "interpretation_rule": (
            "This is a one-time external payload-detection test, not benchmark-native attack success rate. "
            "Any later detector change invalidates the confirmatory status of these BIPIA results."
        ),
    }
    if manifest["unopened_external_inputs_sha256"] != manifest["known_input_hashes_from_download_only"]:
        raise SystemExit("External BIPIA hashes changed between download and freeze")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
