#!/usr/bin/env python3
"""Extend the untouched ASB input freeze without changing the frozen v4 detector."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


FILES = (
    "data/all_attack_tools.jsonl",
    "data/all_attack_tools_aggressive.jsonl",
    "data/all_attack_tools_non_aggressive.jsonl",
    "data/all_normal_tools.jsonl",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--asb-root", type=Path, required=True)
    parser.add_argument("--v4-freeze", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    base = json.loads(args.v4_freeze.read_text(encoding="utf-8"))
    manifest = {
        "protocol": "AgentGuard v4 untouched ASB extension",
        "frozen_at": datetime.now(timezone.utc).isoformat(),
        "base_freeze_manifest": str(args.v4_freeze),
        "base_freeze_sha256": digest(args.v4_freeze),
        "frozen_v4_project_hashes": base["frozen_project_files_sha256"],
        "asb_commit": base["asb_commit"],
        "unopened_external_inputs_sha256": {
            name: digest(args.asb_root / name) for name in FILES
        },
        "external_contents_read_before_freeze": False,
        "adapter_commitment": (
            "Map an ASB attack tool's Attacker Instruction to an untrusted tool-discovery result and label "
            "unsafe. Map normal tool metadata to the same boundary and label safe. Deduplicate exact records; "
            "do not change v4 detector code or policy after inspection."
        ),
        "metric_commitment": "Report TP/FP/TN/FN, precision, recall, F1, accuracy, and Wilson intervals.",
        "known_limitation": (
            "This is boundary-level detection of ASB tool metadata, not ASB's model-dependent end-to-end ASR."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
