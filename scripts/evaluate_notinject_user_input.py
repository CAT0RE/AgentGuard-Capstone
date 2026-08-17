#!/usr/bin/env python3
"""Evaluate NotInject in its correct context: authenticated direct user input."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from agentguard.models import Decision
from agentguard.v4 import build_v4_monitor


FILES = ("NotInject_one.json", "NotInject_two.json", "NotInject_three.json")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--notinject-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    details = []
    hashes = {}
    for filename in FILES:
        path = args.notinject_dir / filename
        hashes[filename] = hashlib.sha256(path.read_bytes()).hexdigest()
        for index, item in enumerate(json.loads(path.read_text(encoding="utf-8")), 1):
            monitor = build_v4_monitor()
            trace_id = monitor.start_trace(item["prompt"], allowed_tools=[])
            assessment = monitor.trace(trace_id).assessments[-1]
            flagged = assessment.decision in {Decision.VERIFY, Decision.CONFIRM, Decision.BLOCK}
            details.append(
                {
                    "file": filename,
                    "index": index,
                    "flagged": flagged,
                    "score": assessment.score,
                    "decision": assessment.decision.value,
                }
            )
    false_positive = sum(item["flagged"] for item in details)
    output = {
        "role": "opened hard-benign authenticated-user-input control",
        "context": "trusted user_input, not untrusted tool_result",
        "case_count": len(details),
        "false_positive": false_positive,
        "true_negative": len(details) - false_positive,
        "false_positive_rate": round(false_positive / len(details), 4),
        "specificity": round((len(details) - false_positive) / len(details), 4),
        "source_hashes_sha256": hashes,
        "details": details,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: output[key] for key in ("case_count", "false_positive", "false_positive_rate", "specificity")}, indent=2))


if __name__ == "__main__":
    main()
