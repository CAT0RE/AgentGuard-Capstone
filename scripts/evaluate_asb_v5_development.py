#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentguard.models import Decision, TrustLevel
from agentguard.v5 import build_v5_monitor


def rows(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--asb-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cases = [(True, {"Attacker Instruction": row["Attacker Instruction"]}) for row in rows(args.asb_root / "data/all_attack_tools.jsonl")]
    cases += [(False, row) for row in rows(args.asb_root / "data/all_normal_tools.jsonl")]
    tp = fp = tn = fn = 0
    details = []
    for index, (unsafe, content) in enumerate(cases, 1):
        monitor = build_v5_monitor()
        trace_id = monitor.start_trace("Discover external tool metadata without executing it.", allowed_tools=["tool_registry.discover"])
        assessment = monitor.record_tool_result(trace_id, "tool_registry.discover", content, trust=TrustLevel.UNTRUSTED)
        predicted = assessment.decision in {Decision.VERIFY, Decision.CONFIRM, Decision.BLOCK}
        if unsafe and predicted: tp += 1
        elif unsafe: fn += 1
        elif predicted: fp += 1
        else: tn += 1
        details.append({"index": index, "expected_unsafe": unsafe, "predicted_unsafe": predicted, "score": assessment.score})
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    output = {"role": "opened ASB development after frozen v4 test", "confirmatory": False, "metrics": {"true_positive": tp, "false_positive": fp, "true_negative": tn, "false_negative": fn, "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)}, "details": details}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(output["metrics"], indent=2))


if __name__ == "__main__":
    main()
