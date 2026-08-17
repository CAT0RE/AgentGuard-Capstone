#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from agentguard.evaluation import load_cases
from agentguard.v4 import evaluate_v4_cases


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--role", default="opened development/regression set")
    args = parser.parse_args()
    result = evaluate_v4_cases(load_cases(args.cases))
    result["dataset"] = {
        "path": str(args.cases),
        "sha256": hashlib.sha256(args.cases.read_bytes()).hexdigest(),
        "role": args.role,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"metrics": result["metrics"], "latency_ms": result["latency_ms"]}, indent=2))


if __name__ == "__main__":
    main()
