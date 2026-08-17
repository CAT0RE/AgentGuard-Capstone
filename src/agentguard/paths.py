from __future__ import annotations

import sys
from pathlib import Path


def default_benchmark_path() -> Path:
    """Resolve the development benchmark in a source checkout or installed environment."""
    source_path = Path("benchmarks/cases.jsonl")
    if source_path.is_file():
        return source_path
    installed_path = Path(sys.prefix) / "share" / "agentguard" / "benchmarks" / "cases.jsonl"
    return installed_path

