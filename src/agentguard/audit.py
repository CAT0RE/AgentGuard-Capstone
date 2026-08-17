from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Iterable, List, Optional


class JsonlAuditStore:
    """Append-only JSONL audit log. Passing no path keeps records in memory only."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path else None
        self._records: List[Dict[str, Any]] = []
        self._lock = Lock()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, record: Dict[str, Any]) -> None:
        with self._lock:
            self._records.append(record)
            if self.path:
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")

    def records(self, trace_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            values = list(self._records)
        if trace_id is None:
            return values
        return [item for item in values if item.get("trace_id") == trace_id]

    def extend(self, records: Iterable[Dict[str, Any]]) -> None:
        for record in records:
            self.append(record)

