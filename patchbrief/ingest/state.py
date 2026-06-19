from __future__ import annotations

import json
from pathlib import Path


class ProcessedState:
    """Tracks CVE IDs that have already been processed to prevent duplicates."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._processed: set[str] = set()
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                self._processed = set(data.get("processed", []))
            except (json.JSONDecodeError, KeyError):
                pass

    def is_processed(self, cve_id: str) -> bool:
        return cve_id.upper() in self._processed

    def mark_processed(self, cve_id: str) -> None:
        self._processed.add(cve_id.upper())

    def save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps({"processed": sorted(self._processed)}, indent=2),
            encoding="utf-8",
        )

    def __len__(self) -> int:
        return len(self._processed)
