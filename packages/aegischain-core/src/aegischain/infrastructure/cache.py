"""On-disk cache for OSV vulnerability records, keyed by id and ``modified``."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any


class VulnerabilityCache:
    """A record is reused only while OSV's ``modified`` timestamp is unchanged."""

    def __init__(self, directory: Path | None) -> None:
        self._dir = directory
        self._memory: dict[str, dict[str, Any]] = {}
        if directory is not None:
            directory.mkdir(parents=True, exist_ok=True)

    def _path(self, osv_id: str) -> Path | None:
        if self._dir is None:
            return None
        return self._dir / (hashlib.sha256(osv_id.encode()).hexdigest() + ".json")

    def get(self, osv_id: str, modified: str | None) -> dict[str, Any] | None:
        entry = self._memory.get(osv_id)
        path = self._path(osv_id)
        if entry is None and path is not None and path.is_file():
            try:
                entry = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return None  # corrupt entry == miss
        if not isinstance(entry, dict) or modified is None or entry.get("modified") != modified:
            return None
        record = entry.get("record")
        return record if isinstance(record, dict) and record.get("id") == osv_id else None

    def put(self, osv_id: str, record: dict[str, Any], cached_at: datetime) -> None:
        entry = {
            "cached_at": cached_at.isoformat(),
            "modified": record.get("modified"),
            "record": record,
        }
        self._memory[osv_id] = entry
        path = self._path(osv_id)
        if path is None:
            return
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(entry, handle, sort_keys=True)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
