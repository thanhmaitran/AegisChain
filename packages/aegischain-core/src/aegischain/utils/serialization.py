"""Deterministic serialization helpers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from datetime import date, datetime
from enum import Enum
from pathlib import PurePath
from typing import Any


def to_jsonable(obj: Any) -> Any:
    """Convert dataclasses, enums and containers to plain JSON-compatible data."""
    if isinstance(obj, Enum):
        return obj.value
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_jsonable(getattr(obj, f.name)) for f in fields(obj)}
    if isinstance(obj, Mapping):
        return {str(k): to_jsonable(v) for k, v in sorted(obj.items(), key=lambda kv: str(kv[0]))}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, (set, frozenset)):
        return sorted((to_jsonable(v) for v in obj), key=lambda v: json.dumps(v, sort_keys=True))
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, PurePath):
        return obj.as_posix()
    return obj


def canonical_json(obj: Any) -> str:
    """Stable, compact JSON used for hashing and reproducible output."""
    return json.dumps(to_jsonable(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def pretty_json(obj: Any) -> str:
    return json.dumps(to_jsonable(obj), sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
