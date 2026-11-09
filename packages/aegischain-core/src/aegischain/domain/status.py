"""Decision statuses and severities.

Design rule (fail-safe): absence of evidence is never PASS. ``worst`` of an empty
collection is INDETERMINATE.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import Enum


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    INDETERMINATE = "INDETERMINATE"


# Precedence when combining statuses: FAIL > INDETERMINATE > WARN > PASS.
_STATUS_RANK = {Status.PASS: 0, Status.WARN: 1, Status.INDETERMINATE: 2, Status.FAIL: 3}


def worst(statuses: Iterable[Status]) -> Status:
    """Combine statuses. An empty collection yields INDETERMINATE, never PASS."""
    items = list(statuses)
    if not items:
        return Status.INDETERMINATE
    return max(items, key=lambda s: _STATUS_RANK[s])


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def from_score(cls, score: float) -> Severity:
        """Classify a CVSS v3 base score using the standard qualitative scale."""
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.NONE

    @classmethod
    def from_label(cls, label: str | None) -> Severity:
        if not label:
            return cls.UNKNOWN
        normalized = label.strip().upper()
        if normalized == "MODERATE":
            normalized = "MEDIUM"
        try:
            return cls(normalized)
        except ValueError:
            return cls.UNKNOWN


_SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.NONE: 1,
    Severity.UNKNOWN: 0,
}
