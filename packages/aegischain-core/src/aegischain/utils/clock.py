"""Injectable clocks so results can be reproduced."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    """Wall clock. Honours SOURCE_DATE_EPOCH for reproducible builds."""

    def now(self) -> datetime:
        epoch = os.environ.get("SOURCE_DATE_EPOCH")
        if epoch and epoch.isdigit():
            return datetime.fromtimestamp(int(epoch), tz=UTC)
        return datetime.now(tz=UTC).replace(microsecond=0)


@dataclass(frozen=True)
class FixedClock:
    value: datetime

    def now(self) -> datetime:
        return self.value
