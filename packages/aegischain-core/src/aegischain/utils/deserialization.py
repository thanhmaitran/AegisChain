"""Rebuild frozen domain dataclasses from ``to_jsonable`` output (type-hint driven)."""

from __future__ import annotations

import collections.abc
import dataclasses
import types
import typing
from datetime import date, datetime
from enum import Enum
from typing import Any, Union, cast, get_args, get_origin, get_type_hints


def _convert(tp: Any, value: Any) -> Any:
    origin, args = get_origin(tp), get_args(tp)

    if origin in (Union, types.UnionType):
        options = [a for a in args if a is not type(None)]
        return None if value is None else _convert(options[0], value)

    if tp is Any or tp is object or value is None:
        return value

    if origin is tuple:
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(_convert(args[0], v) for v in value)
        return tuple(_convert(a, v) for a, v in zip(args, value, strict=True))

    if origin is list:
        return [_convert(args[0], v) for v in value]

    if origin in (frozenset, set):
        return frozenset(_convert(args[0], v) for v in value)

    if origin in (dict, collections.abc.Mapping):
        return {_convert(args[0], k): _convert(args[1], v) for k, v in value.items()}

    if isinstance(tp, type):
        if issubclass(tp, Enum):
            return tp(value)
        if issubclass(tp, datetime):
            return datetime.fromisoformat(value)
        if issubclass(tp, date):
            return date.fromisoformat(value)
        if hasattr(tp, "__dataclass_fields__"):
            return from_jsonable(tp, value)

    return value


def from_jsonable[T](cls: type[T], data: dict[str, Any]) -> T:
    hints = get_type_hints(cls, localns=vars(typing))
    kwargs = {
        field.name: _convert(hints[field.name], data[field.name])
        for field in dataclasses.fields(cast(Any, cls))
        if field.name in data
    }
    return cls(**kwargs)
