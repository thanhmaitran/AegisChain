"""SPDX license expression parser (SPDX spec Annex D grammar subset).

Supports ``AND``, ``OR``, ``WITH``, parentheses, the ``+`` or-later suffix and
``LicenseRef-``/``DocumentRef-`` custom identifiers. Operator precedence:
``WITH`` > ``AND`` > ``OR``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from aegischain.engines.license.spdx_data import (
    ALIASES,
    DEPRECATED,
    EXCEPTION_IDS,
    LICENSE_IDS,
)


class ExpressionError(ValueError):
    """The text is not a valid (or recognisable) SPDX license expression."""


@dataclass(frozen=True)
class License:
    id: str  # canonical SPDX id, or a LicenseRef-* identifier
    custom: bool = False


@dataclass(frozen=True)
class With:
    license: License
    exception: str


@dataclass(frozen=True)
class And:
    left: Node
    right: Node


@dataclass(frozen=True)
class Or:
    left: Node
    right: Node


Node = License | With | And | Or

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9][A-Za-z0-9.\-+:_]*)")
_CUSTOM = re.compile(r"^(?:DocumentRef-[A-Za-z0-9.\-]+:)?LicenseRef-[A-Za-z0-9.\-]+$")


def _tokenize(text: str) -> list[str]:
    tokens, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise ExpressionError(
                f"unexpected character at position {pos}: {text[pos : pos + 10]!r}"
            )
        tokens.append(m.group(1))
        pos = m.end()
    if not tokens:
        raise ExpressionError("empty expression")
    return tokens


def canonical_license_id(raw: str) -> License:
    if _CUSTOM.match(raw):
        return License(raw, custom=True)
    low = raw.lower()
    if low in LICENSE_IDS:
        return License(LICENSE_IDS[low])
    if low in DEPRECATED:
        return License(DEPRECATED[low])
    if low.endswith("+") and low[:-1] in LICENSE_IDS:
        # "Apache-2.0+" style or-later suffix on a non-GPL family: keep as written.
        return License(LICENSE_IDS[low[:-1]] + "+")
    raise ExpressionError(f"unknown license identifier: {raw!r}")


class _Parser:
    def __init__(self, tokens: list[str]) -> None:
        self.tokens, self.i = tokens, 0

    def peek(self) -> str | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def take(self) -> str:
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def parse(self) -> Node:
        node = self.or_expr()
        if self.peek() is not None:
            raise ExpressionError(f"unexpected token {self.peek()!r}")
        return node

    def or_expr(self) -> Node:
        node = self.and_expr()
        while (t := self.peek()) is not None and t.upper() == "OR":
            self.take()
            node = Or(node, self.and_expr())
        return node

    def and_expr(self) -> Node:
        node = self.with_expr()
        while (t := self.peek()) is not None and t.upper() == "AND":
            self.take()
            node = And(node, self.with_expr())
        return node

    def with_expr(self) -> Node:
        node = self.primary()
        if (t := self.peek()) is not None and t.upper() == "WITH":
            self.take()
            if not isinstance(node, License):
                raise ExpressionError("WITH must follow a single license")
            if self.peek() is None:
                raise ExpressionError("WITH requires an exception identifier")
            exc = self.take()
            canonical = EXCEPTION_IDS.get(exc.lower())
            if canonical is None:
                raise ExpressionError(f"unknown exception identifier: {exc!r}")
            return With(node, canonical)
        return node

    def primary(self) -> Node:
        tok = self.peek()
        if tok is None:
            raise ExpressionError("unexpected end of expression")
        if tok == "(":
            self.take()
            node = self.or_expr()
            if self.peek() != ")":
                raise ExpressionError("missing closing parenthesis")
            self.take()
            return node
        if tok == ")" or tok.upper() in {"AND", "OR", "WITH"}:
            raise ExpressionError(f"unexpected token {tok!r}")
        return canonical_license_id(self.take())


def parse_expression(text: str) -> Node:
    return _Parser(_tokenize(text)).parse()


def to_string(node: Node, parent: str = "") -> str:
    """Render a canonical SPDX expression string."""
    if isinstance(node, License):
        return node.id
    if isinstance(node, With):
        return f"{node.license.id} WITH {node.exception}"
    op = "AND" if isinstance(node, And) else "OR"
    text = f"{to_string(node.left, op)} {op} {to_string(node.right, op)}"
    return f"({text})" if parent and parent != op else text


def leaves(node: Node) -> list[License]:
    if isinstance(node, License):
        return [node]
    if isinstance(node, With):
        return [node.license]
    return leaves(node.left) + leaves(node.right)


def normalize(text: str) -> tuple[Node, bool]:
    """Parse ``text``; returns (node, changed) where changed means it was rewritten.

    Tries the exact text first, then a small exact-match alias table. Never guesses.
    """
    stripped = text.strip()
    try:
        node = parse_expression(stripped)
        return node, to_string(node) != stripped
    except ExpressionError:
        alias = ALIASES.get(stripped.lower())
        if alias is None:
            raise
        return parse_expression(alias), True
