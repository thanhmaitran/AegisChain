"""License policy evaluation over SPDX expressions."""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from aegischain.domain.models import Component, LicenseFinding, LicenseStatus
from aegischain.engines.license.expression import (
    And,
    ExpressionError,
    License,
    Node,
    Or,
    With,
    normalize,
    to_string,
)


@dataclass(frozen=True)
class LicensePolicy:
    allowed: tuple[str, ...] = ()  # fnmatch patterns; empty means "anything not denied"
    denied: tuple[str, ...] = ()


def _matches(license_id: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatchcase(license_id.lower(), p.lower()) for p in patterns)


def _eval(node: Node, policy: LicensePolicy) -> tuple[LicenseStatus, str]:
    if isinstance(node, With):
        return _eval(node.license, policy)
    if isinstance(node, License):
        if node.custom:
            return LicenseStatus.UNKNOWN, f"{node.id} is a custom license reference"
        if _matches(node.id, policy.denied):
            return LicenseStatus.DENIED, f"{node.id} is denied by policy"
        if policy.allowed and not _matches(node.id, policy.allowed):
            return LicenseStatus.DENIED, f"{node.id} is not in the allowed list"
        return LicenseStatus.ALLOWED, f"{node.id} is permitted"
    left, right = _eval(node.left, policy), _eval(node.right, policy)
    pair = (left, right)
    if isinstance(node, And):
        for status in (LicenseStatus.DENIED, LicenseStatus.UNKNOWN):
            for s, r in pair:
                if s is status:
                    return s, r
        return LicenseStatus.ALLOWED, left[1] + "; " + right[1]
    assert isinstance(node, Or)
    for s, r in pair:
        if s is LicenseStatus.ALLOWED:  # the licensee may choose any alternative
            return s, r
    for s, r in pair:
        if s is LicenseStatus.UNKNOWN:
            return s, r
    return LicenseStatus.DENIED, left[1] + "; " + right[1]


def evaluate_license(purl: str, declared: str | None, policy: LicensePolicy) -> LicenseFinding:
    """Evaluate one declared license. Missing evidence is UNKNOWN, never inferred."""
    if declared is None or not declared.strip():
        return LicenseFinding(
            purl, None, None, LicenseStatus.UNKNOWN, "No license declared in available metadata"
        )
    try:
        node, changed = normalize(declared)
    except ExpressionError as exc:
        return LicenseFinding(
            purl, declared, None, LicenseStatus.INVALID, f"Not a recognised SPDX expression: {exc}"
        )
    status, reason = _eval(node, policy)
    normalized = to_string(node)
    if changed:
        reason += f" (normalised from {declared!r})"
    return LicenseFinding(purl, declared, normalized, status, reason)


def evaluate_components(
    components: Sequence[Component], policy: LicensePolicy
) -> tuple[LicenseFinding, ...]:
    return tuple(evaluate_license(c.purl, c.declared_license, policy) for c in components)
