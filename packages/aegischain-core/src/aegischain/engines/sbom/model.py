"""Internal SBOM model shared by both format adapters."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from aegischain.domain.models import Component
from aegischain.engines.license.expression import ExpressionError, normalize, to_string
from aegischain.utils.serialization import canonical_json, sha256_text


@dataclass(frozen=True)
class SBOMInput:
    root_name: str
    components: tuple[Component, ...]
    tool_name: str
    tool_version: str
    created: datetime

    @property
    def content_digest(self) -> str:
        """Digest of the *content* (not the timestamp), used for deterministic IDs."""
        return sha256_text(
            canonical_json(
                {
                    "root": self.root_name,
                    "components": [
                        (c.purl, c.direct, c.scope, c.dependencies, c.hashes, c.declared_license)
                        for c in self.components
                    ],
                }
            )
        )

    @property
    def direct_purls(self) -> list[str]:
        return [c.purl for c in self.components if c.direct]


def license_expression(declared: str | None) -> str | None:
    """Return a valid canonical SPDX expression for ``declared`` or None."""
    if not declared:
        return None
    try:
        node, _ = normalize(declared)
    except ExpressionError:
        return None
    return to_string(node)


def build_input(
    root_name: str, components: Sequence[Component], tool_version: str, created: datetime
) -> SBOMInput:
    return SBOMInput(
        root_name,
        tuple(sorted(components, key=lambda c: c.purl)),
        "aegischain",
        tool_version,
        created,
    )


_SAFE = re.compile(r"[^A-Za-z0-9.\-]+")


def safe_id(text: str) -> str:
    return _SAFE.sub("-", text).strip("-") or "x"
