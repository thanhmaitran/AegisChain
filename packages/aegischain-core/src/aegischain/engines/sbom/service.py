"""SBOM generation service."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from aegischain.domain.models import Component, SBOMValidationReport
from aegischain.engines.sbom.cyclonedx import generate_cyclonedx
from aegischain.engines.sbom.model import build_input
from aegischain.engines.sbom.spdx import generate_spdx
from aegischain.engines.sbom.validator import cross_check, validate_cyclonedx, validate_spdx


@dataclass(frozen=True)
class SBOMBundle:
    cyclonedx: dict[str, Any]
    spdx: dict[str, Any]
    validation: tuple[SBOMValidationReport, ...]

    @property
    def valid(self) -> bool:
        return all(v.valid for v in self.validation)


def generate_sboms(
    root_name: str, components: Sequence[Component], tool_version: str, created: datetime
) -> SBOMBundle:
    sbom = build_input(root_name, components, tool_version, created)
    cdx, spdx_doc = generate_cyclonedx(sbom), generate_spdx(sbom)
    reports = (validate_cyclonedx(cdx), validate_spdx(spdx_doc), cross_check(cdx, spdx_doc))
    return SBOMBundle(cdx, spdx_doc, reports)
