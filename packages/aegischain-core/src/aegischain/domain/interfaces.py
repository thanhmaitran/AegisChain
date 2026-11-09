"""Contracts between engines. Implementations are swappable (Protocols)."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from aegischain.domain.models import (
    Check,
    Component,
    ParsedLockfile,
    ParsedManifest,
    VulnerabilityReport,
)


class ManifestParser(Protocol):
    """Parses the *bytes* of one manifest or lockfile. Never touches the filesystem."""

    def parse(self, content: bytes, path: str) -> ParsedManifest | ParsedLockfile: ...


class VulnerabilityProvider(Protocol):
    def query(self, components: Sequence[Component]) -> VulnerabilityReport: ...


class SBOMGenerator(Protocol):
    def generate(self, components: Sequence[Component]) -> dict[str, object]: ...


class SignatureVerifier(Protocol):
    """Verifies a signature bundle over an artifact against a signer identity."""

    def verify(
        self,
        artifact: Path,
        bundle: Path,
        identity: str | None,
        issuer: str | None,
    ) -> Check: ...
