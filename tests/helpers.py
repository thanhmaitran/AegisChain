"""Shared test helpers."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path

from aegischain.domain.models import Component, Ecosystem, Scope
from aegischain.engines.dependency.parsers.common import npm_purl, pypi_purl
from aegischain.utils.clock import FixedClock

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_PY = ROOT / "examples" / "python-project"
EXAMPLE_NODE = ROOT / "examples" / "node-project"
FIXED_NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
CLOCK = FixedClock(FIXED_NOW)


def write_files(root: Path, files: dict[str, str | bytes]) -> Path:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode())
    return root


def pypi(
    name: str,
    version: str | None,
    direct: bool = True,
    deps: tuple[str, ...] = (),
    lic: str | None = None,
) -> Component:
    return Component(
        name,
        version,
        Ecosystem.PYPI,
        pypi_purl(name, version),
        direct,
        Scope.RUNTIME,
        deps,
        {},
        lic,
        1 if direct else None,
        ("t",),
    )


def npm(
    name: str,
    version: str | None,
    direct: bool = True,
    deps: tuple[str, ...] = (),
    lic: str | None = None,
) -> Component:
    return Component(
        name,
        version,
        Ecosystem.NPM,
        npm_purl(name, version),
        direct,
        Scope.RUNTIME,
        deps,
        {},
        lic,
        1 if direct else None,
        ("t",),
    )


def dsse(statement: dict) -> str:
    return json.dumps(
        {
            "payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
            "signatures": [{"sig": "AAAA"}],
        }
    )


def slsa_statement(
    sha256: str,
    builder: str = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.0.0",
    source: str = "git+https://github.com/acme/app@refs/heads/main",
) -> dict:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "app.tar.gz", "digest": {"sha256": sha256}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "x",
                "externalParameters": {"workflow": {"repository": source}},
            },
            "runDetails": {"builder": {"id": builder}},
        },
    }
