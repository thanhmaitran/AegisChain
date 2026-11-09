"""requirements.txt parser (pip requirements file format, subset)."""

from __future__ import annotations

import re

from packaging.requirements import InvalidRequirement, Requirement

from aegischain.domain.models import DeclaredDependency, Ecosystem, ParsedManifest, Scope
from aegischain.engines.dependency.parsers.common import decode_utf8, normalize_pypi_name

_HASH = re.compile(r"--hash=(sha256|sha384|sha512):([0-9a-fA-F]+)")


def _logical_lines(text: str) -> list[str]:
    lines: list[str] = []
    buffer = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        lines.append(buffer + line)
        buffer = ""
    if buffer:
        lines.append(buffer)
    return lines


def _strip_comment(line: str) -> str:
    return re.sub(r"(^|\s)#.*$", "", line).strip()


class RequirementsParser:
    def parse(self, content: bytes, path: str) -> ParsedManifest:
        text = decode_utf8(content, path)
        lowered = path.lower()
        scope = (
            Scope.DEV
            if any(t in lowered for t in ("dev", "test", "lint", "docs"))
            else Scope.RUNTIME
        )
        declared: list[DeclaredDependency] = []
        warnings: list[str] = []
        for line in _logical_lines(text):
            line = _strip_comment(line)
            if not line:
                continue
            if line.startswith("-"):
                warnings.append(f"{path}: option not interpreted: {line.split()[0]}")
                continue
            hashes = _HASH.findall(line)
            requirement_text = _HASH.sub("", line).strip()
            try:
                req = Requirement(requirement_text)
            except InvalidRequirement:
                warnings.append(
                    f"{path}: unparseable requirement skipped: {requirement_text[:80]!r}"
                )
                continue
            if req.url:
                warnings.append(
                    f"{path}: direct URL requirement has no resolvable version: {req.name}"
                )
            pinned = None
            specs = list(req.specifier)
            if len(specs) == 1 and specs[0].operator == "==" and "*" not in specs[0].version:
                pinned = specs[0].version
            elif not req.url:
                warnings.append(f"{path}: {req.name} is not pinned with '=='; version is unknown")
            digest = {a: h.lower() for a, h in hashes[:1]} if len(hashes) == 1 else {}
            declared.append(
                DeclaredDependency(
                    name=normalize_pypi_name(req.name),
                    specifier=str(req.specifier) or None,
                    scope=scope,
                    ecosystem=Ecosystem.PYPI,
                    source_file=path,
                    pinned_version=pinned,
                    hashes=digest,
                )
            )
        return ParsedManifest(path, Ecosystem.PYPI, tuple(declared), tuple(warnings))
