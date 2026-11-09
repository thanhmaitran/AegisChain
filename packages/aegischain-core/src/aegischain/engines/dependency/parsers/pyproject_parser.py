"""pyproject.toml parser: PEP 621, PEP 735 dependency groups and Poetry sections."""

from __future__ import annotations

import re
import tomllib
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

from aegischain.domain.models import DeclaredDependency, Ecosystem, ParsedManifest, Scope
from aegischain.engines.dependency.parsers.common import decode_utf8, normalize_pypi_name
from aegischain.exceptions import ParseError


def _bump(parts: list[int], index: int) -> str:
    bumped = parts[: index + 1]
    bumped[index] += 1
    bumped += [0] * (len(parts) - index - 1)
    return ".".join(str(p) for p in bumped)


def _release(version: str) -> list[int]:
    nums = []
    for piece in version.split("."):
        m = re.match(r"\d+", piece)
        if not m:
            break
        nums.append(int(m.group()))
    if not nums:
        raise ValueError(version)
    return nums


def poetry_to_specifier(constraint: str) -> str | None:
    """Translate a Poetry version constraint to a PEP 440 specifier (None = any)."""
    constraint = constraint.strip()
    if constraint in ("", "*"):
        return None
    out: list[str] = []
    for part in (p.strip() for p in constraint.split(",")):
        if not part:
            continue
        if part.startswith("^"):
            rel = _release(part[1:])
            idx = next((i for i, n in enumerate(rel) if n != 0), len(rel) - 1)
            out.append(f">={part[1:]},<{_bump(rel, idx)}")
        elif part.startswith("~") and not part.startswith("~="):
            rel = _release(part[1:])
            idx = 0 if len(rel) == 1 else 1
            out.append(f">={part[1:]},<{_bump(rel, idx)}")
        elif part[0].isdigit():
            out.append(f"=={part}")
        else:
            out.append(part)
    return ",".join(out) or None


def _pep508(entry: str, scope: Scope, path: str, warnings: list[str]) -> DeclaredDependency | None:
    try:
        req = Requirement(entry)
    except InvalidRequirement:
        warnings.append(f"{path}: unparseable requirement skipped: {entry[:80]!r}")
        return None
    specs = list(req.specifier)
    pinned = (
        specs[0].version
        if len(specs) == 1 and specs[0].operator == "==" and "*" not in specs[0].version
        else None
    )
    return DeclaredDependency(
        name=normalize_pypi_name(req.name),
        specifier=str(req.specifier) or None,
        scope=scope,
        ecosystem=Ecosystem.PYPI,
        source_file=path,
        pinned_version=pinned,
    )


def _poetry_table(
    table: dict[str, Any], scope: Scope, path: str, warnings: list[str]
) -> list[DeclaredDependency]:
    out: list[DeclaredDependency] = []
    for name, value in table.items():
        if name.lower() == "python":
            continue
        entry_scope = scope
        constraint: str | None
        if isinstance(value, str):
            constraint = value
        elif isinstance(value, dict):
            constraint = value.get("version") if isinstance(value.get("version"), str) else None
            if value.get("optional") is True:
                entry_scope = Scope.OPTIONAL
            if constraint is None:
                warnings.append(f"{path}: {name} uses a non-registry source; version unknown")
        else:
            warnings.append(f"{path}: {name} has multiple constraints; not evaluated")
            constraint = None
        try:
            spec = poetry_to_specifier(constraint) if constraint else None
        except ValueError:
            warnings.append(f"{path}: cannot interpret constraint {constraint!r} for {name}")
            spec = None
        pinned = (
            spec[2:]
            if spec and spec.startswith("==") and "," not in spec and "*" not in spec
            else None
        )
        out.append(
            DeclaredDependency(
                name=normalize_pypi_name(name),
                specifier=spec,
                scope=entry_scope,
                ecosystem=Ecosystem.PYPI,
                source_file=path,
                pinned_version=pinned,
            )
        )
    return out


class PyprojectParser:
    def parse(self, content: bytes, path: str) -> ParsedManifest:
        try:
            data = tomllib.loads(decode_utf8(content, path))
        except tomllib.TOMLDecodeError as exc:
            raise ParseError(f"{path}: invalid TOML: {exc}") from exc
        warnings: list[str] = []
        declared: list[DeclaredDependency] = []

        project = data.get("project", {})
        if isinstance(project, dict):
            for entry in project.get("dependencies", []) or []:
                if isinstance(entry, str) and (d := _pep508(entry, Scope.RUNTIME, path, warnings)):
                    declared.append(d)
            optional = project.get("optional-dependencies", {}) or {}
            if isinstance(optional, dict):
                for entries in optional.values():
                    for entry in entries or []:
                        if isinstance(entry, str) and (
                            d := _pep508(entry, Scope.OPTIONAL, path, warnings)
                        ):
                            declared.append(d)
        groups = data.get("dependency-groups", {}) or {}
        if isinstance(groups, dict):
            for entries in groups.values():
                for entry in entries or []:
                    if isinstance(entry, str) and (d := _pep508(entry, Scope.DEV, path, warnings)):
                        declared.append(d)

        poetry = (
            data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
        )
        if isinstance(poetry, dict):
            declared += _poetry_table(
                poetry.get("dependencies", {}) or {}, Scope.RUNTIME, path, warnings
            )
            declared += _poetry_table(
                poetry.get("dev-dependencies", {}) or {}, Scope.DEV, path, warnings
            )
            for gname, group in (poetry.get("group", {}) or {}).items():
                scope = Scope.RUNTIME if gname == "main" else Scope.DEV
                if isinstance(group, dict):
                    declared += _poetry_table(
                        group.get("dependencies", {}) or {}, scope, path, warnings
                    )
        if not declared:
            warnings.append(f"{path}: no dependency declarations found")
        return ParsedManifest(path, Ecosystem.PYPI, tuple(declared), tuple(warnings))
