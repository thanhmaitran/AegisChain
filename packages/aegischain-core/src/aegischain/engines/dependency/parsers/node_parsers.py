"""package.json and package-lock.json (lockfileVersion 2 and 3) parsers."""

from __future__ import annotations

import json
import re
from typing import Any

from aegischain.domain.models import (
    DeclaredDependency,
    Ecosystem,
    ParsedLockfile,
    ParsedManifest,
    ResolvedPackage,
    Scope,
)
from aegischain.engines.dependency.parsers.common import decode_utf8, npm_integrity_to_hash
from aegischain.exceptions import ParseError

_EXACT = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_NON_REGISTRY = (
    "git",
    "file:",
    "link:",
    "workspace:",
    "http:",
    "https:",
    "npm:",
    "github:",
    "/",
    ".",
)
_MAX_JSON_DEPTH = 64


def _load_json(content: bytes, path: str) -> dict[str, Any]:
    try:
        data = json.loads(decode_utf8(content, path))
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ParseError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ParseError(f"{path}: top-level JSON value must be an object")
    return data


class PackageJsonParser:
    def parse(self, content: bytes, path: str) -> ParsedManifest:
        data = _load_json(content, path)
        declared: list[DeclaredDependency] = []
        warnings: list[str] = []
        for field, scope in (
            ("dependencies", Scope.RUNTIME),
            ("devDependencies", Scope.DEV),
            ("optionalDependencies", Scope.OPTIONAL),
        ):
            table = data.get(field)
            if table is None:
                continue
            if not isinstance(table, dict):
                raise ParseError(f"{path}: {field} must be an object")
            for name, spec in table.items():
                if not isinstance(spec, str):
                    warnings.append(f"{path}: {name} has a non-string specifier; ignored")
                    continue
                if spec.startswith(_NON_REGISTRY):
                    warnings.append(f"{path}: {name} uses a non-registry specifier ({spec[:40]})")
                declared.append(
                    DeclaredDependency(
                        name=name,
                        specifier=spec,
                        scope=scope,
                        ecosystem=Ecosystem.NPM,
                        source_file=path,
                        pinned_version=spec if _EXACT.match(spec) else None,
                    )
                )
        if data.get("peerDependencies"):
            warnings.append(f"{path}: peerDependencies are not treated as declared dependencies")
        return ParsedManifest(path, Ecosystem.NPM, tuple(declared), tuple(warnings))


def _resolve(packages: dict[str, Any], owner: str, dep: str) -> str | None:
    """Node resolution: look in owner/node_modules, then climb to parents."""
    base = owner
    while True:
        candidate = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
        if candidate in packages:
            return candidate
        if not base:
            return None
        idx = base.rfind("node_modules/")
        base = base[:idx].rstrip("/") if idx != -1 else ""


class NpmLockParser:
    def parse(self, content: bytes, path: str) -> ParsedLockfile:
        data = _load_json(content, path)
        version = data.get("lockfileVersion")
        packages = data.get("packages")
        if not isinstance(version, int) or version < 2 or not isinstance(packages, dict):
            raise ParseError(
                f"{path}: only lockfileVersion 2 or 3 with a 'packages' map is supported"
            )
        warnings: list[str] = []
        resolved: list[ResolvedPackage] = []
        workspace_count = 0
        for key, entry in packages.items():
            if key == "":
                continue
            if not isinstance(entry, dict):
                raise ParseError(f"{path}: malformed entry {key!r}")
            if entry.get("link") or "node_modules/" not in key:
                workspace_count += 1
                continue
            name: str = (
                entry["name"]
                if isinstance(entry.get("name"), str)
                else key.rsplit("node_modules/", 1)[1]
            )
            ver = entry.get("version")
            if not isinstance(ver, str):
                warnings.append(f"{path}: {key} has no version; skipped")
                continue
            scope = (
                Scope.DEV
                if entry.get("dev")
                else Scope.OPTIONAL
                if (entry.get("optional") or entry.get("devOptional"))
                else Scope.RUNTIME
            )
            deps: list[str] = []
            unresolved: list[str] = []
            for field in ("dependencies", "optionalDependencies", "peerDependencies"):
                table = entry.get(field) or {}
                if not isinstance(table, dict):
                    continue
                for dep in table:
                    target = _resolve(packages, key, dep)
                    if target is not None and target != key and not packages[target].get("link"):
                        deps.append(target)
                    elif field == "dependencies":
                        unresolved.append(dep)
            lic = entry.get("license")
            if isinstance(lic, dict):
                lic = lic.get("type")
            resolved.append(
                ResolvedPackage(
                    key=key,
                    name=name,
                    version=ver,
                    ecosystem=Ecosystem.NPM,
                    scope=scope,
                    depends_on=tuple(sorted(set(deps))),
                    hashes=npm_integrity_to_hash(entry.get("integrity")),
                    declared_license=lic if isinstance(lic, str) and lic else None,
                    unresolved_dependencies=tuple(sorted(unresolved)),
                )
            )
        if workspace_count:
            warnings.append(
                f"{path}: {workspace_count} workspace/link entries are first-party and were skipped"
            )
        root = packages.get("") or {}
        direct: set[str] = set()
        for field in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ):
            table = root.get(field) or {}
            if isinstance(table, dict):
                for dep in table:
                    target = _resolve(packages, "", dep)
                    if target is not None:
                        direct.add(target)
        known = {p.key for p in resolved}
        return ParsedLockfile(
            path, Ecosystem.NPM, tuple(resolved), frozenset(direct & known), tuple(warnings)
        )
