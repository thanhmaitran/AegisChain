"""poetry.lock and uv.lock parsers."""

from __future__ import annotations

import tomllib
from collections import defaultdict, deque
from typing import Any

from aegischain.domain.models import Ecosystem, ParsedLockfile, ResolvedPackage, Scope
from aegischain.engines.dependency.parsers.common import decode_utf8, normalize_pypi_name
from aegischain.exceptions import ParseError


def _load(content: bytes, path: str) -> dict[str, Any]:
    try:
        return tomllib.loads(decode_utf8(content, path))
    except tomllib.TOMLDecodeError as exc:
        raise ParseError(f"{path}: invalid TOML: {exc}") from exc


class PoetryLockParser:
    def parse(self, content: bytes, path: str) -> ParsedLockfile:
        data = _load(content, path)
        entries = data.get("package")
        if not isinstance(entries, list):
            raise ParseError(f"{path}: no [[package]] entries")
        by_name: dict[str, list[str]] = defaultdict(list)
        rows: list[tuple[str, str, str, dict[str, Any]]] = []
        for e in entries:
            if not isinstance(e, dict) or "name" not in e or "version" not in e:
                raise ParseError(f"{path}: package entry without name/version")
            name = normalize_pypi_name(str(e["name"]))
            key = f"{name}@{e['version']}"
            by_name[name].append(key)
            rows.append((key, name, str(e["version"]), e))
        packages: list[ResolvedPackage] = []
        warnings: list[str] = []
        for key, name, version, e in rows:
            deps: list[str] = []
            for dep in e.get("dependencies") or {}:
                targets = by_name.get(normalize_pypi_name(dep), [])
                deps += targets  # optional dependencies may legitimately be absent
            groups = e.get("groups")
            category = e.get("category")
            if (isinstance(groups, list) and "main" in groups) or category == "main":
                scope = Scope.RUNTIME
            elif e.get("optional") is True:
                scope = Scope.OPTIONAL
            else:
                scope = Scope.DEV if (groups or category) else Scope.RUNTIME
            files = e.get("files") or []
            hashes: dict[str, str] = {}
            if len(files) == 1 and isinstance(files[0], dict):
                algo, _, digest = str(files[0].get("hash", "")).partition(":")
                if algo and digest:
                    hashes[algo] = digest
            packages.append(
                ResolvedPackage(
                    key, name, version, Ecosystem.PYPI, scope, tuple(sorted(set(deps))), hashes
                )
            )
        warnings.append(
            f"{path}: lockfile does not identify direct dependencies; "
            "they are taken from pyproject.toml when available"
        )
        return ParsedLockfile(path, Ecosystem.PYPI, tuple(packages), None, tuple(warnings))


class UvLockParser:
    def parse(self, content: bytes, path: str) -> ParsedLockfile:
        data = _load(content, path)
        entries = data.get("package")
        if not isinstance(entries, list):
            raise ParseError(f"{path}: no [[package]] entries")
        by_name: dict[str, list[tuple[str, str]]] = defaultdict(list)
        roots: list[dict[str, Any]] = []
        regular: list[tuple[str, str, str, dict[str, Any]]] = []
        for e in entries:
            if not isinstance(e, dict) or "name" not in e:
                raise ParseError(f"{path}: package entry without name")
            source = e.get("source") or {}
            if isinstance(source, dict) and ("virtual" in source or "editable" in source):
                roots.append(e)
                continue
            if "version" not in e:
                raise ParseError(f"{path}: package {e['name']} has no version")
            name = normalize_pypi_name(str(e["name"]))
            key = f"{name}@{e['version']}"
            by_name[name].append((str(e["version"]), key))
            regular.append((key, name, str(e["version"]), e))

        def resolve(dep: dict[str, Any]) -> list[str]:
            cands = by_name.get(normalize_pypi_name(str(dep.get("name", ""))), [])
            if "version" in dep:
                cands = [c for c in cands if c[0] == str(dep["version"])]
            return [k for _, k in cands]

        # Scope propagation from the root project(s).
        runtime_seeds: list[str] = []
        optional_seeds: list[str] = []
        dev_seeds: list[str] = []
        for r in roots:
            for d in r.get("dependencies") or []:
                runtime_seeds += resolve(d)
            for group in (r.get("optional-dependencies") or {}).values():
                for d in group:
                    optional_seeds += resolve(d)
            for group in (r.get("dev-dependencies") or {}).values():
                for d in group:
                    dev_seeds += resolve(d)
        edges = {
            k: [t for d in (e.get("dependencies") or []) for t in resolve(d)]
            for k, _, _, e in regular
        }

        def reach(seeds: list[str]) -> set[str]:
            seen, queue = set(seeds), deque(seeds)
            while queue:
                for nxt in edges.get(queue.popleft(), []):
                    if nxt not in seen:
                        seen.add(nxt)
                        queue.append(nxt)
            return seen

        runtime, optional = reach(runtime_seeds), reach(optional_seeds)
        packages = []
        for key, name, version, _ in regular:
            scope = (
                Scope.RUNTIME
                if key in runtime
                else Scope.OPTIONAL
                if key in optional
                else Scope.DEV
            )
            packages.append(
                ResolvedPackage(
                    key, name, version, Ecosystem.PYPI, scope, tuple(sorted(set(edges[key])))
                )
            )
        direct = frozenset(runtime_seeds + optional_seeds + dev_seeds) if roots else None
        warnings: tuple[str, ...] = ()
        if not roots:
            warnings = (f"{path}: root project not found; direct dependencies unknown",)
        return ParsedLockfile(path, Ecosystem.PYPI, tuple(packages), direct, warnings)
