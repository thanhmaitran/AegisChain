"""Dependency intelligence service: parse -> resolve -> graph -> findings."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from aegischain.domain.models import (
    Component,
    DeclaredDependency,
    DependencyResult,
    Ecosystem,
    FileKind,
    Finding,
    IngestionResult,
    ParsedLockfile,
    ParsedManifest,
    ResolvedPackage,
    Scope,
)
from aegischain.domain.status import Status, worst
from aegischain.engines.dependency.graph.analyzer import find_cycles, version_findings
from aegischain.engines.dependency.graph.builder import build_digraph
from aegischain.engines.dependency.graph.traversal import depths_from_roots
from aegischain.engines.dependency.parsers import get_parser
from aegischain.engines.dependency.parsers.common import (
    normalize_pypi_name,
    npm_purl,
    pypi_purl,
)
from aegischain.engines.ingestion.scanner import load_file
from aegischain.exceptions import ParseError, ValidationError

_INFO_MARKERS = ("does not identify direct", "first-party and were skipped")
_SCOPE_ORDER = {Scope.RUNTIME: 0, Scope.OPTIONAL: 1, Scope.DEV: 2}


def make_purl(eco: Ecosystem, name: str, version: str | None) -> str:
    return pypi_purl(name, version) if eco is Ecosystem.PYPI else npm_purl(name, version)


def _norm(eco: Ecosystem, name: str) -> str:
    return normalize_pypi_name(name) if eco is Ecosystem.PYPI else name


@dataclass
class _Acc:
    name: str
    version: str | None
    eco: Ecosystem
    purl: str
    direct: bool
    scope: Scope
    deps: set[str] = field(default_factory=set)
    hashes: dict[str, str] = field(default_factory=dict)
    license: str | None = None
    sources: set[str] = field(default_factory=set)


def _group_lock(
    lock: ParsedLockfile,
    declared: list[DeclaredDependency],
    include_dev: bool,
    findings: list[Finding],
) -> list[_Acc]:
    eco = lock.ecosystem
    pkgs: list[ResolvedPackage] = [
        p for p in lock.packages if include_dev or p.scope is not Scope.DEV
    ]
    purl_of = {p.key: make_purl(eco, p.name, p.version) for p in pkgs}
    if lock.direct_keys is not None:
        direct_keys = {k for k in lock.direct_keys if k in purl_of}
    else:
        names = {_norm(eco, d.name) for d in declared}
        if names:
            direct_keys = {p.key for p in pkgs if _norm(eco, p.name) in names}
        else:
            incoming = {t for p in pkgs for t in p.depends_on}
            direct_keys = {p.key for p in pkgs if p.key not in incoming}
            findings.append(
                Finding(
                    "DIRECT_INFERRED",
                    Status.WARN,
                    f"{lock.source_file}: no manifest found; direct dependencies inferred "
                    "from graph roots and may be inaccurate",
                )
            )
    # Manifest/lockfile consistency.
    locked: dict[str, list[ResolvedPackage]] = defaultdict(list)
    for p in lock.packages:
        locked[_norm(eco, p.name)].append(p)
    for d in declared:
        if not include_dev and d.scope is Scope.DEV:
            continue
        name = _norm(eco, d.name)
        if name not in locked:
            findings.append(
                Finding(
                    "DECLARED_NOT_LOCKED",
                    Status.WARN,
                    f"{d.name} is declared in {d.source_file} but absent from {lock.source_file}",
                    (d.name,),
                )
            )
        elif eco is Ecosystem.PYPI and d.specifier:
            try:
                spec = SpecifierSet(d.specifier)
                ok = any(spec.contains(Version(p.version), prereleases=True) for p in locked[name])
            except (InvalidSpecifier, InvalidVersion):
                continue
            if not ok:
                findings.append(
                    Finding(
                        "LOCK_MISMATCH",
                        Status.WARN,
                        f"{d.name}{d.specifier} in {d.source_file} is not satisfied by "
                        f"{lock.source_file} ({', '.join(sorted(p.version for p in locked[name]))})",
                        (d.name,),
                    )
                )
    out: list[_Acc] = []
    for p in pkgs:
        for dep in p.unresolved_dependencies:
            findings.append(
                Finding(
                    "UNRESOLVED_DEPENDENCY",
                    Status.WARN,
                    f"{p.name}@{p.version} requires {dep} which is not in {lock.source_file}",
                    (purl_of[p.key],),
                )
            )
        out.append(
            _Acc(
                p.name,
                p.version,
                eco,
                purl_of[p.key],
                p.key in direct_keys,
                p.scope,
                {purl_of[t] for t in p.depends_on if t in purl_of},
                dict(p.hashes),
                p.declared_license,
                {lock.source_file},
            )
        )
    return out


def _group_manifest(
    declared: list[DeclaredDependency], include_dev: bool, findings: list[Finding]
) -> list[_Acc]:
    out: list[_Acc] = []
    if declared:
        findings.append(
            Finding(
                "NO_LOCKFILE",
                Status.WARN,
                "No lockfile found next to "
                + ", ".join(sorted({d.source_file for d in declared}))
                + "; transitive dependencies are unknown and were NOT inferred",
            )
        )
    for d in declared:
        if not include_dev and d.scope is Scope.DEV:
            continue
        name = _norm(d.ecosystem, d.name)
        out.append(
            _Acc(
                name,
                d.pinned_version,
                d.ecosystem,
                make_purl(d.ecosystem, name, d.pinned_version),
                True,
                d.scope,
                set(),
                dict(d.hashes),
                None,
                {d.source_file},
            )
        )
    return out


def _merge(accs: list[_Acc]) -> dict[str, _Acc]:
    merged: dict[str, _Acc] = {}
    for a in accs:
        m = merged.get(a.purl)
        if m is None:
            merged[a.purl] = a
            continue
        m.direct = m.direct or a.direct
        if _SCOPE_ORDER[a.scope] < _SCOPE_ORDER[m.scope]:
            m.scope = a.scope
        m.deps |= a.deps
        m.sources |= a.sources
        m.hashes = m.hashes or a.hashes
        m.license = m.license or a.license
    return merged


def analyze_dependencies(
    root: Path,
    ingestion: IngestionResult,
    include_dev: bool = True,
    max_file_bytes: int = 10 * 1024 * 1024,
) -> DependencyResult:
    findings: list[Finding] = []
    parsed_files: list[str] = []
    by_dir: dict[tuple[str, Ecosystem], dict[str, list[ParsedManifest | ParsedLockfile]]] = (
        defaultdict(lambda: {"manifest": [], "lock": []})
    )
    for f in ingestion.discovered_files:
        parser = get_parser(f.filename)
        if parser is None or f.ecosystem is None:
            continue
        try:
            parsed = parser.parse(load_file(root, f, max_file_bytes), f.path)
        except (ParseError, ValidationError) as exc:
            findings.append(Finding("PARSE_ERROR", Status.INDETERMINATE, str(exc), (f.path,)))
            continue
        parsed_files.append(f.path)
        for w in parsed.warnings:
            info = any(m in w for m in _INFO_MARKERS)
            findings.append(
                Finding(
                    "PARSER_NOTE" if info else "PARSER_WARNING",
                    Status.PASS if info else Status.WARN,
                    w,
                    (f.path,),
                )
            )
        directory = str(Path(f.path).parent)
        kind = "lock" if f.kind is FileKind.LOCKFILE else "manifest"
        by_dir[(directory, f.ecosystem)][kind].append(parsed)

    accs: list[_Acc] = []
    for (_, _eco), group in sorted(by_dir.items(), key=lambda kv: (kv[0][0], kv[0][1].value)):
        declared = [
            d for m in group["manifest"] if isinstance(m, ParsedManifest) for d in m.declared
        ]
        locks = [lk for lk in group["lock"] if isinstance(lk, ParsedLockfile)]
        if locks:
            for lk in locks:
                accs += _group_lock(lk, declared, include_dev, findings)
        else:
            accs += _group_manifest(declared, include_dev, findings)

    merged = _merge(accs)
    graph = build_digraph(
        Component(
            a.name,
            a.version,
            a.eco,
            a.purl,
            a.direct,
            a.scope,
            tuple(sorted(a.deps)),
            a.hashes,
            a.license,
            None,
            tuple(sorted(a.sources)),
        )
        for a in merged.values()
    )
    depth = depths_from_roots(graph, {p for p, a in merged.items() if a.direct})
    components = tuple(
        Component(
            a.name,
            a.version,
            a.eco,
            a.purl,
            a.direct,
            a.scope,
            tuple(sorted(d for d in a.deps if d in merged)),
            dict(sorted(a.hashes.items())),
            a.license,
            depth.get(a.purl),
            tuple(sorted(a.sources)),
        )
        for _, a in sorted(merged.items())
    )
    findings += version_findings(components)
    for cyc in find_cycles(graph):
        findings.append(
            Finding("CYCLE", Status.PASS, "Dependency cycle: " + " -> ".join(cyc), tuple(cyc))
        )
    unreachable = tuple(c.purl for c in components if c.depth is None)
    if unreachable:
        findings.append(
            Finding(
                "UNREACHABLE",
                Status.WARN,
                f"{len(unreachable)} component(s) are not reachable from any direct dependency",
                unreachable,
            )
        )
    unpinned = tuple(c.purl for c in components if c.version is None)
    if unpinned:
        findings.append(
            Finding(
                "UNPINNED_VERSION",
                Status.WARN,
                f"{len(unpinned)} component(s) have no exact version and cannot be matched "
                "against vulnerability data",
                unpinned,
            )
        )
    if not parsed_files:
        findings.append(
            Finding("NOTHING_PARSED", Status.INDETERMINATE, "No dependency file could be parsed")
        )
    elif not components:
        findings.append(
            Finding("NO_DEPENDENCIES", Status.PASS, "Parsed files declare no dependencies")
        )

    edges = tuple(sorted((c.purl, d) for c in components for d in c.dependencies))
    findings.sort(key=lambda f: (f.code, f.message))
    return DependencyResult(
        components,
        edges,
        tuple(findings),
        tuple(sorted(parsed_files)),
        worst(f.status for f in findings) if findings else Status.PASS,
    )


def graph_view(result: DependencyResult) -> dict[str, object]:
    """Visualisation payload (nodes/edges) consumed by the dashboard graph."""
    return {
        "nodes": [
            {
                "id": c.purl,
                "name": c.name,
                "version": c.version,
                "direct": c.direct,
                "depth": c.depth,
                "scope": c.scope.value,
                "ecosystem": c.ecosystem.value,
            }
            for c in result.components
        ],
        "edges": [{"source": s, "target": t} for s, t in result.edges],
    }
