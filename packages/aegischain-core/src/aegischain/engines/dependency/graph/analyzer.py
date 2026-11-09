"""Graph analyses: cycles, duplicate versions, conflicts."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

import networkx as nx

from aegischain.domain.models import Component, Ecosystem, Finding
from aegischain.domain.status import Status


def find_cycles(graph: nx.DiGraph) -> list[list[str]]:
    """Strongly connected components with more than one node, or self-loops."""
    cycles = []
    for comp in nx.strongly_connected_components(graph):
        nodes = sorted(comp)
        if len(nodes) > 1 or graph.has_edge(nodes[0], nodes[0]):
            cycles.append(nodes)
    return sorted(cycles)


def version_findings(components: Iterable[Component]) -> list[Finding]:
    """Distinguish a version *conflict* from a *duplicate*.

    * PyPI: one environment holds one version per distribution, so several resolved
      versions of a name is a CONFLICT (WARN).
    * npm: nested ``node_modules`` legitimately hold several versions, so this is a
      DUPLICATE_VERSIONS informational finding (PASS).
    """
    versions: dict[tuple[Ecosystem, str], set[str]] = defaultdict(set)
    for c in components:
        if c.version is not None:
            versions[(c.ecosystem, c.name)].add(c.version)
    findings: list[Finding] = []
    for (eco, name), vs in sorted(versions.items(), key=lambda kv: (kv[0][0].value, kv[0][1])):
        if len(vs) < 2:
            continue
        listing = ", ".join(sorted(vs))
        if eco is Ecosystem.PYPI:
            findings.append(
                Finding(
                    "VERSION_CONFLICT",
                    Status.WARN,
                    f"{name} resolves to multiple versions in a single-version ecosystem: {listing}",
                    (name,),
                )
            )
        else:
            findings.append(
                Finding(
                    "DUPLICATE_VERSIONS",
                    Status.PASS,
                    f"{name} is present in multiple versions (allowed by npm): {listing}",
                    (name,),
                )
            )
    return findings
