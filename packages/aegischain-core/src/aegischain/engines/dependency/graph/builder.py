"""Build a NetworkX directed graph from components (edge = depends-on)."""

from __future__ import annotations

from collections.abc import Iterable

import networkx as nx

from aegischain.domain.models import Component


def build_digraph(components: Iterable[Component]) -> nx.DiGraph:
    graph: nx.DiGraph = nx.DiGraph()
    comps = list(components)
    for c in comps:
        graph.add_node(c.purl, direct=c.direct)
    for c in comps:
        for dep in c.dependencies:
            if dep in graph:  # never create edges to unknown nodes
                graph.add_edge(c.purl, dep)
    return graph
