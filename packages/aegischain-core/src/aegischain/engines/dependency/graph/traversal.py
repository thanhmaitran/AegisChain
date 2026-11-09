"""Traversal helpers over the dependency graph."""

from __future__ import annotations

from collections import deque

import networkx as nx


def depths_from_roots(graph: nx.DiGraph, roots: set[str]) -> dict[str, int]:
    """Minimal distance from any root; roots themselves have depth 1."""
    depth = {r: 1 for r in roots if r in graph}
    queue = deque(sorted(depth))
    while queue:
        node = queue.popleft()
        for nxt in sorted(graph.successors(node)):
            if nxt not in depth:
                depth[nxt] = depth[node] + 1
                queue.append(nxt)
    return depth


def transitive_dependencies(graph: nx.DiGraph, node: str) -> set[str]:
    return set(nx.descendants(graph, node))


def dependents(graph: nx.DiGraph, node: str) -> set[str]:
    """Everything that (transitively) depends on ``node``."""
    return set(nx.ancestors(graph, node))
