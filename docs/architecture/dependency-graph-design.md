# Dependency Graph Design

## Construction

1. Parsers produce either `ParsedManifest` (declared requirements) or `ParsedLockfile`
   (resolved packages with already-resolved edges).
2. Files are grouped by (directory, ecosystem). A group with a lockfile uses the lockfile as the
   source of truth; a group without one falls back to declared dependencies and emits `NO_LOCKFILE`.
   **Transitive dependencies are never inferred from package names.**
3. Groups are merged by Package URL; `direct` is OR-ed, the most permissive scope wins.
4. A `networkx.DiGraph` is built (edge = *depends on*); edges to unknown nodes are dropped.

## npm resolution

`package-lock.json` (v2/v3) lists packages by install path. A dependency `d` of the package at
`node_modules/a/node_modules/b` is resolved Node-style: `…/b/node_modules/d`, then
`node_modules/a/node_modules/d`, then `node_modules/d`. Direct dependencies are the resolved targets
of the root entry. Workspace/link entries are first-party and skipped (noted as an info finding).

## Direct vs transitive

| Source | How `direct` is known |
|---|---|
| package-lock.json | resolved targets of the root package's dependency tables |
| uv.lock | dependencies of the virtual/editable root project |
| poetry.lock + pyproject.toml | names declared in the manifest |
| poetry.lock alone | inferred from graph roots; flagged `DIRECT_INFERRED` (WARN) |
| manifest only | all declared entries; flagged `NO_LOCKFILE` (WARN) |

## Analyses

| Analysis | Algorithm | Finding |
|---|---|---|
| Depth | multi-source BFS from direct nodes | `UNREACHABLE` (WARN) for depth `None` |
| Cycles | strongly connected components with size > 1 or self-loop | `CYCLE` (info) |
| Version conflict | >1 resolved version of a name in PyPI | `VERSION_CONFLICT` (WARN) |
| Duplicates | >1 resolved version of a name in npm | `DUPLICATE_VERSIONS` (info; allowed by npm) |
| Consistency | PEP 440 specifier vs locked version | `LOCK_MISMATCH`, `DECLARED_NOT_LOCKED` (WARN) |
| Unresolved | lock entry requires a package absent from the lock | `UNRESOLVED_DEPENDENCY` (WARN) |

All operations are linear in nodes + edges (SCC is Tarjan/Kosaraju-style; no `simple_cycles`
enumeration, which can be exponential on hostile graphs). See `reports/performance`.

## Visualisation payload

`graph_view()` returns `{nodes: [{id, name, version, direct, depth, scope, ecosystem}], edges}`.
The dashboard lays out columns by depth with React Flow.
