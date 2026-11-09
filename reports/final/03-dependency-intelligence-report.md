# 03 - Dependency Intelligence Report

* **Supported formats:** `requirements*.txt`, `pyproject.toml` (PEP 621, PEP 735 groups, Poetry),
  `poetry.lock`, `uv.lock`, `package.json`, `package-lock.json` v2/v3. Recognised but unsupported
  files (pnpm, yarn, Pipfile.lock, Go, Cargo, Maven, Gradle) are reported, never silently ignored.
* **Parser design:** parsers take bytes and return declared dependencies or resolved lockfile
  packages; they never touch the filesystem. Poetry constraints (`^`, `~`) are translated to PEP 440
  for consistency checks. npm resolution follows Node's `node_modules` lookup.
* **Graph construction and classification:** `networkx.DiGraph`, multi-source BFS depth, SCC cycle
  detection. Direct/transitive provenance per source is tabulated in
  `docs/architecture/dependency-graph-design.md`. No transitive dependency is ever inferred from
  names.
* **Conflicts vs duplicates:** several PyPI versions -> `VERSION_CONFLICT` (WARN); several npm
  versions -> `DUPLICATE_VERSIONS` (info).
* **Evaluation** (`reports/dependency-analysis/`): exact match (precision = recall = 1.0, 0 FP/FN)
  on six generated lockfiles (20-1,000 packages, npm and Poetry), 6/6 exact; 3,000/3,000 random
  byte inputs rejected cleanly (only `ParseError`).
* **Limits:** npm ranges not evaluated against locked versions; lockfile v1 rejected; Poetry/uv
  multi-file hashes omitted.
