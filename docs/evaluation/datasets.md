# Datasets

| Dataset | Source | Generated | Size | Ground truth |
|---|---|---|---|---|
| `examples/python-project` | hand-written fixture (`pyproject.toml` + `poetry.lock`) | committed | 13 components (4 direct) | asserted in `tests/unit/dependency/test_service.py` |
| `examples/node-project` | hand-written fixture (`package.json` + `package-lock.json` v3, nested duplicate `debug`/`ms`) | committed | 9 components (3 direct) | asserted in the same test |
| synthetic npm / Poetry graphs | `benchmarks/datasets.py`, seeded `random.Random` | at run time | 20, 200, 1,000 (evaluation); 50 / 1,000 / 10,000 npm and 50 / 1,000 / 5,000 Poetry (benchmark) | exact: the generator emits packages, edges and the direct set |
| OSV range cases | authored in `benchmarks/run_evaluation.py` | in source | 22 | hand-derived |
| License expressions | authored | in source | 24 | hand-derived |
| Provenance evidence | authored (DSSE-wrapped SLSA v1 statements) | in source | 11 | hand-derived |

Notes: example lockfile hashes and `integrity` values are **synthetic** (derived from the package
name) and the advisory IDs in tests (`AEGIS-TEST-*`) are fictional. Fixtures contain no real
vulnerability claims. Data collection date for synthetic sets: generated deterministically at run
time (seeds 1-5, 42, 7, 0).
