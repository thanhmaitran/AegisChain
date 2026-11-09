# Testing

```
tests/
  unit/<engine>/        parsers, graph, SBOM, vulnerability, license, integrity, provenance, policy,
                        infrastructure (archive, repository), utils (serialisation round trip)
  property/             seeded randomised properties (stdlib) + Hypothesis properties (if installed)
  security/             hostile repositories, policy-file attacks
  integration/          repository contract tests (SQLite always; PostgreSQL when configured)
  end_to_end/           full pipeline + CLI
apps/api/tests/         API service layer (always) and HTTP layer (needs fastapi + httpx)
```

Run: `pytest` (or `python -m unittest discover -s tests -t .` with `PYTHONPATH=packages/aegischain-core/src:apps/api/src`;
tests are `unittest.TestCase` classes so both runners work).

## Status when this version was produced

| Suite | Result in the authoring sandbox |
|---|---|
| `tests/` + API service tests | 203 tests passing; 3 skipped (Hypothesis, PostgreSQL and FastAPI/httpx not available) |
| `apps/api/tests/test_http_api.py` | not run (FastAPI/httpx unavailable offline) |
| PostgreSQL contract test | not run |
| `ruff`, `mypy`, `vitest`, `tsc` with real deps | not run |
| `python benchmarks/run_evaluation.py` | all evaluations match ground truth |

## What the tests assert about fail-safe behaviour

* OSV outage / skipped / partial lookup -> never PASS.
* No provenance / unverifiable signature -> INDETERMINATE (WARN if the policy does not require it).
* Unparseable manifest -> INDETERMINATE, other files still analysed.
* Adding a blocking vulnerability never improves a decision (property test).
* Decision independent of finding order and identical across repeated runs.
* Defects found while writing tests and fixed: `"dependencies": []` accepted instead of rejected;
  empty policy file silently defaulted; zip entries without file-type bits rejected as links.

Coverage is a means, not a target: priority is decision logic, security boundaries and failure
handling. Run `make cov` for a report.
