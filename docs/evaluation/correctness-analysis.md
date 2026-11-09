# Correctness Analysis

Results of `python benchmarks/run_evaluation.py` (see `evaluation-methodology.md` for scope).

## Summary


| Area | Evaluation | Passed | Total |
|---|---|---|---|
| dependency-analysis | graph-ground-truth | 6 | 6 |
| sbom-validation | structural-validity-and-coverage | 4 | 4 |
| vulnerability-analysis | affected-range-matching | 22 | 22 |
| vulnerability-analysis | cvss-v3-reference-vectors | 8 | 8 |
| vulnerability-analysis | license-expression-evaluation | 24 | 24 |
| provenance-verification | integrity-digest-verification | 1004 | 1004 |
| provenance-verification | evidence-classification | 11 | 11 |
| policy-evaluation | decision-table | 10 | 10 |
| policy-evaluation | determinism-10-runs | 1 | 1 |
| dependency-analysis | parser-fuzz-random-bytes | 3000 | 3000 |

## Dependency graph ground truth

| Dataset | Components P / R | Edges P / R | Direct P / R | FP / FN (all sets) |
|---|---|---|---|---|
| npm-20-seed1 | 1.0 / 1.0 | 1.0 / 1.0 | 1.0 / 1.0 | 0 / 0 |
| npm-200-seed2 | 1.0 / 1.0 | 1.0 / 1.0 | 1.0 / 1.0 | 0 / 0 |
| npm-1000-seed3 | 1.0 / 1.0 | 1.0 / 1.0 | 1.0 / 1.0 | 0 / 0 |
| poetry-20-seed1 | 1.0 / 1.0 | 1.0 / 1.0 | 1.0 / 1.0 | 0 / 0 |
| poetry-200-seed2 | 1.0 / 1.0 | 1.0 / 1.0 | 1.0 / 1.0 | 0 / 0 |
| poetry-1000-seed3 | 1.0 / 1.0 | 1.0 / 1.0 | 1.0 / 1.0 | 0 / 0 |

Precision/recall of 1.0 here means the parsers and graph builder reproduce the generator's exact
packages, edges and direct set for lockfiles of 20-1,000 packages in two ecosystems. It does not
imply parity with every real-world lockfile variant (see `docs/security/limitations.md`).

## Findings worth noting

* **Tests written during development found three real defects**: an empty
  `dependencies` array accepted as "no dependencies", an empty policy file silently turned into the
  default policy, and valid zip files (no file-type bits in the attributes) rejected as if they
  contained links. All three are fixed and have regression tests.
* **Integrity**: 500/500 unmodified files accepted and 500/500 single-bit modifications detected,
  plus the missing/invalid/empty-file edge cases (1,004 checks).
* **Fail-safe**: the policy decision table includes "offline" (no OSV lookup) and confirms the
  decision is `INDETERMINATE`, never `PASS`.
* **Fuzzing**: 3,000 random byte strings across the six parsers produced no unhandled exception
  (every rejection was a `ParseError`).
