# Evaluation Methodology

Each engine is evaluated separately against explicit ground truth; there is deliberately **no
aggregate "accuracy" score for the platform**.

| Area | Evaluation | Ground truth source | Metric |
|---|---|---|---|
| Dependency parsing + graph | `graph-ground-truth` | generator knows the exact packages, edges and direct set | precision / recall / FP / FN for components, edges, direct set |
| Parser robustness | `parser-fuzz-random-bytes` | contract: only `ParseError` may escape | unhandled exceptions = 0 |
| SBOM | `structural-validity-and-coverage` | component count in = components out | structural validity, input-order independence, coverage |
| Vulnerability matching | `affected-range-matching` | 22 authored OSV-range cases with hand-derived expectations | exact verdict (affected / not / unknown) |
| CVSS | `cvss-v3-reference-vectors` | published scores for well-known vectors | exact base score |
| License | `license-expression-evaluation` | 24 authored expressions incl. malformed | exact status |
| Integrity | `integrity-digest-verification` | 500 random files: unmodified accepted, single-bit flip detected; edge cases | accept / detect counts |
| Provenance | `evidence-classification` | 11 crafted evidence sets | exact status |
| Policy | `decision-table`, `determinism-10-runs` | 10 authored scenarios; 10 identical runs | exact decision; digest equality |

Run everything: `python benchmarks/run_evaluation.py` (exit code 1 if any evaluation deviates).
Outputs: `reports/<area>/*.json` and `reports/final/evaluation-summary.md`.

## What this evaluation shows - and does not show

* It shows the engines implement the specified semantics, including edge cases and failure paths,
  and that they are deterministic.
* It does **not** measure false-positive/negative rates against real-world advisories: the
  vulnerability evaluation tests the *matching logic* on authored records, not OSV's data quality
  or coverage. A study on real repositories with a labelled set of known-vulnerable versions is
  future work.
* Because the author wrote both the cases and the code, the cases can share blind spots. One
  authored expectation was found to be wrong during evaluation (an ill-formed range with `fixed`
  below `introduced`); the code was right and the case was replaced.
* The signature backend is a test double; Sigstore behaviour is not part of this evaluation.
