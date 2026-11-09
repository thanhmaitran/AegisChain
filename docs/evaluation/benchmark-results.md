# Benchmark Results

Produced by `python benchmarks/run_benchmarks.py` (5 repetitions per dataset, each in a fresh child
process; peak memory is the child's `ru_maxrss`).

## Environment

* Python 3.12.3
* Platform: Linux-6.18.44-fc-v242-x86_64-with-glibc2.39
* CPUs visible: 1
* Offline pipeline with an empty static vulnerability provider; network latency to OSV is excluded.

## Results

| Dataset | Components | Median runtime (s) | Min / Max (s) | Peak RSS (MiB) | Slowest stage (median s) |
|---|---|---|---|---|---|
| npm-small | 50 | 0.007 | 0.006 / 0.007 | 37.4 | dependency (0.002) |
| npm-medium | 1000 | 0.078 | 0.076 / 0.083 | 42.4 | sbom (0.044) |
| npm-large | 10000 | 0.821 | 0.777 / 0.897 | 87.2 | sbom (0.381) |
| poetry-small | 50 | 0.007 | 0.007 / 0.008 | 37.3 | dependency (0.003) |
| poetry-medium | 1000 | 0.084 | 0.083 / 0.088 | 41.3 | dependency (0.04) |
| poetry-large | 5000 | 0.414 | 0.401 / 0.461 | 56.4 | dependency (0.25) |

Per-stage median seconds:

| Dataset | ingestion | dependency | sbom | vulnerability | license | policy |
|---|---|---|---|---|---|---|
| npm-small | 0.001 | 0.002 | 0.002 | 0.0 | 0.0 | 0.0 |
| npm-medium | 0.002 | 0.021 | 0.044 | 0.0 | 0.003 | 0.0 |
| npm-large | 0.004 | 0.292 | 0.381 | 0.001 | 0.031 | 0.001 |
| poetry-small | 0.001 | 0.003 | 0.001 | 0.0 | 0.0 | 0.0 |
| poetry-medium | 0.001 | 0.04 | 0.034 | 0.0 | 0.001 | 0.0 |
| poetry-large | 0.002 | 0.25 | 0.119 | 0.001 | 0.003 | 0.001 |

## Reading the results

* Runtime and memory grow roughly linearly with component count (npm 1,000 -> 10,000 components:
  about 10x time and about 2x memory). No super-linear behaviour was observed up to 10,000 components.
* Absolute numbers depend on this machine; compare ratios, not seconds, across environments.
* The benchmark excludes network time. A real OSV lookup adds latency proportional to
  ceil(components / 1000) batch requests plus one request per *uncached* advisory.
* The datasets are synthetic seeded DAGs (see `datasets.md`), not real-world repositories; real
  lockfiles have different fan-out and metadata sizes. A benchmark on real public repositories has
  **not** been run.

Raw data: `reports/performance/benchmark-results.json`.
