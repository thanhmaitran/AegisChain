# 07 - Performance Evaluation Report

* **Environment:** Python 3.12.3, Linux-6.18.44-fc-v242-x86_64-with-glibc2.39, 1 CPUs.
* **Datasets:** synthetic seeded dependency DAGs (npm and Poetry lockfiles) of 50 / 1,000 / 5,000-10,000
  components with ground truth (`docs/evaluation/datasets.md`).
* **Methodology:** full offline pipeline (ingestion -> dependency -> SBOM x2 + validation ->
  vulnerability stub -> license -> policy), 5 runs per dataset, each in a fresh process;
  runtime = wall clock of `AnalysisPipeline.run`; memory = child `ru_maxrss`.

| Dataset | Components | Median (s) | Peak RSS (MiB) |
|---|---|---|---|
| npm-small | 50 | 0.007 | 37.4 |
| npm-medium | 1000 | 0.078 | 42.4 |
| npm-large | 10000 | 0.821 | 87.2 |
| poetry-small | 50 | 0.007 | 37.3 |
| poetry-medium | 1000 | 0.084 | 41.3 |
| poetry-large | 5000 | 0.414 | 56.4 |

* **Scalability:** near-linear in components (npm 1,000 -> 10,000: ~10.5x time, ~2x peak RSS).
* **Bottlenecks:** see the per-stage table in `docs/evaluation/benchmark-results.md`.
* **Caveats:** one machine, synthetic data, network excluded (OSV latency would dominate real runs),
  no real-world repository benchmark. Raw data in `reports/performance/benchmark-results.json`.
