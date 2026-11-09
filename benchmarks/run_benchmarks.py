"""Performance benchmark: wall time and peak RSS of the full offline pipeline.

Each measurement runs in a fresh child process so peak memory is not polluted by earlier runs.
Usage: python benchmarks/run_benchmarks.py [--repeats 5]
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from datasets import make_npm, make_poetry  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CHILD = r"""
import json, resource, sys, time
sys.path.insert(0, "packages/aegischain-core/src")
from pathlib import Path
from aegischain.application.pipeline import AnalysisPipeline, AnalysisRequest
from aegischain.engines.vulnerability.provider import StaticVulnerabilityProvider
t = time.perf_counter()
out = AnalysisPipeline(StaticVulnerabilityProvider({})).run(AnalysisRequest(Path(sys.argv[1])))
elapsed = time.perf_counter() - t
print(json.dumps({"seconds": elapsed, "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                  "components": len(out.report.dependency.components), "stages": dict(out.report.metrics)}))
"""

DATASETS = [
    ("small", "npm", 50),
    ("medium", "npm", 1000),
    ("large", "npm", 10000),
    ("small", "poetry", 50),
    ("medium", "poetry", 1000),
    ("large", "poetry", 5000),
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=5)
    args = ap.parse_args()
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        for size, kind, n in DATASETS:
            repo = Path(tmp) / f"{kind}-{size}"
            (make_npm if kind == "npm" else make_poetry)(repo, n)
            runs = []
            for _ in range(args.repeats):
                proc = subprocess.run(
                    [sys.executable, "-c", CHILD, str(repo)],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                runs.append(json.loads(proc.stdout))
            secs = [r["seconds"] for r in runs]
            stage_names = runs[0]["stages"].keys()
            results.append(
                {
                    "dataset": f"{kind}-{size}",
                    "ecosystem": kind,
                    "components": runs[0]["components"],
                    "seconds_median": round(statistics.median(secs), 3),
                    "seconds_min": round(min(secs), 3),
                    "seconds_max": round(max(secs), 3),
                    "peak_rss_mib_median": round(
                        statistics.median(r["peak_rss_kib"] for r in runs) / 1024, 1
                    ),
                    "stage_seconds_median": {
                        s: round(statistics.median(r["stages"][s] for r in runs), 3)
                        for s in stage_names
                    },
                    "repeats": args.repeats,
                }
            )
            print(
                results[-1]["dataset"],
                results[-1]["components"],
                results[-1]["seconds_median"],
                "s",
                results[-1]["peak_rss_mib_median"],
                "MiB",
                flush=True,
            )
    env = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "note": "Offline pipeline with an empty static vulnerability provider; network latency to OSV is excluded.",
    }
    out = ROOT / "reports" / "performance"
    out.mkdir(parents=True, exist_ok=True)
    (out / "benchmark-results.json").write_text(
        json.dumps({"environment": env, "results": results}, indent=2) + "\n"
    )
    lines = [
        "| Dataset | Components | Median runtime (s) | Min / Max (s) | Peak RSS (MiB) |",
        "|---|---|---|---|---|",
    ]
    lines += [
        f"| {r['dataset']} | {r['components']} | {r['seconds_median']} | {r['seconds_min']} / {r['seconds_max']} | {r['peak_rss_mib_median']} |"
        for r in results
    ]
    (out / "benchmark-table.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
