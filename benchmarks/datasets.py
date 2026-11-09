"""Deterministic synthetic repositories with known ground truth (seeded)."""

from __future__ import annotations

import base64
import hashlib
import json
import random
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class GroundTruth:
    purls: frozenset[str]
    edges: frozenset[tuple[str, str]]
    direct: frozenset[str]


def _graph(n: int, seed: int) -> tuple[list[list[int]], set[int]]:
    rng = random.Random(seed)
    deps = [
        sorted(rng.sample(range(i + 1, n), k=min(rng.randint(0, 3), n - i - 1))) for i in range(n)
    ]
    direct = set(range(max(1, n // 10)))
    return deps, direct


def make_npm(root: Path, n: int, seed: int = 1) -> GroundTruth:
    deps, direct = _graph(n, seed)
    pk: dict[str, dict] = {
        "": {
            "name": "bench",
            "version": "1.0.0",
            "dependencies": {f"pkg-{i}": "1.0.0" for i in sorted(direct)},
        }
    }
    for i in range(n):
        digest = base64.b64encode(hashlib.sha512(f"{i}".encode()).digest()).decode()
        entry = {"version": "1.0.0", "integrity": "sha512-" + digest, "license": "MIT"}
        if deps[i]:
            entry["dependencies"] = {f"pkg-{j}": "1.0.0" for j in deps[i]}
        pk[f"node_modules/pkg-{i}"] = entry
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(
        json.dumps({"name": "bench", "dependencies": pk[""]["dependencies"]})
    )
    (root / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": pk}))

    def purl(i: int) -> str:
        return f"pkg:npm/pkg-{i}@1.0.0"

    return GroundTruth(
        frozenset(purl(i) for i in range(n)),
        frozenset((purl(i), purl(j)) for i in range(n) for j in deps[i]),
        frozenset(purl(i) for i in direct),
    )


def make_poetry(root: Path, n: int, seed: int = 1) -> GroundTruth:
    deps, direct = _graph(n, seed)
    lock = []
    for i in range(n):
        lock.append(f'[[package]]\nname = "pkg-{i}"\nversion = "1.0.{i}"\ngroups = ["main"]\n')
        if deps[i]:
            lock.append("[package.dependencies]\n" + "".join(f'pkg-{j} = "*"\n' for j in deps[i]))
    root.mkdir(parents=True, exist_ok=True)
    (root / "poetry.lock").write_text("\n".join(lock))
    (root / "pyproject.toml").write_text(
        '[project]\nname = "bench"\ndependencies = ['
        + ", ".join(f'"pkg-{i}"' for i in sorted(direct))
        + "]\n"
    )

    def purl(i: int) -> str:
        return f"pkg:pypi/pkg-{i}@1.0.{i}"

    return GroundTruth(
        frozenset(purl(i) for i in range(n)),
        frozenset((purl(i), purl(j)) for i in range(n) for j in deps[i]),
        frozenset(purl(i) for i in direct),
    )
