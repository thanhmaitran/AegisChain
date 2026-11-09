"""Minimal unused-import checker (stdlib only). Complements, not replaces, ruff."""

from __future__ import annotations

import ast
import sys
from pathlib import Path


def unused(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imported[(a.asname or a.name).split(".")[0]] = node.lineno
        elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
            for a in node.names:
                imported[a.asname or a.name] = node.lineno
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    used |= {
        n.value.id
        for n in ast.walk(tree)
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
    }
    source = path.read_text(encoding="utf-8")
    exported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets
        ):
            exported = {e.value for e in node.value.elts if isinstance(e, ast.Constant)}  # type: ignore[attr-defined]
    return [
        f"{path}:{line}: unused import {name}"
        for name, line in sorted(imported.items(), key=lambda kv: kv[1])
        if name not in used
        and name not in exported
        and f'"{name}"' not in source.replace(f"import {name}", "")
        and path.name != "__init__.py"
    ]


def main(roots: list[str]) -> int:
    problems = [p for r in roots for f in sorted(Path(r).rglob("*.py")) for p in unused(f)]
    print("\n".join(problems) or "no unused imports")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:] or ["packages", "tests", "apps"]))
