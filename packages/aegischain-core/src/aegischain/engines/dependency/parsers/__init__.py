"""Parser registry."""

from __future__ import annotations

from aegischain.domain.interfaces import ManifestParser
from aegischain.engines.dependency.parsers.node_parsers import NpmLockParser, PackageJsonParser
from aegischain.engines.dependency.parsers.pyproject_parser import PyprojectParser
from aegischain.engines.dependency.parsers.python_locks import PoetryLockParser, UvLockParser
from aegischain.engines.dependency.parsers.requirements_parser import RequirementsParser


def get_parser(filename: str) -> ManifestParser | None:
    if filename == "pyproject.toml":
        return PyprojectParser()
    if filename == "poetry.lock":
        return PoetryLockParser()
    if filename == "uv.lock":
        return UvLockParser()
    if filename == "package.json":
        return PackageJsonParser()
    if filename in ("package-lock.json", "npm-shrinkwrap.json"):
        return NpmLockParser()
    if filename.endswith(".txt"):
        return RequirementsParser()
    return None
