"""Repository ingestion engine (Phase 2).

Safely discovers manifests and lockfiles in an *untrusted* repository directory.

Security properties:
* never executes or imports repository code, never installs anything;
* never follows symbolic links (files or directories);
* every candidate path is re-validated to live under the resolved root;
* credential-like files are never opened (only their relative names are recorded);
* limits on file count, directory depth and per-file size;
* each discovered file is hashed once; later stages re-read it through
  :func:`load_file`, which verifies the hash (detects TOCTOU modification).
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from aegischain.domain.models import (
    DiscoveredFile,
    Ecosystem,
    FileKind,
    IngestionResult,
    IngestionStatus,
)
from aegischain.exceptions import IngestionError, ValidationError
from aegischain.utils.serialization import sha256_text


@dataclass(frozen=True)
class IngestionLimits:
    max_files: int = 50_000
    max_file_bytes: int = 10 * 1024 * 1024
    max_depth: int = 16


@dataclass(frozen=True)
class RepositoryInput:
    root_path: Path
    include_dev_dependencies: bool = True
    limits: IngestionLimits = field(default_factory=IngestionLimits)


SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".idea",
        ".vscode",
    }
)

# Credential-like files: never opened, never parsed.
SENSITIVE_PATTERNS = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.kdbx",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials",
    "credentials.*",
    "*.secret",
    "secrets.*",
)

_SUPPORTED: dict[str, tuple[Ecosystem, FileKind]] = {
    "pyproject.toml": (Ecosystem.PYPI, FileKind.MANIFEST),
    "poetry.lock": (Ecosystem.PYPI, FileKind.LOCKFILE),
    "uv.lock": (Ecosystem.PYPI, FileKind.LOCKFILE),
    "package.json": (Ecosystem.NPM, FileKind.MANIFEST),
    "package-lock.json": (Ecosystem.NPM, FileKind.LOCKFILE),
    "npm-shrinkwrap.json": (Ecosystem.NPM, FileKind.LOCKFILE),
}
_REQUIREMENTS = re.compile(r"^requirements[-_.a-zA-Z0-9]*\.txt$")
_UNSUPPORTED: dict[str, Ecosystem | None] = {
    "pnpm-lock.yaml": Ecosystem.NPM,
    "yarn.lock": Ecosystem.NPM,
    "Pipfile.lock": Ecosystem.PYPI,
    "go.mod": None,
    "go.sum": None,
    "Cargo.lock": None,
    "pom.xml": None,
    "build.gradle": None,
    "build.gradle.kts": None,
}


def is_sensitive(filename: str) -> bool:
    lowered = filename.lower()
    return any(fnmatch.fnmatch(lowered, pattern) for pattern in SENSITIVE_PATTERNS)


def classify(
    filename: str, parent_name: str = ""
) -> tuple[Ecosystem | None, FileKind, bool] | None:
    """Return (ecosystem, kind, supported) for recognised dependency files, else None."""
    if filename in _SUPPORTED:
        eco, kind = _SUPPORTED[filename]
        return eco, kind, True
    if _REQUIREMENTS.match(filename):
        return Ecosystem.PYPI, FileKind.MANIFEST, True
    if parent_name == "requirements" and filename.endswith(".txt"):
        return Ecosystem.PYPI, FileKind.MANIFEST, True
    if filename in _UNSUPPORTED:
        return _UNSUPPORTED[filename], FileKind.LOCKFILE, False
    return None


def _read_bounded(path: Path, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValidationError(f"{path.name}: exceeds {max_bytes} byte limit")
    return data


def scan_repository(inp: RepositoryInput) -> IngestionResult:
    """Discover supported manifests/lockfiles under ``inp.root_path``."""
    limits = inp.limits
    try:
        root = Path(inp.root_path).resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise IngestionError(f"Repository path does not exist: {inp.root_path}") from exc
    if not root.is_dir():
        raise IngestionError(f"Repository path is not a directory: {inp.root_path}")

    warnings: list[str] = []
    errors: list[str] = []
    discovered: list[DiscoveredFile] = []
    unsupported: list[str] = []
    sensitive: list[str] = []
    examined = 0
    truncated = False

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(dirpath)
        rel_dir = current.relative_to(root)
        depth = len(rel_dir.parts)

        kept: list[str] = []
        for d in sorted(dirnames):
            sub = current / d
            if d in SKIP_DIRS:
                continue
            if sub.is_symlink():
                warnings.append(f"Symbolic link directory not followed: {(rel_dir / d).as_posix()}")
                continue
            if depth + 1 > limits.max_depth:
                warnings.append(
                    f"Directory deeper than {limits.max_depth} not scanned: {(rel_dir / d).as_posix()}"
                )
                continue
            kept.append(d)
        dirnames[:] = kept

        for name in sorted(filenames):
            examined += 1
            if examined > limits.max_files:
                errors.append(f"File limit of {limits.max_files} exceeded; scan is incomplete")
                truncated = True
                break
            rel = (rel_dir / name).as_posix() if rel_dir.parts else name
            if is_sensitive(name):
                sensitive.append(rel)
                continue
            cls = classify(name, current.name)
            if cls is None:
                continue
            ecosystem, kind, supported = cls
            full = current / name
            if full.is_symlink():
                warnings.append(f"Symbolic link file not followed: {rel}")
                continue
            try:
                full.resolve(strict=True).relative_to(root)
            except (ValueError, OSError):
                errors.append(f"Path escapes repository root and was skipped: {rel}")
                continue
            try:
                st = full.lstat()
            except OSError as exc:
                errors.append(f"Cannot stat {rel}: {exc.strerror}")
                continue
            if not stat.S_ISREG(st.st_mode):
                warnings.append(f"Not a regular file, skipped: {rel}")
                continue
            if not supported:
                unsupported.append(rel)
                warnings.append(f"Unsupported dependency file (not analysed): {rel}")
                continue
            if st.st_size > limits.max_file_bytes:
                errors.append(f"{rel}: {st.st_size} bytes exceeds limit of {limits.max_file_bytes}")
                continue
            try:
                data = _read_bounded(full, limits.max_file_bytes)
            except (OSError, ValidationError) as exc:
                errors.append(f"Cannot read {rel}: {exc}")
                continue
            discovered.append(
                DiscoveredFile(
                    path=rel,
                    filename=name,
                    kind=kind,
                    ecosystem=ecosystem,
                    size_bytes=len(data),
                    sha256=hashlib.sha256(data).hexdigest(),
                    supported=True,
                )
            )
        if truncated:
            break

    discovered.sort(key=lambda f: f.path)
    if not discovered:
        errors.append("No supported manifests or lockfiles were found")
    ecosystems = tuple(sorted({f.ecosystem.value for f in discovered if f.ecosystem}))
    repo_id = "sha256:" + sha256_text("\n".join(f"{f.path}\0{f.sha256}" for f in discovered))
    if not discovered:
        status = IngestionStatus.FAILED
    elif errors:
        status = IngestionStatus.PARTIAL
    else:
        status = IngestionStatus.OK
    return IngestionResult(
        repository_id=repo_id,
        root_name=root.name,
        discovered_files=tuple(discovered),
        supported_ecosystems=ecosystems,
        unsupported_files=tuple(sorted(unsupported)),
        skipped_sensitive=tuple(sorted(sensitive)),
        files_examined=examined,
        warnings=tuple(warnings),
        errors=tuple(errors),
        status=status,
    )


def load_file(root: Path, file: DiscoveredFile, max_bytes: int) -> bytes:
    """Re-read a discovered file and verify it still matches the ingested digest."""
    root_resolved = Path(root).resolve(strict=True)
    full = root_resolved / file.path
    try:
        full.resolve(strict=True).relative_to(root_resolved)
        data = _read_bounded(full, max_bytes)
    except (OSError, ValueError) as exc:
        raise ValidationError(f"Cannot safely read {file.path}: {exc}") from exc
    if hashlib.sha256(data).hexdigest() != file.sha256:
        raise ValidationError(f"{file.path} changed after ingestion; refusing to parse")
    return data
