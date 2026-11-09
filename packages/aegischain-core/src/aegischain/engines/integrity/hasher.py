"""Artifact integrity engine (Phase 7): streaming SHA-256 and tamper detection.

A matching digest only proves the bytes equal a *reference digest*. It says nothing
about who produced the file; that is the job of signature/provenance verification.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
from pathlib import Path

from aegischain.domain.models import IntegrityResult
from aegischain.domain.status import Status

CHUNK_SIZE = 1024 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def normalize_digest(value: str) -> str | None:
    """Accept ``<hex>`` or ``sha256:<hex>`` (any case). Return lowercase hex or None."""
    text = value.strip().lower()
    if text.startswith("sha256:"):
        text = text[len("sha256:") :]
    return text if _HEX64.match(text) else None


def hash_file(path: Path, chunk_size: int = CHUNK_SIZE) -> tuple[str, int]:
    """Stream a regular, non-symlink file; reject unsafe or changing artifacts."""

    # Inspect the path itself without following symbolic links.
    path_before = os.lstat(path)

    if stat.S_ISLNK(path_before.st_mode):
        raise ValueError("symbolic links are not accepted as artifacts")

    if not stat.S_ISREG(path_before.st_mode):
        raise ValueError("not a regular file")

    # O_NOFOLLOW provides additional protection on platforms that support it.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)

    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())

        if not stat.S_ISREG(before.st_mode):
            raise ValueError("not a regular file")

        # Ensure the opened file matches the file inspected by lstat().
        if (path_before.st_dev, path_before.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            raise RuntimeError("artifact path changed while it was being opened")

        digest = hashlib.sha256()
        total = 0

        while chunk := handle.read(chunk_size):
            digest.update(chunk)
            total += len(chunk)

        after = os.fstat(handle.fileno())

    # Inspect the path again after hashing.
    path_after = os.lstat(path)

    if stat.S_ISLNK(path_after.st_mode):
        raise RuntimeError("artifact path changed to a symbolic link while being hashed")

    if (path_before.st_dev, path_before.st_ino) != (
        path_after.st_dev,
        path_after.st_ino,
    ):
        raise RuntimeError("artifact path changed while it was being hashed")

    # Detect modifications to the opened file during hashing.
    if (before.st_size, before.st_mtime_ns) != (
        after.st_size,
        after.st_mtime_ns,
    ) or total != after.st_size:
        raise RuntimeError("file changed while it was being hashed")

    return digest.hexdigest(), total


def verify_artifact(
    path: Path | None,
    expected_sha256: str | None,
) -> IntegrityResult:
    """Compute the digest of ``path`` and compare it with ``expected_sha256`` (if given)."""

    name = path.name if path else "<none>"

    if path is None:
        return IntegrityResult(
            name,
            None,
            None,
            expected_sha256,
            Status.INDETERMINATE,
            "No artifact supplied",
        )

    expected = None

    if expected_sha256 is not None:
        expected = normalize_digest(expected_sha256)

        if expected is None:
            return IntegrityResult(
                name,
                None,
                None,
                expected_sha256,
                Status.INDETERMINATE,
                "Expected digest is not a valid SHA-256 value",
            )

    try:
        actual, size = hash_file(path)

    except FileNotFoundError:
        return IntegrityResult(
            name,
            None,
            None,
            expected,
            Status.INDETERMINATE,
            "Artifact not found",
        )

    except RuntimeError as exc:
        return IntegrityResult(
            name,
            None,
            None,
            expected,
            Status.INDETERMINATE,
            str(exc),
        )

    except (OSError, ValueError) as exc:
        return IntegrityResult(
            name,
            None,
            None,
            expected,
            Status.INDETERMINATE,
            f"Artifact cannot be read safely: {exc}",
        )

    if expected is None:
        return IntegrityResult(
            name,
            size,
            actual,
            None,
            Status.INDETERMINATE,
            "Digest computed, but no trusted reference digest was supplied to compare against",
        )

    if hmac.compare_digest(actual, expected):
        return IntegrityResult(
            name,
            size,
            actual,
            expected,
            Status.PASS,
            "SHA-256 digest matches the reference",
        )

    return IntegrityResult(
        name,
        size,
        actual,
        expected,
        Status.FAIL,
        "SHA-256 digest does NOT match the reference; artifact was modified or is not the expected file",
    )
