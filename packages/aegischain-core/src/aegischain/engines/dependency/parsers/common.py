"""Shared helpers for manifest and lockfile parsers."""

from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import quote

from aegischain.exceptions import ParseError

_PYPI_SEP = re.compile(r"[-_.]+")


def normalize_pypi_name(name: str) -> str:
    """PEP 503 name normalisation."""
    return _PYPI_SEP.sub("-", name.strip()).lower()


def pypi_purl(name: str, version: str | None) -> str:
    base = f"pkg:pypi/{quote(normalize_pypi_name(name), safe='')}"
    return f"{base}@{quote(version, safe='')}" if version else base


def npm_purl(name: str, version: str | None) -> str:
    """Scoped names ``@scope/pkg`` become ``%40scope/pkg`` per the purl spec."""
    if name.startswith("@") and "/" in name:
        scope, pkg = name.split("/", 1)
        base = f"pkg:npm/{quote(scope, safe='')}/{quote(pkg, safe='')}"
    else:
        base = f"pkg:npm/{quote(name, safe='')}"
    return f"{base}@{quote(version, safe='')}" if version else base


_NPM_ALGOS = {"sha1": 40, "sha256": 64, "sha384": 96, "sha512": 128}


def npm_integrity_to_hash(integrity: object) -> dict[str, str]:
    """Convert an SRI string (``sha512-<base64>``) to ``{"sha512": "<hex>"}``.

    Returns an empty dict for anything that is not exactly one well-formed digest.
    """
    if not isinstance(integrity, str):
        return {}
    parts = integrity.split()
    if len(parts) != 1 or "-" not in parts[0]:
        return {}
    algo, _, b64 = parts[0].partition("-")
    if algo not in _NPM_ALGOS:
        return {}
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        return {}
    hex_digest = raw.hex()
    return {algo: hex_digest} if len(hex_digest) == _NPM_ALGOS[algo] else {}


def decode_utf8(content: bytes, path: str) -> str:
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ParseError(f"{path}: not valid UTF-8") from exc
