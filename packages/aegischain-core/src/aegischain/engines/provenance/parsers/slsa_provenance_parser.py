"""Parse in-toto statements carrying SLSA provenance (v0.2 and v1).

Accepted containers: a bare in-toto Statement, a DSSE envelope, a Sigstore bundle
with ``dsseEnvelope``, or JSON-lines of those (GitHub attestation downloads).
Parsing does *not* establish trust; verification is a separate step.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegischain.exceptions import ParseError

MAX_PROVENANCE_BYTES = 5 * 1024 * 1024
SLSA_PREFIX = "https://slsa.dev/provenance/"
_STATEMENT_TYPES = ("https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1")
_REPO = re.compile(r"^(https?://[^/@#\s]+/[^@#\s]+)")


@dataclass(frozen=True)
class ProvenanceStatement:
    predicate_type: str
    subjects: tuple[tuple[str, dict[str, str]], ...]
    builder_id: str | None
    source_uri: str | None
    is_sigstore_bundle: bool
    has_signatures: bool


def normalize_repo_uri(uri: str | None) -> str | None:
    """``git+https://host/org/repo.git@refs/heads/main`` -> ``https://host/org/repo``."""
    if not uri:
        return None
    text = uri.strip()
    if text.startswith("git+"):
        text = text[4:]
    m = _REPO.match(text)
    if not m:
        return None
    out = m.group(1).rstrip("/")
    if out.endswith(".git"):
        out = out[:-4]
    scheme, rest = out.split("://", 1)
    host, _, path = rest.partition("/")
    return f"{scheme}://{host.lower()}/{path}"


def _dig(obj: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _decode_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    payload = envelope.get("payload")
    if not isinstance(payload, str):
        raise ParseError("DSSE envelope has no payload")
    try:
        decoded = json.loads(base64.b64decode(payload, validate=False))
    except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ParseError("DSSE payload is not base64-encoded JSON") from exc
    if not isinstance(decoded, dict):
        raise ParseError("DSSE payload is not a JSON object")
    return decoded


def _unwrap(doc: dict[str, Any]) -> tuple[dict[str, Any], bool, bool]:
    """Return (statement, is_bundle, has_signatures)."""
    if "dsseEnvelope" in doc:
        env = doc["dsseEnvelope"]
        if not isinstance(env, dict):
            raise ParseError("dsseEnvelope is malformed")
        return _decode_payload(env), True, bool(env.get("signatures"))
    if "payload" in doc and "payloadType" in doc:
        return _decode_payload(doc), False, bool(doc.get("signatures"))
    return doc, False, False


def parse_statement_document(doc: dict[str, Any]) -> ProvenanceStatement:
    statement, is_bundle, signed = _unwrap(doc)
    if statement.get("_type") not in _STATEMENT_TYPES:
        raise ParseError("document is not an in-toto Statement v0.1/v1")
    predicate_type = statement.get("predicateType")
    if not isinstance(predicate_type, str):
        raise ParseError("statement has no predicateType")
    raw_subjects = statement.get("subject")
    if not isinstance(raw_subjects, list) or not raw_subjects:
        raise ParseError("statement has no subjects")
    subjects: list[tuple[str, dict[str, str]]] = []
    for s in raw_subjects:
        digest = s.get("digest") if isinstance(s, dict) else None
        if not isinstance(digest, dict):
            raise ParseError("subject without digest")
        subjects.append(
            (str(s.get("name", "")), {str(k).lower(): str(v).lower() for k, v in digest.items()})
        )
    pred = statement.get("predicate") or {}
    builder = _dig(pred, "runDetails", "builder", "id") or _dig(pred, "builder", "id")
    resolved = _dig(pred, "buildDefinition", "resolvedDependencies")
    source = (
        _dig(pred, "buildDefinition", "externalParameters", "workflow", "repository")
        or (
            resolved[0].get("uri")
            if isinstance(resolved, list) and resolved and isinstance(resolved[0], dict)
            else None
        )
        or _dig(pred, "invocation", "configSource", "uri")
    )
    return ProvenanceStatement(
        predicate_type=predicate_type,
        subjects=tuple(subjects),
        builder_id=str(builder) if builder else None,
        source_uri=normalize_repo_uri(str(source)) if source else None,
        is_sigstore_bundle=is_bundle,
        has_signatures=signed,
    )


def load_provenance(path: Path) -> ProvenanceStatement:
    try:
        raw = path.read_bytes() if path.stat().st_size <= MAX_PROVENANCE_BYTES else None
    except OSError as exc:
        raise ParseError(f"cannot read provenance file: {exc.strerror}") from exc
    if raw is None:
        raise ParseError("provenance file exceeds the size limit")
    text = raw.decode("utf-8", errors="replace")
    candidates: list[str] = [text, *[ln for ln in text.splitlines() if ln.strip()]]
    last: ParseError | None = None
    for cand in candidates:
        try:
            doc = json.loads(cand)
        except json.JSONDecodeError:
            continue
        if not isinstance(doc, dict):
            continue
        try:
            return parse_statement_document(doc)
        except ParseError as exc:
            last = exc
    raise last or ParseError("provenance file is not valid JSON")
