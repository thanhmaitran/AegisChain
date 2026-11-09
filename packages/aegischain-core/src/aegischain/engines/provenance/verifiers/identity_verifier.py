"""Builder and source identity checks against an explicit trust policy."""

from __future__ import annotations

import fnmatch
from collections.abc import Sequence

from aegischain.domain.models import Check
from aegischain.domain.status import Status
from aegischain.engines.provenance.parsers.slsa_provenance_parser import normalize_repo_uri


def _any_match(value: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch.fnmatchcase(value, p) for p in patterns)


def check_builder(builder_id: str | None, trusted: Sequence[str]) -> Check:
    if not trusted:
        return Check(
            "builder_identity", Status.INDETERMINATE, "No trusted builders configured in policy"
        )
    if not builder_id:
        return Check(
            "builder_identity", Status.FAIL, "Provenance does not state a builder identity"
        )
    if _any_match(builder_id, trusted):
        return Check("builder_identity", Status.PASS, f"Builder is trusted: {builder_id}")
    return Check("builder_identity", Status.FAIL, f"Builder is not trusted: {builder_id}")


def check_source(source_uri: str | None, trusted: Sequence[str]) -> Check:
    if not trusted:
        return Check(
            "source_repository",
            Status.INDETERMINATE,
            "No trusted source repositories configured in policy",
        )
    if not source_uri:
        return Check(
            "source_repository", Status.FAIL, "Provenance does not state a source repository"
        )
    normalized = [normalize_repo_uri(t) or t for t in trusted]
    if _any_match(source_uri, normalized):
        return Check(
            "source_repository", Status.PASS, f"Source repository is trusted: {source_uri}"
        )
    return Check(
        "source_repository", Status.FAIL, f"Source repository is not trusted: {source_uri}"
    )
