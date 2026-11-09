"""Provenance verification: each trust question is a separate, named check.

* subject_digest_match - does the provenance describe *this* artifact?
* builder_identity / source_repository - do builder and source satisfy policy?
* sigstore_signature - is the evidence signed by the expected identity?

A check is PASS only when it was actually performed and succeeded.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from pathlib import Path

from aegischain.domain.interfaces import SignatureVerifier
from aegischain.domain.models import Check, ProvenanceResult
from aegischain.domain.status import Status, worst
from aegischain.engines.provenance.parsers.slsa_provenance_parser import (
    SLSA_PREFIX,
    ProvenanceStatement,
    load_provenance,
)
from aegischain.engines.provenance.verifiers.identity_verifier import check_builder, check_source
from aegischain.engines.provenance.verifiers.signature_verifier import CHECK_NAME as SIG_CHECK
from aegischain.exceptions import ParseError


@dataclass(frozen=True)
class ProvenanceExpectations:
    trusted_builders: tuple[str, ...] = ()
    trusted_sources: tuple[str, ...] = ()
    signer_identity: str | None = None
    oidc_issuer: str | None = None


def _subject_check(stmt: ProvenanceStatement, artifact_sha256: str | None) -> Check:
    if artifact_sha256 is None:
        return Check(
            "subject_digest_match",
            Status.INDETERMINATE,
            "Artifact digest unavailable; cannot compare with provenance subjects",
        )
    for name, digest in stmt.subjects:
        recorded = digest.get("sha256")
        if recorded is not None and hmac.compare_digest(recorded, artifact_sha256):
            return Check(
                "subject_digest_match",
                Status.PASS,
                f"Provenance subject {name or '<unnamed>'} matches the artifact SHA-256",
            )
    return Check(
        "subject_digest_match", Status.FAIL, "No provenance subject matches the artifact SHA-256"
    )


def verify_provenance(
    artifact_path: Path | None,
    artifact_sha256: str | None,
    provenance_path: Path | None,
    bundle_path: Path | None,
    expectations: ProvenanceExpectations,
    signature_verifier: SignatureVerifier,
) -> ProvenanceResult:
    if provenance_path is None and bundle_path is None:
        return ProvenanceResult(False, (), Status.INDETERMINATE, False, None, None, None)
    checks: list[Check] = []
    stmt: ProvenanceStatement | None = None
    if provenance_path is not None:
        try:
            stmt = load_provenance(provenance_path)
        except ParseError as exc:
            checks.append(
                Check("provenance_parsed", Status.FAIL, f"Provenance is malformed: {exc}")
            )
        else:
            checks.append(
                Check(
                    "provenance_parsed",
                    Status.PASS,
                    f"Parsed in-toto statement ({stmt.predicate_type})",
                )
            )
            if not stmt.predicate_type.startswith(SLSA_PREFIX):
                checks.append(
                    Check(
                        "predicate_type",
                        Status.FAIL,
                        f"Not a SLSA provenance predicate: {stmt.predicate_type}",
                    )
                )
            else:
                checks.append(Check("predicate_type", Status.PASS, "SLSA provenance predicate"))
            checks.append(_subject_check(stmt, artifact_sha256))
            checks.append(check_builder(stmt.builder_id, expectations.trusted_builders))
            checks.append(check_source(stmt.source_uri, expectations.trusted_sources))

    bundle = bundle_path or (
        provenance_path if stmt is not None and stmt.is_sigstore_bundle else None
    )
    if bundle is None:
        checks.append(Check(SIG_CHECK, Status.INDETERMINATE, "No signature bundle supplied"))
    elif artifact_path is None:
        checks.append(
            Check(
                SIG_CHECK,
                Status.INDETERMINATE,
                "No artifact supplied to verify the signature against",
            )
        )
    else:
        checks.append(
            signature_verifier.verify(
                artifact_path, bundle, expectations.signer_identity, expectations.oidc_issuer
            )
        )

    sig = next(c for c in checks if c.name == SIG_CHECK)
    return ProvenanceResult(
        provided=True,
        checks=tuple(checks),
        status=worst(c.status for c in checks),
        signature_verified=sig.status is Status.PASS,
        signer_identity=expectations.signer_identity if sig.status is Status.PASS else None,
        builder_id=stmt.builder_id if stmt else None,
        source_uri=stmt.source_uri if stmt else None,
    )
