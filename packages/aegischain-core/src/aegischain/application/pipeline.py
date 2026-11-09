"""Analysis pipeline: orchestrates all engines into one deterministic report.

The pipeline is the only place that knows the order of engines. Every stage failure is
converted into INDETERMINATE evidence; nothing is ever silently turned into PASS.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aegischain import __version__
from aegischain.domain.interfaces import SignatureVerifier, VulnerabilityProvider
from aegischain.domain.models import (
    AnalysisReport,
    Component,
    DependencyResult,
    Finding,
    IngestionResult,
    IntegrityResult,
    LookupStatus,
    ProvenanceResult,
    SBOMValidationReport,
    VulnerabilityReport,
)
from aegischain.domain.status import Status
from aegischain.engines.dependency.service import analyze_dependencies, graph_view
from aegischain.engines.ingestion.scanner import IngestionLimits, RepositoryInput, scan_repository
from aegischain.engines.integrity.hasher import verify_artifact
from aegischain.engines.license.evaluator import LicensePolicy, evaluate_components
from aegischain.engines.policy import SecurityEvidence, SecurityPolicy, evaluate_policy
from aegischain.engines.provenance.verifiers.provenance_verifier import (
    ProvenanceExpectations,
    verify_provenance,
)
from aegischain.engines.provenance.verifiers.signature_verifier import UnavailableSignatureVerifier
from aegischain.engines.sbom.service import SBOMBundle, generate_sboms
from aegischain.engines.vulnerability.provider import SkippedVulnerabilityProvider
from aegischain.utils.clock import Clock, SystemClock
from aegischain.utils.logging import get_logger, timed
from aegischain.utils.serialization import canonical_json, sha256_text

REPORT_VERSION = "1"


@dataclass(frozen=True)
class AnalysisRequest:
    root_path: Path
    policy: SecurityPolicy = field(default_factory=SecurityPolicy)
    include_dev_dependencies: bool = True
    artifact_path: Path | None = None
    expected_sha256: str | None = None
    provenance_path: Path | None = None
    signature_bundle_path: Path | None = None
    #: purl -> declared license, supplied as external evidence (never inferred).
    license_evidence: Mapping[str, str] = field(default_factory=dict)
    limits: IngestionLimits = field(default_factory=IngestionLimits)


@dataclass(frozen=True)
class AnalysisOutput:
    report: AnalysisReport
    sbom: SBOMBundle | None
    graph: dict[str, Any]


class AnalysisPipeline:
    def __init__(
        self,
        vulnerability_provider: VulnerabilityProvider | None = None,
        signature_verifier: SignatureVerifier | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._vuln = vulnerability_provider or SkippedVulnerabilityProvider()
        self._sig = signature_verifier or UnavailableSignatureVerifier()
        self._clock = clock or SystemClock()

    def run(self, request: AnalysisRequest) -> AnalysisOutput:
        log = get_logger()
        metrics: dict[str, float] = {}
        errors: list[str] = []
        now = self._clock.now()

        with timed("ingestion", metrics):
            ingestion: IngestionResult = scan_repository(
                RepositoryInput(request.root_path, request.include_dev_dependencies, request.limits)
            )

        with timed("dependency", metrics):
            try:
                dependency = analyze_dependencies(
                    request.root_path,
                    ingestion,
                    request.include_dev_dependencies,
                    request.limits.max_file_bytes,
                )
            except Exception as exc:  # noqa: BLE001 - convert any engine bug to INDETERMINATE evidence
                log.exception("dependency analysis crashed")
                errors.append(f"dependency analysis crashed: {type(exc).__name__}")
                dependency = DependencyResult(
                    (),
                    (),
                    (Finding("ENGINE_ERROR", Status.INDETERMINATE, "Dependency analysis crashed"),),
                    (),
                    Status.INDETERMINATE,
                )

        components: tuple[Component, ...] = tuple(
            dataclasses.replace(c, declared_license=request.license_evidence[c.purl])
            if c.declared_license is None and c.purl in request.license_evidence
            else c
            for c in dependency.components
        )
        dependency = dataclasses.replace(dependency, components=components)

        with timed("sbom", metrics):
            sbom: SBOMBundle | None = None
            validation: tuple[SBOMValidationReport, ...] | None = None
            try:
                sbom = generate_sboms(ingestion.root_name, components, __version__, now)
                validation = sbom.validation
            except Exception as exc:  # noqa: BLE001
                log.exception("sbom generation crashed")
                errors.append(f"sbom generation crashed: {type(exc).__name__}")

        with timed("vulnerability", metrics):
            try:
                vuln = self._vuln.query(components)
            except Exception as exc:  # noqa: BLE001
                log.exception("vulnerability provider crashed")
                errors.append(f"vulnerability provider crashed: {type(exc).__name__}")
                vuln = VulnerabilityReport(
                    "unavailable",
                    None,
                    LookupStatus.FAILED,
                    (),
                    (),
                    tuple(c.purl for c in components),
                    (f"provider crashed: {type(exc).__name__}",),
                    {},
                )

        with timed("license", metrics):
            licenses = evaluate_components(
                components,
                LicensePolicy(request.policy.licenses.allowed, request.policy.licenses.denied),
            )

        integrity: IntegrityResult | None = None
        provenance: ProvenanceResult | None = None
        if request.artifact_path is not None:
            with timed("integrity", metrics):
                integrity = verify_artifact(request.artifact_path, request.expected_sha256)
        if request.provenance_path is not None or request.signature_bundle_path is not None:
            with timed("provenance", metrics):
                pp = request.policy.provenance
                provenance = verify_provenance(
                    request.artifact_path,
                    integrity.sha256 if integrity else None,
                    request.provenance_path,
                    request.signature_bundle_path,
                    ProvenanceExpectations(
                        pp.trusted_builders, pp.trusted_sources, pp.signer_identity, pp.oidc_issuer
                    ),
                    self._sig,
                )

        with timed("policy", metrics):
            evidence = SecurityEvidence(
                ingestion, dependency, validation, vuln, licenses, integrity, provenance, now.date()
            )
            evaluation = evaluate_policy(evidence, request.policy)

        digest = sha256_text(
            canonical_json(
                {
                    "repository": ingestion.repository_id,
                    "components": [(c.purl, c.direct, c.scope, c.dependencies) for c in components],
                    "matches": [(m.component_purl, m.osv_id, m.severity) for m in vuln.matches],
                    "licenses": [(f.purl, f.status, f.normalized) for f in licenses],
                    "integrity": integrity and (integrity.sha256, integrity.status),
                    "provenance": provenance and [(c.name, c.status) for c in provenance.checks],
                    "policy": evaluation,
                }
            )
        )
        report = AnalysisReport(
            report_version=REPORT_VERSION,
            tool_version=__version__,
            generated_at=now,
            evidence_digest="sha256:" + digest,
            repository_id=ingestion.repository_id,
            ingestion=ingestion,
            dependency=dependency,
            sbom_validation=validation or (),
            vulnerability=vuln,
            licenses=licenses,
            integrity=integrity,
            provenance=provenance,
            policy_evaluation=evaluation,
            metrics=metrics,
            errors=tuple(errors),
        )
        log.info(
            "analysis complete",
            extra={"fields": {"decision": evaluation.status.value, "components": len(components)}},
        )
        return AnalysisOutput(report, sbom, graph_view(dependency))
