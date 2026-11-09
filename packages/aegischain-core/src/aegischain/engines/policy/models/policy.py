"""Security policy model and evidence container."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from aegischain.domain.models import (
    DependencyResult,
    IngestionResult,
    IntegrityResult,
    LicenseFinding,
    ProvenanceResult,
    SBOMValidationReport,
    VulnerabilityReport,
)
from aegischain.domain.status import Severity, Status


@dataclass(frozen=True)
class Waiver:
    id: str
    justification: str
    expires: date


@dataclass(frozen=True)
class DependencyPolicy:
    require_lockfile: bool = False


@dataclass(frozen=True)
class VulnerabilityPolicy:
    block_on: tuple[Severity, ...] = (Severity.CRITICAL,)
    warn_on: tuple[Severity, ...] = (Severity.HIGH,)
    #: FAIL on any vulnerability with no available fix at or above ``unfixed_min_severity``.
    fail_on_unfixed: bool = False
    unfixed_min_severity: Severity = Severity.MEDIUM
    #: Status when some components could not be scanned (unpinned, lookup errors).
    on_unscanned: Status = Status.INDETERMINATE
    waivers: tuple[Waiver, ...] = ()


@dataclass(frozen=True)
class LicensePolicyConfig:
    allowed: tuple[str, ...] = ()
    denied: tuple[str, ...] = ()
    unknown_license: Status = Status.WARN


@dataclass(frozen=True)
class ProvenancePolicy:
    require_provenance: bool = False
    require_verified_signature: bool = False
    trusted_builders: tuple[str, ...] = ()
    trusted_sources: tuple[str, ...] = ()
    signer_identity: str | None = None
    oidc_issuer: str | None = None


@dataclass(frozen=True)
class IntegrityPolicy:
    require_sha256: bool = False


@dataclass(frozen=True)
class SecurityPolicy:
    name: str = "default"
    version: str = "1"
    dependencies: DependencyPolicy = field(default_factory=DependencyPolicy)
    vulnerabilities: VulnerabilityPolicy = field(default_factory=VulnerabilityPolicy)
    licenses: LicensePolicyConfig = field(default_factory=LicensePolicyConfig)
    provenance: ProvenancePolicy = field(default_factory=ProvenancePolicy)
    integrity: IntegrityPolicy = field(default_factory=IntegrityPolicy)


@dataclass(frozen=True)
class SecurityEvidence:
    ingestion: IngestionResult
    dependency: DependencyResult
    sbom_validation: tuple[SBOMValidationReport, ...] | None
    vulnerability: VulnerabilityReport
    licenses: tuple[LicenseFinding, ...]
    integrity: IntegrityResult | None
    provenance: ProvenanceResult | None
    as_of: date
