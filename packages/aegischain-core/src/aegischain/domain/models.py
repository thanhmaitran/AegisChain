"""Core immutable domain models.

All models are frozen dataclasses so evidence cannot be mutated after creation.
They are serialised with :func:`aegischain.utils.serialization.to_jsonable`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum

from aegischain.domain.status import Severity, Status

# ----------------------------------------------------------------------------
# Enumerations
# ----------------------------------------------------------------------------


class Ecosystem(str, Enum):
    """Package ecosystems. Values match OSV ecosystem names."""

    PYPI = "PyPI"
    NPM = "npm"


class FileKind(str, Enum):
    MANIFEST = "manifest"
    LOCKFILE = "lockfile"


class Scope(str, Enum):
    RUNTIME = "runtime"
    DEV = "dev"
    OPTIONAL = "optional"


class IngestionStatus(str, Enum):
    OK = "OK"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class LookupStatus(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class LicenseStatus(str, Enum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    UNKNOWN = "UNKNOWN"
    INVALID = "INVALID"


# ----------------------------------------------------------------------------
# Repository ingestion
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class DiscoveredFile:
    path: str  # POSIX path relative to the repository root
    filename: str
    kind: FileKind
    ecosystem: Ecosystem | None
    size_bytes: int
    sha256: str
    supported: bool


@dataclass(frozen=True)
class IngestionResult:
    repository_id: str
    root_name: str
    discovered_files: tuple[DiscoveredFile, ...]
    supported_ecosystems: tuple[str, ...]
    unsupported_files: tuple[str, ...]
    skipped_sensitive: tuple[str, ...]
    files_examined: int
    warnings: tuple[str, ...]
    errors: tuple[str, ...]
    status: IngestionStatus


# ----------------------------------------------------------------------------
# Parsing results
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class DeclaredDependency:
    """A dependency declared in a manifest (a requirement, not a resolved version)."""

    name: str
    specifier: str | None
    scope: Scope
    ecosystem: Ecosystem
    source_file: str
    pinned_version: str | None = None
    hashes: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ResolvedPackage:
    """A package resolved by a lockfile. ``key`` is unique within that lockfile."""

    key: str
    name: str
    version: str
    ecosystem: Ecosystem
    scope: Scope
    depends_on: tuple[str, ...]  # keys of other ResolvedPackage entries
    hashes: Mapping[str, str] = field(default_factory=dict)
    declared_license: str | None = None
    unresolved_dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class ParsedManifest:
    source_file: str
    ecosystem: Ecosystem
    declared: tuple[DeclaredDependency, ...]
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class ParsedLockfile:
    source_file: str
    ecosystem: Ecosystem
    packages: tuple[ResolvedPackage, ...]
    #: Keys of packages the lockfile itself marks as direct, or None if unknown.
    direct_keys: frozenset[str] | None
    warnings: tuple[str, ...] = ()


# ----------------------------------------------------------------------------
# Dependency intelligence
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class Component:
    name: str
    version: str | None
    ecosystem: Ecosystem
    purl: str
    direct: bool
    scope: Scope
    dependencies: tuple[str, ...]  # purls of components this one depends on
    hashes: Mapping[str, str]  # e.g. {"sha256": "...", "sha512": "..."}
    declared_license: str | None
    depth: int | None  # minimal distance from a direct dependency (direct == 1)
    source_files: tuple[str, ...]

    @property
    def resolved(self) -> bool:
        return self.version is not None


@dataclass(frozen=True)
class Finding:
    code: str
    status: Status
    message: str
    subjects: tuple[str, ...] = ()


@dataclass(frozen=True)
class DependencyResult:
    components: tuple[Component, ...]
    edges: tuple[tuple[str, str], ...]
    findings: tuple[Finding, ...]
    parsed_files: tuple[str, ...]
    status: Status


# ----------------------------------------------------------------------------
# SBOM
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class SBOMValidationReport:
    format: str
    spec_version: str
    valid: bool
    errors: tuple[str, ...]
    checks_performed: tuple[str, ...]
    #: True only if validated against the official JSON schema. The built-in validator
    #: is structural, so this is False unless an official validator was run separately.
    schema_validated: bool = False


# ----------------------------------------------------------------------------
# Vulnerabilities
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class Vulnerability:
    osv_id: str
    aliases: tuple[str, ...]
    summary: str
    severity: Severity
    severity_source: str  # e.g. "CVSS_V3 vector", "database_specific label", "none"
    cvss_score: float | None
    references: tuple[str, ...]
    published: str | None
    modified: str | None
    affected: tuple[Mapping[str, object], ...] = ()


@dataclass(frozen=True)
class VulnerabilityMatch:
    component_purl: str
    osv_id: str
    severity: Severity
    direct: bool
    fixed_versions: tuple[str, ...]  # fix versions strictly greater than the affected version
    fix_available: bool
    #: CONFIRMED (local range check agrees), UNVERIFIED (could not evaluate),
    #: CONTRADICTED (OSV reported it but local range check says not affected).
    local_verification: str


@dataclass(frozen=True)
class VulnerabilityReport:
    source: str
    queried_at: datetime | None
    lookup_status: LookupStatus
    vulnerabilities: tuple[Vulnerability, ...]
    matches: tuple[VulnerabilityMatch, ...]
    unscanned: tuple[str, ...]  # purls that could not be queried (no version, errors)
    errors: tuple[str, ...]
    severity_counts: Mapping[str, int]


# ----------------------------------------------------------------------------
# Licenses
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class LicenseFinding:
    purl: str
    declared: str | None
    normalized: str | None
    status: LicenseStatus
    reason: str


# ----------------------------------------------------------------------------
# Integrity and provenance
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class IntegrityResult:
    filename: str
    size_bytes: int | None
    sha256: str | None
    expected_sha256: str | None
    status: Status
    detail: str


@dataclass(frozen=True)
class Check:
    name: str
    status: Status
    detail: str


@dataclass(frozen=True)
class ProvenanceResult:
    provided: bool
    checks: tuple[Check, ...]
    status: Status
    signature_verified: bool
    signer_identity: str | None
    builder_id: str | None
    source_uri: str | None


# ----------------------------------------------------------------------------
# Policy
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleResult:
    rule_id: str
    engine: str
    status: Status
    message: str
    subjects: tuple[str, ...] = ()


@dataclass(frozen=True)
class EngineDecision:
    engine: str
    status: Status
    evaluated: bool
    rules: tuple[RuleResult, ...]


@dataclass(frozen=True)
class PolicyEvaluation:
    policy_name: str
    policy_version: str
    as_of: date
    engines: tuple[EngineDecision, ...]
    status: Status
    reasons: tuple[str, ...]


# ----------------------------------------------------------------------------
# Final report
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class AnalysisReport:
    report_version: str
    tool_version: str
    generated_at: datetime
    evidence_digest: str
    repository_id: str
    ingestion: IngestionResult
    dependency: DependencyResult
    sbom_validation: tuple[SBOMValidationReport, ...]
    vulnerability: VulnerabilityReport
    licenses: tuple[LicenseFinding, ...]
    integrity: IntegrityResult | None
    provenance: ProvenanceResult | None
    policy_evaluation: PolicyEvaluation
    metrics: Mapping[str, float]
    errors: tuple[str, ...]

    @property
    def decision(self) -> Status:
        return self.policy_evaluation.status
