"""Policy rules. Each function maps evidence to RuleResults for one engine.

Rules never *upgrade* weak evidence: missing or unverifiable evidence yields
INDETERMINATE (or WARN where the policy does not require it), never PASS.
"""

from __future__ import annotations

from datetime import date

from aegischain.domain.models import (
    DependencyResult,
    IngestionResult,
    IngestionStatus,
    IntegrityResult,
    LicenseFinding,
    LicenseStatus,
    LookupStatus,
    ProvenanceResult,
    RuleResult,
    SBOMValidationReport,
    VulnerabilityReport,
)
from aegischain.domain.status import Severity, Status
from aegischain.engines.policy.models.policy import SecurityPolicy

DEPENDENCY, SBOM, VULN, LICENSE, INTEGRITY, PROVENANCE = (
    "Dependency Analysis",
    "SBOM Validation",
    "Vulnerability Analysis",
    "License Compliance",
    "Artifact Integrity",
    "Provenance Verification",
)


def dependency_rules(
    dep: DependencyResult, ing: IngestionResult, policy: SecurityPolicy
) -> list[RuleResult]:
    out: list[RuleResult] = []
    if ing.status is IngestionStatus.FAILED:
        out.append(
            RuleResult(
                "dep.ingestion_failed",
                DEPENDENCY,
                Status.INDETERMINATE,
                "Repository ingestion failed: " + "; ".join(ing.errors),
            )
        )
    elif ing.status is IngestionStatus.PARTIAL:
        out.append(
            RuleResult(
                "dep.ingestion_partial",
                DEPENDENCY,
                Status.INDETERMINATE,
                "Repository ingestion was incomplete: " + "; ".join(ing.errors),
            )
        )
    for f in dep.findings:
        if f.status is Status.PASS:
            continue
        status = f.status
        if f.code == "NO_LOCKFILE" and policy.dependencies.require_lockfile:
            status = Status.FAIL
        out.append(RuleResult(f"dep.{f.code.lower()}", DEPENDENCY, status, f.message, f.subjects))
    if not out:
        out.append(
            RuleResult(
                "dep.ok",
                DEPENDENCY,
                Status.PASS,
                f"{len(dep.components)} component(s) resolved without issues",
            )
        )
    return out


def sbom_rules(reports: tuple[SBOMValidationReport, ...] | None) -> list[RuleResult]:
    if not reports:
        return [
            RuleResult(
                "sbom.missing", SBOM, Status.INDETERMINATE, "No SBOM was generated or validated"
            )
        ]
    out = []
    for r in reports:
        if r.valid:
            out.append(
                RuleResult(
                    "sbom.valid",
                    SBOM,
                    Status.PASS,
                    f"{r.format} {r.spec_version}: structural validation passed",
                )
            )
        else:
            out.append(
                RuleResult(
                    "sbom.invalid",
                    SBOM,
                    Status.FAIL,
                    f"{r.format}: " + "; ".join(r.errors[:3]),
                    r.errors[:10],
                )
            )
    return out


def vulnerability_rules(
    rep: VulnerabilityReport, policy: SecurityPolicy, as_of: date
) -> list[RuleResult]:
    vp = policy.vulnerabilities
    out: list[RuleResult] = []
    if rep.lookup_status in (LookupStatus.SKIPPED, LookupStatus.FAILED):
        reason = "; ".join(rep.errors) or rep.lookup_status.value
        return [
            RuleResult(
                "vuln.lookup_unavailable",
                VULN,
                Status.INDETERMINATE,
                f"Vulnerability lookup {rep.lookup_status.value.lower()}: {reason}. "
                "This is NOT evidence that the dependencies are vulnerability-free.",
            )
        ]
    if rep.errors:
        out.append(
            RuleResult(
                "vuln.lookup_errors",
                VULN,
                Status.INDETERMINATE,
                f"{len(rep.errors)} vulnerability detail lookup(s) failed",
                tuple(rep.errors[:10]),
            )
        )
    if rep.unscanned:
        out.append(
            RuleResult(
                "vuln.unscanned",
                VULN,
                vp.on_unscanned,
                f"{len(rep.unscanned)} component(s) could not be scanned (no exact version)",
                rep.unscanned,
            )
        )

    active_waivers = {w.id for w in vp.waivers if w.expires >= as_of}
    for w in vp.waivers:
        if w.expires < as_of:
            out.append(
                RuleResult(
                    "vuln.waiver_expired",
                    VULN,
                    Status.WARN,
                    f"Waiver for {w.id} expired on {w.expires.isoformat()}",
                )
            )
    aliases = {v.osv_id: set(v.aliases) | {v.osv_id} for v in rep.vulnerabilities}
    blocking: list[str] = []
    warning: list[str] = []
    unknown: list[str] = []
    unfixed: list[str] = []
    waived: list[str] = []
    for m in rep.matches:
        subject = f"{m.component_purl} {m.osv_id} ({m.severity.value})"
        if aliases.get(m.osv_id, {m.osv_id}) & active_waivers:
            waived.append(subject)
            continue
        if m.severity in vp.block_on:
            blocking.append(subject)
        elif m.severity in vp.warn_on:
            warning.append(subject)
        elif m.severity is Severity.UNKNOWN:
            unknown.append(subject)
        if (
            vp.fail_on_unfixed
            and not m.fix_available
            and m.severity.rank >= vp.unfixed_min_severity.rank
        ):
            unfixed.append(subject)
    if blocking:
        out.append(
            RuleResult(
                "vuln.blocking",
                VULN,
                Status.FAIL,
                f"{len(blocking)} blocking vulnerabilit(ies) detected",
                tuple(blocking),
            )
        )
    if unfixed:
        out.append(
            RuleResult(
                "vuln.unfixed",
                VULN,
                Status.FAIL,
                f"{len(unfixed)} vulnerabilit(ies) have no available fix",
                tuple(unfixed),
            )
        )
    if warning:
        out.append(
            RuleResult(
                "vuln.warning",
                VULN,
                Status.WARN,
                f"{len(warning)} vulnerabilit(ies) at warning severity",
                tuple(warning),
            )
        )
    if unknown:
        out.append(
            RuleResult(
                "vuln.unknown_severity",
                VULN,
                Status.WARN,
                f"{len(unknown)} vulnerabilit(ies) have unclassifiable severity",
                tuple(unknown),
            )
        )
    if waived:
        out.append(
            RuleResult(
                "vuln.waived",
                VULN,
                Status.PASS,
                f"{len(waived)} vulnerabilit(ies) waived by unexpired waiver",
                tuple(waived),
            )
        )
    if not out:
        note = "No known vulnerabilities in OSV for the scanned versions (absence from a database is not proof of safety)"
        out.append(
            RuleResult(
                "vuln.none_blocking",
                VULN,
                Status.PASS,
                note if not rep.matches else f"{len(rep.matches)} vulnerabilit(ies), none blocking",
            )
        )
    return out


def license_rules(findings: tuple[LicenseFinding, ...], policy: SecurityPolicy) -> list[RuleResult]:
    denied = tuple(f.purl for f in findings if f.status is LicenseStatus.DENIED)
    unknown = tuple(
        f.purl for f in findings if f.status in (LicenseStatus.UNKNOWN, LicenseStatus.INVALID)
    )
    out: list[RuleResult] = []
    if denied:
        out.append(
            RuleResult(
                "license.denied",
                LICENSE,
                Status.FAIL,
                f"{len(denied)} component(s) violate the license policy",
                denied,
            )
        )
    if unknown:
        out.append(
            RuleResult(
                "license.unknown",
                LICENSE,
                policy.licenses.unknown_license,
                f"{len(unknown)} component(s) have a missing, invalid or custom license",
                unknown,
            )
        )
    if not out:
        out.append(
            RuleResult(
                "license.ok",
                LICENSE,
                Status.PASS,
                f"{len(findings)} component license(s) comply with policy",
            )
        )
    return out


def integrity_rules(
    res: IntegrityResult | None, policy: SecurityPolicy
) -> tuple[list[RuleResult], bool]:
    required = policy.integrity.require_sha256
    if res is None:
        if required:
            return [
                RuleResult(
                    "integrity.missing",
                    INTEGRITY,
                    Status.INDETERMINATE,
                    "Policy requires SHA-256 verification but no artifact was supplied",
                )
            ], True
        return [
            RuleResult(
                "integrity.not_required",
                INTEGRITY,
                Status.PASS,
                "No artifact supplied; integrity not required by policy",
            )
        ], False
    if res.status is Status.INDETERMINATE and not required:
        return [RuleResult("integrity.unverified", INTEGRITY, Status.WARN, res.detail)], True
    return [
        RuleResult(f"integrity.{res.status.value.lower()}", INTEGRITY, res.status, res.detail)
    ], True


def provenance_rules(
    res: ProvenanceResult | None, policy: SecurityPolicy
) -> tuple[list[RuleResult], bool]:
    pp = policy.provenance
    if res is None or not res.provided:
        if pp.require_provenance or pp.require_verified_signature:
            return [
                RuleResult(
                    "prov.missing",
                    PROVENANCE,
                    Status.INDETERMINATE,
                    "Provenance evidence is unavailable",
                )
            ], True
        return [
            RuleResult(
                "prov.not_required",
                PROVENANCE,
                Status.PASS,
                "No provenance supplied; not required by policy",
            )
        ], False
    out: list[RuleResult] = []
    for c in res.checks:
        status = c.status
        if status is Status.INDETERMINATE:
            required = (
                pp.require_verified_signature
                if c.name == "sigstore_signature"
                else pp.require_provenance
            )
            status = Status.INDETERMINATE if required else Status.WARN
        out.append(RuleResult(f"prov.{c.name}", PROVENANCE, status, c.detail))
    if (
        pp.require_verified_signature
        and not res.signature_verified
        and not any(r.rule_id == "prov.sigstore_signature" for r in out)
    ):
        out.append(
            RuleResult(
                "prov.sigstore_signature",
                PROVENANCE,
                Status.INDETERMINATE,
                "Signature was not verified",
            )
        )
    return out, True
