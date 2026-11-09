import dataclasses
import unittest
from datetime import date

from aegischain.domain.models import (
    Check,
    DependencyResult,
    Finding,
    IngestionResult,
    IngestionStatus,
    IntegrityResult,
    LicenseFinding,
    LicenseStatus,
    LookupStatus,
    ProvenanceResult,
    SBOMValidationReport,
    VulnerabilityMatch,
    VulnerabilityReport,
)
from aegischain.domain.status import Severity, Status, worst
from aegischain.engines.policy import SecurityEvidence, evaluate_policy, parse_policy
from aegischain.engines.policy.models.policy import SecurityPolicy
from aegischain.exceptions import PolicyError

from tests.helpers import pypi

AS_OF = date(2026, 1, 15)


def ingestion(status=IngestionStatus.OK):
    return IngestionResult("sha256:x", "r", (), ("PyPI",), (), (), 1, (), (), status)


def vuln_report(matches=(), status=LookupStatus.COMPLETE, unscanned=(), errors=()):
    return VulnerabilityReport(
        "t", None, status, (), tuple(matches), tuple(unscanned), tuple(errors), {}
    )


def match(sev, fixed=("2.0",), purl="pkg:pypi/a@1", vid="V-1"):
    return VulnerabilityMatch(purl, vid, sev, True, fixed, bool(fixed), "CONFIRMED")


def evidence(**kw):
    base = dict(
        ingestion=ingestion(),
        dependency=DependencyResult((pypi("a", "1"),), (), (), ("f",), Status.PASS),
        sbom_validation=(SBOMValidationReport("CycloneDX", "1.5", True, (), ()),),
        vulnerability=vuln_report(),
        licenses=(LicenseFinding("pkg:pypi/a@1", "MIT", "MIT", LicenseStatus.ALLOWED, "ok"),),
        integrity=None,
        provenance=None,
        as_of=AS_OF,
    )
    base.update(kw)
    return SecurityEvidence(**base)


def decide(policy=None, **kw):
    return evaluate_policy(evidence(**kw), policy or SecurityPolicy())


def engine(res, name):
    return next(e for e in res.engines if e.engine == name)


class StatusTests(unittest.TestCase):
    def test_precedence(self) -> None:
        self.assertEqual(worst([Status.PASS, Status.WARN]), Status.WARN)
        self.assertEqual(worst([Status.WARN, Status.INDETERMINATE]), Status.INDETERMINATE)
        self.assertEqual(worst([Status.INDETERMINATE, Status.FAIL, Status.PASS]), Status.FAIL)

    def test_empty_is_never_pass(self) -> None:
        self.assertEqual(worst([]), Status.INDETERMINATE)


class DecisionTests(unittest.TestCase):
    def test_clean_evidence_passes(self) -> None:
        r = decide()
        self.assertEqual(r.status, Status.PASS)
        self.assertEqual(r.reasons, ())

    def test_blocking_vulnerability_fails(self) -> None:
        r = decide(vulnerability=vuln_report([match(Severity.CRITICAL)]))
        self.assertEqual(r.status, Status.FAIL)
        self.assertTrue(any("blocking" in x for x in r.reasons))

    def test_warn_severity_warns(self) -> None:
        self.assertEqual(
            decide(vulnerability=vuln_report([match(Severity.HIGH)])).status, Status.WARN
        )

    def test_unknown_severity_is_not_ignored(self) -> None:
        self.assertEqual(
            decide(vulnerability=vuln_report([match(Severity.UNKNOWN)])).status, Status.WARN
        )

    def test_low_severity_passes_by_default(self) -> None:
        self.assertEqual(
            decide(vulnerability=vuln_report([match(Severity.LOW)])).status, Status.PASS
        )

    def test_fail_on_unfixed(self) -> None:
        p = parse_policy(
            {
                "policy": {
                    "vulnerabilities": {
                        "block_on": [],
                        "warn_on": [],
                        "fail_on_unfixed": True,
                        "unfixed_min_severity": "HIGH",
                    }
                }
            }
        )
        self.assertEqual(
            decide(p, vulnerability=vuln_report([match(Severity.HIGH, fixed=())])).status,
            Status.FAIL,
        )
        self.assertEqual(
            decide(p, vulnerability=vuln_report([match(Severity.HIGH, fixed=("2",))])).status,
            Status.PASS,
        )
        self.assertEqual(
            decide(p, vulnerability=vuln_report([match(Severity.LOW, fixed=())])).status,
            Status.PASS,
        )

    def test_failed_or_skipped_lookup_is_indeterminate_never_pass(self) -> None:
        for st in (LookupStatus.FAILED, LookupStatus.SKIPPED):
            r = decide(vulnerability=vuln_report(status=st, errors=("boom",)))
            self.assertEqual(engine(r, "Vulnerability Analysis").status, Status.INDETERMINATE)
            self.assertEqual(r.status, Status.INDETERMINATE)

    def test_unscanned_components_follow_policy(self) -> None:
        rep = vuln_report(status=LookupStatus.PARTIAL, unscanned=("pkg:pypi/a",))
        self.assertEqual(decide(vulnerability=rep).status, Status.INDETERMINATE)
        lenient = parse_policy({"policy": {"vulnerabilities": {"on_unscanned": "WARN"}}})
        self.assertEqual(decide(lenient, vulnerability=rep).status, Status.WARN)

    def test_fail_beats_indeterminate(self) -> None:
        r = decide(
            vulnerability=vuln_report([match(Severity.CRITICAL)]),
            ingestion=ingestion(IngestionStatus.PARTIAL),
        )
        self.assertEqual(r.status, Status.FAIL)

    def test_incomplete_ingestion_is_indeterminate(self) -> None:
        self.assertEqual(
            decide(ingestion=ingestion(IngestionStatus.PARTIAL)).status, Status.INDETERMINATE
        )

    def test_dependency_findings_map_to_status(self) -> None:
        dep = DependencyResult(
            (), (), (Finding("NO_LOCKFILE", Status.WARN, "x"),), ("f",), Status.WARN
        )
        self.assertEqual(decide(dependency=dep).status, Status.WARN)
        strict = parse_policy({"policy": {"dependencies": {"require_lockfile": True}}})
        self.assertEqual(decide(strict, dependency=dep).status, Status.FAIL)

    def test_invalid_sbom_fails_and_missing_sbom_is_indeterminate(self) -> None:
        bad = (SBOMValidationReport("SPDX", "2.3", False, ("broken",), ()),)
        self.assertEqual(decide(sbom_validation=bad).status, Status.FAIL)
        self.assertEqual(decide(sbom_validation=None).status, Status.INDETERMINATE)

    def test_licenses(self) -> None:
        def mk(status: LicenseStatus) -> tuple[LicenseFinding, ...]:
            return (LicenseFinding("p", "x", "x", status, "r"),)

        self.assertEqual(decide(licenses=mk(LicenseStatus.DENIED)).status, Status.FAIL)
        self.assertEqual(decide(licenses=mk(LicenseStatus.UNKNOWN)).status, Status.WARN)
        strict = parse_policy({"policy": {"licenses": {"unknown_license": "FAIL"}}})
        self.assertEqual(decide(strict, licenses=mk(LicenseStatus.INVALID)).status, Status.FAIL)

    def test_integrity_requirements(self) -> None:
        req = parse_policy({"policy": {"integrity": {"require_sha256": True}}})
        self.assertEqual(decide(req).status, Status.INDETERMINATE)
        ok = IntegrityResult("a", 1, "0" * 64, "0" * 64, Status.PASS, "ok")
        self.assertEqual(decide(req, integrity=ok).status, Status.PASS)
        bad = dataclasses.replace(ok, status=Status.FAIL)
        self.assertEqual(decide(integrity=bad).status, Status.FAIL)
        unverified = dataclasses.replace(ok, status=Status.INDETERMINATE)
        self.assertEqual(decide(integrity=unverified).status, Status.WARN)
        self.assertEqual(decide(req, integrity=unverified).status, Status.INDETERMINATE)
        self.assertFalse(engine(decide(), "Artifact Integrity").evaluated)

    def test_provenance_requirements(self) -> None:
        req = parse_policy({"policy": {"provenance": {"require_provenance": True}}})
        r = decide(req)
        self.assertEqual(r.status, Status.INDETERMINATE)
        self.assertTrue(any("unavailable" in x for x in r.reasons))
        prov = ProvenanceResult(
            True,
            (
                Check("subject_digest_match", Status.PASS, "ok"),
                Check("sigstore_signature", Status.INDETERMINATE, "none"),
            ),
            Status.INDETERMINATE,
            False,
            None,
            None,
            None,
        )
        self.assertEqual(
            decide(provenance=prov).status, Status.WARN
        )  # not required: only a warning
        sig = parse_policy({"policy": {"provenance": {"require_verified_signature": True}}})
        self.assertEqual(decide(sig, provenance=prov).status, Status.INDETERMINATE)
        failing = ProvenanceResult(
            True,
            (Check("subject_digest_match", Status.FAIL, "mismatch"),),
            Status.FAIL,
            False,
            None,
            None,
            None,
        )
        self.assertEqual(decide(provenance=failing).status, Status.FAIL)

    def test_waivers(self) -> None:
        rep = vuln_report([match(Severity.CRITICAL)])
        active = parse_policy(
            {
                "policy": {
                    "vulnerabilities": {
                        "waivers": [{"id": "V-1", "justification": "n/a", "expires": "2026-06-01"}]
                    }
                }
            }
        )
        self.assertEqual(decide(active, vulnerability=rep).status, Status.PASS)
        expired = parse_policy(
            {
                "policy": {
                    "vulnerabilities": {
                        "waivers": [{"id": "V-1", "justification": "n/a", "expires": "2026-01-01"}]
                    }
                }
            }
        )
        r = decide(expired, vulnerability=rep)
        self.assertEqual(r.status, Status.FAIL)
        self.assertTrue(any("expired" in x for x in r.reasons))

    def test_waiver_applies_to_aliases(self) -> None:
        from aegischain.domain.models import Vulnerability

        v = Vulnerability("GHSA-1", ("CVE-1",), "s", Severity.CRITICAL, "t", None, (), None, None)
        rep = dataclasses.replace(
            vuln_report([match(Severity.CRITICAL, vid="GHSA-1")]), vulnerabilities=(v,)
        )
        p = parse_policy(
            {
                "policy": {
                    "vulnerabilities": {
                        "waivers": [{"id": "CVE-1", "justification": "j", "expires": "2027-01-01"}]
                    }
                }
            }
        )
        self.assertEqual(decide(p, vulnerability=rep).status, Status.PASS)

    def test_determinism(self) -> None:
        ev = evidence(
            vulnerability=vuln_report([match(Severity.HIGH), match(Severity.CRITICAL, vid="V-2")])
        )
        p = SecurityPolicy()
        self.assertEqual(evaluate_policy(ev, p), evaluate_policy(ev, p))


class PolicyParserTests(unittest.TestCase):
    def test_example_policy_parses(self) -> None:
        from pathlib import Path

        from aegischain.engines.policy import load_policy

        root = Path(__file__).resolve().parents[3] / "configs" / "policies"
        for f in sorted(root.glob("*.yaml")):
            self.assertTrue(load_policy(f).name, f)

    def test_strictness(self) -> None:
        bad = [
            None,
            [],
            {"policy": {"unknown": 1}},
            {"policy": {"vulnerabilities": {"block_on": ["SEVERE"]}}},
            {"policy": {"vulnerabilities": {"fail_on_unfixed": "yes"}}},
            {"policy": {"vulnerabilities": {"on_unscanned": "PASS"}}},
            {
                "policy": {"vulnerabilities": {"waivers": [{"id": "x", "justification": "j"}]}}
            },  # no expiry
            {"policy": {"licenses": {"denied": "GPL"}}},
            {"typo": {}},
            {"policy": {"name": ""}},
        ]
        for doc in bad:
            with self.assertRaises(PolicyError, msg=str(doc)):
                parse_policy(doc)

    def test_defaults(self) -> None:
        p = parse_policy({"policy": {"name": "x"}})
        self.assertEqual(p.vulnerabilities.block_on, (Severity.CRITICAL,))


if __name__ == "__main__":
    unittest.main()
