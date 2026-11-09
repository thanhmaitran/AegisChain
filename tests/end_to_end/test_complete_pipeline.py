import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from aegischain.application.pipeline import AnalysisPipeline, AnalysisRequest
from aegischain.application.report import render_markdown, write_outputs
from aegischain.cli import main
from aegischain.domain.status import Status
from aegischain.engines.policy import load_policy, parse_policy
from aegischain.engines.provenance.verifiers.signature_verifier import StaticSignatureVerifier
from aegischain.engines.vulnerability.provider import StaticVulnerabilityProvider

from tests.helpers import CLOCK, EXAMPLE_NODE, EXAMPLE_PY, ROOT, dsse, slsa_statement
from tests.unit.vulnerability.test_vulnerability import pyyaml_record

PRODUCTION = ROOT / "configs" / "policies" / "production-release.yaml"


class PipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_offline_run_is_indeterminate_not_pass(self) -> None:
        out = AnalysisPipeline(clock=CLOCK).run(AnalysisRequest(EXAMPLE_PY))
        self.assertEqual(out.report.decision, Status.INDETERMINATE)
        self.assertTrue(any("NOT evidence" in r for r in out.report.policy_evaluation.reasons))

    def test_vulnerable_component_blocks_release(self) -> None:
        provider = StaticVulnerabilityProvider({"pkg:pypi/pyyaml@5.3": [pyyaml_record()]}, CLOCK)
        out = AnalysisPipeline(provider, clock=CLOCK).run(AnalysisRequest(EXAMPLE_PY))
        self.assertEqual(out.report.decision, Status.FAIL)
        self.assertEqual(out.report.vulnerability.matches[0].fixed_versions, ("5.4",))

    def test_clean_run_with_all_evidence_passes(self) -> None:
        artifact = self.dir / "app.tar.gz"
        artifact.write_bytes(b"release bytes")
        sha = hashlib.sha256(b"release bytes").hexdigest()

        prov = self.dir / "prov.json"
        prov.write_text(dsse(slsa_statement(sha)))

        bundle = self.dir / "bundle.json"
        bundle.write_text("{}")

        policy = parse_policy(
            {
                "policy": {
                    "name": "strict",
                    "dependencies": {"require_lockfile": True},
                    "licenses": {"unknown_license": "PASS"},
                    "provenance": {
                        "require_provenance": True,
                        "require_verified_signature": True,
                        "trusted_builders": [
                            "https://github.com/slsa-framework/slsa-github-generator/*"
                        ],
                        "trusted_sources": ["https://github.com/acme/app"],
                        "signer_identity": "id",
                        "oidc_issuer": "iss",
                    },
                    "integrity": {"require_sha256": True},
                }
            }
        )

        out = AnalysisPipeline(
            StaticVulnerabilityProvider({}, CLOCK),
            StaticSignatureVerifier(Status.PASS),
            CLOCK,
        ).run(
            AnalysisRequest(
                EXAMPLE_NODE,
                policy,
                artifact_path=artifact,
                expected_sha256=sha,
                provenance_path=prov,
                signature_bundle_path=bundle,
            )
        )

        self.assertEqual(
            out.report.decision,
            Status.PASS,
            out.report.policy_evaluation.reasons,
        )
        self.assertTrue(all(e.evaluated for e in out.report.policy_evaluation.engines))

    def test_tampered_artifact_fails_even_if_everything_else_is_fine(self) -> None:
        artifact = self.dir / "app.tar.gz"
        artifact.write_bytes(b"tampered")
        sha = hashlib.sha256(b"original").hexdigest()

        out = AnalysisPipeline(StaticVulnerabilityProvider({}, CLOCK), clock=CLOCK).run(
            AnalysisRequest(
                EXAMPLE_NODE,
                artifact_path=artifact,
                expected_sha256=sha,
            )
        )

        self.assertEqual(out.report.decision, Status.FAIL)

    def test_provider_crash_becomes_indeterminate(self) -> None:
        class Crash:
            def query(self, components):
                raise RuntimeError("bug")

        import logging

        logging.getLogger("aegischain").addHandler(logging.NullHandler())

        out = AnalysisPipeline(Crash(), clock=CLOCK).run(AnalysisRequest(EXAMPLE_PY))

        self.assertEqual(out.report.decision, Status.INDETERMINATE)
        self.assertIn(
            "vulnerability provider crashed: RuntimeError",
            out.report.errors,
        )

    def test_license_evidence_is_applied_only_when_supplied(self) -> None:
        pol = parse_policy({"policy": {"licenses": {"denied": ["MIT"]}}})

        out = AnalysisPipeline(StaticVulnerabilityProvider({}, CLOCK), clock=CLOCK).run(
            AnalysisRequest(
                EXAMPLE_PY,
                pol,
                license_evidence={"pkg:pypi/requests@2.32.0": "MIT"},
            )
        )

        denied = [f.purl for f in out.report.licenses if f.status.value == "DENIED"]
        self.assertEqual(denied, ["pkg:pypi/requests@2.32.0"])

    def test_reproducibility(self) -> None:
        def run():
            return AnalysisPipeline(StaticVulnerabilityProvider({}, CLOCK), clock=CLOCK).run(
                AnalysisRequest(EXAMPLE_NODE)
            )

        a, b = run(), run()

        self.assertEqual(
            a.report.evidence_digest,
            b.report.evidence_digest,
        )
        self.assertEqual(
            json.dumps(a.sbom.cyclonedx, sort_keys=True),
            json.dumps(b.sbom.cyclonedx, sort_keys=True),
        )

    def test_outputs_written(self) -> None:
        out = AnalysisPipeline(StaticVulnerabilityProvider({}, CLOCK), clock=CLOCK).run(
            AnalysisRequest(EXAMPLE_NODE)
        )

        files = {p.relative_to(self.dir).as_posix() for p in write_outputs(out, self.dir)}

        self.assertEqual(
            files,
            {
                "sbom/sbom.cdx.json",
                "sbom/sbom.spdx.json",
                "sbom/validation-report.json",
                "reports/component-inventory.json",
                "reports/dependency-graph.json",
                "reports/report.json",
                "reports/report.md",
            },
        )

        self.assertIn("Final decision", render_markdown(out.report))
        json.loads((self.dir / "reports/report.json").read_text())

    def test_production_policy_loads_and_blocks_without_evidence(self) -> None:
        out = AnalysisPipeline(StaticVulnerabilityProvider({}, CLOCK), clock=CLOCK).run(
            AnalysisRequest(
                EXAMPLE_PY,
                load_policy(PRODUCTION),
            )
        )

        self.assertNotEqual(out.report.decision, Status.PASS)


class CliTests(unittest.TestCase):
    def run_cli(self, *argv):
        buf, err = io.StringIO(), io.StringIO()

        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            code = main(list(argv))

        return code, buf.getvalue(), err.getvalue()

    def test_offline_analysis_exit_code_is_indeterminate(self) -> None:
        code, out, _ = self.run_cli("analyze", str(EXAMPLE_PY), "--offline")

        self.assertEqual(code, 2)
        self.assertIn("INDETERMINATE", out)

    def test_json_output(self) -> None:
        _, out, _ = self.run_cli("analyze", str(EXAMPLE_NODE), "--offline", "--format", "json")

        self.assertEqual(json.loads(out)["report_version"], "1")

    def test_usage_errors_exit_3(self) -> None:
        self.assertEqual(
            self.run_cli("analyze", "/no/such/dir", "--offline")[0],
            3,
        )
        self.assertEqual(
            self.run_cli("validate-policy", "/no/such.yaml")[0],
            3,
        )

    def test_validate_policy_and_verify_artifact(self) -> None:
        self.assertEqual(
            self.run_cli("validate-policy", str(PRODUCTION))[0],
            0,
        )

        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "artifact.bin"
            artifact.write_bytes(b"abc")

            good = hashlib.sha256(b"abc").hexdigest()

            self.assertEqual(
                self.run_cli(
                    "verify-artifact",
                    str(artifact),
                    "--expected-sha256",
                    good,
                )[0],
                0,
            )

            self.assertEqual(
                self.run_cli(
                    "verify-artifact",
                    str(artifact),
                    "--expected-sha256",
                    "0" * 64,
                )[0],
                1,
            )

            self.assertEqual(
                self.run_cli("verify-artifact", str(artifact))[0],
                2,
            )


if __name__ == "__main__":
    unittest.main()
