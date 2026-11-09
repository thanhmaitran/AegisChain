import hashlib
import io
import unittest
import zipfile
from pathlib import Path

from aegischain.application.pipeline import AnalysisPipeline
from aegischain.engines.vulnerability.provider import StaticVulnerabilityProvider
from aegischain.exceptions import ArchiveError, ValidationError
from aegischain.infrastructure.repository import SqliteRepository
from aegischain_api.services import AnalysisService, NotFound
from aegischain_api.settings import ConfigurationError, Settings

from tests.helpers import CLOCK, EXAMPLE_PY, ROOT, dsse, slsa_statement
from tests.unit.vulnerability.test_vulnerability import pyyaml_record


def zip_of(directory: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for f in sorted(directory.rglob("*")):
            if f.is_file():
                zf.write(f, f.relative_to(directory).as_posix())
    return buf.getvalue()


class ServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = SqliteRepository()
        self.addCleanup(self.repo.close)
        provider = StaticVulnerabilityProvider({"pkg:pypi/pyyaml@5.3": [pyyaml_record()]}, CLOCK)
        self.svc = AnalysisService(
            self.repo,
            lambda: AnalysisPipeline(provider, clock=CLOCK),
            ROOT / "configs" / "policies",
            max_upload_bytes=1_000_000,
        )
        self.project = self.repo.create_project("demo")["id"]

    def analyze(self, data: bytes | None = None, policy="default"):
        return self.svc.analyze_archive(
            self.project, io.BytesIO(data or zip_of(EXAMPLE_PY)), policy
        )

    def test_analyze_and_read_back(self) -> None:
        s = self.analyze()
        self.assertEqual((s["decision"], s["components"], s["vulnerabilities"]), ("FAIL", 13, 1))
        run = s["id"]
        self.assertEqual(self.svc.get_run(run)["decision"], "FAIL")
        self.assertEqual(len(self.svc.dependencies(run)["graph"]["nodes"]), 13)
        self.assertEqual(self.svc.vulnerabilities(run)["matches"][0]["osv_id"], "AEGIS-TEST-0001")
        self.assertEqual(self.svc.sbom(run, "spdx")["spdxVersion"], "SPDX-2.3")
        self.assertIn("Final decision: FAIL", self.svc.report(run, "markdown"))
        self.assertEqual(self.svc.report(run)["report_version"], "1")

    def test_reevaluate_with_other_policy_uses_stored_evidence(self) -> None:
        run = self.analyze()["id"]
        self.assertEqual(self.svc.reevaluate(run, "permissive")["status"], "WARN")
        self.assertEqual(self.svc.reevaluate(run, "default")["status"], "FAIL")
        self.assertIn("policy.reevaluated", [e["event"] for e in self.repo.list_audit(run)])

    def test_policy_names_cannot_traverse(self) -> None:
        for bad in ["../default", "default.yaml", "nope", "/etc/passwd", ""]:
            with self.assertRaises(ValidationError, msg=bad):
                self.svc.get_policy(bad)

    def test_unsafe_and_oversized_uploads_rejected(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../evil.txt", "x")
        with self.assertRaises(ArchiveError):
            self.analyze(buf.getvalue())
        self.assertIn("analysis.rejected", [e["event"] for e in self.repo.list_audit()])
        with self.assertRaises(ValidationError):
            self.analyze(b"0" * 1_000_001)

    def test_unknown_ids(self) -> None:
        with self.assertRaises(NotFound):
            self.svc.get_run("nope")
        with self.assertRaises(NotFound):
            self.svc.analyze_archive("nope", io.BytesIO(b""), None)
        run = self.analyze()["id"]
        with self.assertRaises(ValidationError):
            self.svc.sbom(run, "xml")

    def test_artifact_verification(self) -> None:
        data = b"release"
        sha = hashlib.sha256(data).hexdigest()
        ok = self.svc.verify_artifact_upload(io.BytesIO(data), sha, None)
        self.assertEqual(ok["status"], "PASS")
        bad = self.svc.verify_artifact_upload(io.BytesIO(data), "0" * 64, None)
        self.assertEqual(bad["status"], "FAIL")
        prov = dsse(slsa_statement(sha))
        res = self.svc.verify_artifact_upload(
            io.BytesIO(data), sha, "production-release", io.BytesIO(prov.encode())
        )
        self.assertEqual(res["integrity"]["status"], "PASS")
        self.assertNotEqual(res["status"], "PASS")  # no trusted signature -> never PASS


class SettingsTests(unittest.TestCase):
    def test_api_key_is_mandatory(self) -> None:
        with self.assertRaises(ConfigurationError):
            Settings.from_env({})
        with self.assertRaises(ConfigurationError):
            Settings.from_env({"AEGISCHAIN_API_KEY": "short"})
        s = Settings.from_env(
            {"AEGISCHAIN_API_KEY": "x" * 16, "AEGISCHAIN_CORS_ORIGINS": "http://a,http://b"}
        )
        self.assertEqual(s.cors_origins, ("http://a", "http://b"))


if __name__ == "__main__":
    unittest.main()
