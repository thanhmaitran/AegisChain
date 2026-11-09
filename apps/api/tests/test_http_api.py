"""HTTP-level tests. Require fastapi + httpx (install with ``pip install -e '.[api,dev]'``)."""

import io
import unittest

try:
    from fastapi.testclient import TestClient
except ImportError as exc:  # pragma: no cover
    raise unittest.SkipTest("fastapi/httpx not installed") from exc

from aegischain.application.pipeline import AnalysisPipeline
from aegischain.engines.vulnerability.provider import StaticVulnerabilityProvider
from aegischain.infrastructure.repository import SqliteRepository
from aegischain_api.main import create_app
from aegischain_api.services import AnalysisService
from aegischain_api.settings import Settings

from apps.api.tests.test_services import zip_of
from tests.helpers import CLOCK, EXAMPLE_NODE, ROOT

KEY = "k" * 32
H = {"X-API-Key": KEY}


class HttpApiTests(unittest.TestCase):
    def setUp(self) -> None:
        settings = Settings(
            api_key=KEY, policy_dir=ROOT / "configs" / "policies", max_upload_bytes=2_000_000
        )
        svc = AnalysisService(
            SqliteRepository(),
            lambda: AnalysisPipeline(StaticVulnerabilityProvider({}, CLOCK), clock=CLOCK),
            settings.policy_dir,
            settings.max_upload_bytes,
        )
        self.client = TestClient(create_app(settings, svc))

    def test_authentication_is_required(self) -> None:
        self.assertEqual(self.client.get("/api/v1/projects").status_code, 401)
        self.assertEqual(
            self.client.get("/api/v1/projects", headers={"X-API-Key": "wrong"}).status_code, 401
        )
        self.assertEqual(self.client.get("/health").status_code, 200)

    def test_full_flow(self) -> None:
        pid = self.client.post("/api/v1/projects", json={"name": "demo"}, headers=H).json()["id"]
        r = self.client.post(
            "/api/v1/analysis",
            headers=H,
            data={"project_id": pid, "policy": "default"},
            files={"archive": ("repo.zip", io.BytesIO(zip_of(EXAMPLE_NODE)), "application/zip")},
        )
        self.assertEqual(r.status_code, 201, r.text)
        run = r.json()["id"]
        self.assertEqual(
            self.client.get(f"/api/v1/analysis/{run}", headers=H).json()["decision"],
            r.json()["decision"],
        )
        self.assertEqual(
            self.client.get(f"/api/v1/sbom/{run}?format=spdx", headers=H).json()["spdxVersion"],
            "SPDX-2.3",
        )
        self.assertIn(
            "Final decision",
            self.client.get(f"/api/v1/reports/{run}?format=markdown", headers=H).text,
        )
        self.assertGreater(
            len(self.client.get(f"/api/v1/dependencies/{run}", headers=H).json()["graph"]["nodes"]),
            0,
        )

    def test_input_validation(self) -> None:
        self.assertEqual(
            self.client.post("/api/v1/projects", json={"name": "../x"}, headers=H).status_code, 422
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/projects", json={"name": "ok", "extra": 1}, headers=H
            ).status_code,
            422,
        )
        self.assertEqual(self.client.get("/api/v1/analysis/not-a-uuid", headers=H).status_code, 422)
        self.assertEqual(
            self.client.get(
                "/api/v1/analysis/00000000-0000-0000-0000-000000000000", headers=H
            ).status_code,
            404,
        )

    def test_duplicate_project_conflicts_and_headers(self) -> None:
        self.client.post("/api/v1/projects", json={"name": "dup"}, headers=H)
        r = self.client.post("/api/v1/projects", json={"name": "dup"}, headers=H)
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")

    def test_malicious_archive_is_400(self) -> None:
        pid = self.client.post("/api/v1/projects", json={"name": "p"}, headers=H).json()["id"]
        r = self.client.post(
            "/api/v1/analysis",
            headers=H,
            data={"project_id": pid},
            files={"archive": ("x.zip", io.BytesIO(b"not an archive"), "application/zip")},
        )
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()
