"""Repository contract tests.

The SQLite implementation always runs. The SQLAlchemy/PostgreSQL implementation runs when
``AEGISCHAIN_DATABASE_URL`` points to a migrated database (``alembic upgrade head``), as in CI.
"""

import os
import unittest
import uuid

from aegischain.application.pipeline import AnalysisPipeline, AnalysisRequest
from aegischain.infrastructure.repository import SqliteRepository

from tests.helpers import CLOCK, EXAMPLE_PY


def make_postgres():
    url = os.environ.get("AEGISCHAIN_DATABASE_URL", "")
    if not url.startswith("postgresql"):
        raise unittest.SkipTest("AEGISCHAIN_DATABASE_URL (postgresql) not set")
    from aegischain.infrastructure.sqlalchemy_repository import SqlAlchemyRepository

    return SqlAlchemyRepository(url)


class RepositoryContract:
    def make(self):  # pragma: no cover - overridden
        raise NotImplementedError

    def setUp(self) -> None:
        self.repo = self.make()
        self.report = AnalysisPipeline(clock=CLOCK).run(AnalysisRequest(EXAMPLE_PY)).report

    def test_round_trip(self) -> None:
        project = self.repo.create_project(f"p-{uuid.uuid4().hex[:8]}")
        run = self.repo.save_run(
            project["id"], self.report, {"cyclonedx": {"bomFormat": "CycloneDX"}}
        )
        got = self.repo.get_run(run)
        self.assertEqual(got["decision"], self.report.decision.value)
        self.assertEqual(got["report"]["evidence_digest"], self.report.evidence_digest)
        self.assertEqual(self.repo.get_sbom(run, "cyclonedx")["bomFormat"], "CycloneDX")
        self.assertEqual([r["id"] for r in self.repo.list_runs(project["id"])], [run])
        self.assertIn("analysis.saved", [e["event"] for e in self.repo.list_audit(run)])


class SqliteContract(RepositoryContract, unittest.TestCase):
    def make(self):
        return SqliteRepository()


class PostgresContract(RepositoryContract, unittest.TestCase):
    def make(self):
        return make_postgres()


if __name__ == "__main__":
    unittest.main()
