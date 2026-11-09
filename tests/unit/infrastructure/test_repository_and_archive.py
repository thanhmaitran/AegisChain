import io
import sqlite3
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from aegischain.application.pipeline import AnalysisPipeline, AnalysisRequest
from aegischain.exceptions import ArchiveError
from aegischain.infrastructure.archive import ArchiveLimits, extract_archive
from aegischain.infrastructure.repository import SqliteRepository

from tests.helpers import CLOCK, EXAMPLE_PY


class RepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = SqliteRepository()
        self.addCleanup(self.repo.close)
        self.out = AnalysisPipeline(clock=CLOCK).run(AnalysisRequest(EXAMPLE_PY))

    def test_project_run_round_trip(self) -> None:
        p = self.repo.create_project("demo")
        run = self.repo.save_run(p["id"], self.out.report, {"cyclonedx": self.out.sbom.cyclonedx})
        got = self.repo.get_run(run)
        self.assertEqual(got["decision"], self.out.report.decision.value)
        self.assertEqual(got["report"]["evidence_digest"], self.out.report.evidence_digest)
        self.assertEqual(self.repo.get_sbom(run, "cyclonedx")["bomFormat"], "CycloneDX")
        self.assertIsNone(self.repo.get_sbom(run, "spdx"))
        self.assertEqual(len(self.repo.list_runs(p["id"])), 1)
        self.assertEqual(self.repo.list_projects()[0]["name"], "demo")

    def test_unique_project_names_and_foreign_keys(self) -> None:
        self.repo.create_project("a")
        with self.assertRaises(sqlite3.IntegrityError):
            self.repo.create_project("a")
        with self.assertRaises(sqlite3.IntegrityError):
            self.repo.save_run("no-such-project", self.out.report)

    def test_audit_log_is_append_only(self) -> None:
        p = self.repo.create_project("x")
        self.repo.save_run(p["id"], self.out.report)
        events = [e["event"] for e in self.repo.list_audit()]
        self.assertEqual(events, ["project.created", "analysis.saved"])
        with self.assertRaises(sqlite3.DatabaseError):
            self.repo._conn.execute("UPDATE audit_log SET event='tampered'")
        with self.assertRaises(sqlite3.DatabaseError):
            self.repo._conn.execute("DELETE FROM audit_log")

    def test_runs_are_immutable(self) -> None:
        p = self.repo.create_project("x")
        run = self.repo.save_run(p["id"], self.out.report)
        with self.assertRaises(sqlite3.DatabaseError):
            self.repo._conn.execute("UPDATE analysis_runs SET decision='PASS' WHERE id=?", (run,))

    def test_missing_lookups(self) -> None:
        self.assertIsNone(self.repo.get_run("nope"))
        self.assertIsNone(self.repo.get_project("nope"))


def make_zip(entries: dict[str, bytes], symlink: str | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = 0o120777 << 16
            zf.writestr(info, "/etc/passwd")
    return buf.getvalue()


class ArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.dest = self.dir / "out"
        self.dest.mkdir()

    def extract(self, data: bytes, limits=None):
        path = self.dir / "a.bin"
        path.write_bytes(data)
        self.dest = Path(tempfile.mkdtemp(dir=self.dir))  # fresh destination per call
        return extract_archive(path, self.dest, limits)

    def test_zip_extracts(self) -> None:
        self.assertEqual(self.extract(make_zip({"a/b.txt": b"hi", "c.txt": b"x"})), 2)
        self.assertEqual((self.dest / "a" / "b.txt").read_bytes(), b"hi")

    def test_zip_slip_variants_rejected(self) -> None:
        for name in [
            "../evil.txt",
            "a/../../evil.txt",
            "/abs.txt",
            "C:/win.txt",
            "a\\..\\evil.txt",
        ]:
            with self.assertRaises(ArchiveError, msg=name):
                self.extract(make_zip({name: b"x"}))
        self.assertFalse((self.dir / "evil.txt").exists())

    def test_zip_symlink_rejected(self) -> None:
        with self.assertRaises(ArchiveError):
            self.extract(make_zip({"ok.txt": b"x"}, symlink="link"))

    def test_tar_links_and_traversal_rejected(self) -> None:
        for kind in ("sym", "hard", "traversal"):
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tf:
                info = tarfile.TarInfo("../x" if kind == "traversal" else "l")
                if kind == "sym":
                    info.type, info.linkname = tarfile.SYMTYPE, "/etc/passwd"
                elif kind == "hard":
                    info.type, info.linkname = tarfile.LNKTYPE, "other"
                else:
                    info.size = 1
                tf.addfile(info, io.BytesIO(b"x") if kind == "traversal" else None)
            with self.assertRaises(ArchiveError, msg=kind):
                self.extract(buf.getvalue())

    def test_tar_gz_extracts(self) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            info = tarfile.TarInfo("pkg/requirements.txt")
            info.size = 4
            tf.addfile(info, io.BytesIO(b"a==1"))
        self.assertEqual(self.extract(buf.getvalue()), 1)

    def test_size_and_member_limits(self) -> None:
        with self.assertRaises(ArchiveError):
            self.extract(make_zip({"big": b"0" * 5000}), ArchiveLimits(max_total_bytes=1000))
        with self.assertRaises(ArchiveError):
            self.extract(make_zip({"big": b"0" * 5000}), ArchiveLimits(max_member_bytes=1000))
        with self.assertRaises(ArchiveError):
            self.extract(make_zip({f"f{i}": b"x" for i in range(5)}), ArchiveLimits(max_members=3))

    def test_non_archive_rejected(self) -> None:
        with self.assertRaises(ArchiveError):
            self.extract(b"plain text")


if __name__ == "__main__":
    unittest.main()
