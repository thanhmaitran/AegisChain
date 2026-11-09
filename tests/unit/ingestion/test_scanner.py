import os
import tempfile
import unittest
from pathlib import Path

from aegischain.domain.models import IngestionStatus
from aegischain.engines.ingestion.scanner import (
    IngestionLimits,
    RepositoryInput,
    load_file,
    scan_repository,
)
from aegischain.exceptions import IngestionError, ValidationError

from tests.helpers import EXAMPLE_NODE, EXAMPLE_PY, write_files


class ScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def scan(self, **kw):
        return scan_repository(RepositoryInput(self.root, **kw))

    def test_discovers_python_and_node_files(self) -> None:
        py = scan_repository(RepositoryInput(EXAMPLE_PY))
        self.assertEqual(py.status, IngestionStatus.OK)
        self.assertEqual([f.path for f in py.discovered_files], ["poetry.lock", "pyproject.toml"])
        node = scan_repository(RepositoryInput(EXAMPLE_NODE))
        self.assertEqual(node.supported_ecosystems, ("npm",))

    def test_skips_node_modules_and_vcs(self) -> None:
        write_files(
            self.root,
            {
                "package.json": "{}",
                "node_modules/x/package.json": "{}",
                ".git/requirements.txt": "x",
            },
        )
        self.assertEqual([f.path for f in self.scan().discovered_files], ["package.json"])

    def test_sensitive_files_are_never_read(self) -> None:
        write_files(
            self.root,
            {
                "requirements.txt": "a==1\n",
                ".env": "SECRET=1",
                "server.pem": "KEY",
                "id_rsa": "KEY",
            },
        )
        res = self.scan()
        self.assertEqual(sorted(res.skipped_sensitive), [".env", "id_rsa", "server.pem"])
        self.assertEqual([f.path for f in res.discovered_files], ["requirements.txt"])

    def test_symlinks_are_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            Path(outside, "package.json").write_text("{}")
            Path(outside, "sub").mkdir()
            Path(outside, "sub", "package.json").write_text("{}")
            write_files(self.root, {"requirements.txt": "a==1\n"})
            os.symlink(Path(outside, "package.json"), self.root / "package.json")
            os.symlink(Path(outside, "sub"), self.root / "linked")
            res = self.scan()
        self.assertEqual([f.path for f in res.discovered_files], ["requirements.txt"])
        self.assertTrue(any("Symbolic link" in w for w in res.warnings))

    def test_oversized_file_is_reported_not_parsed(self) -> None:
        write_files(self.root, {"requirements.txt": "a==1\n", "package.json": "x" * 200})
        res = self.scan(limits=IngestionLimits(max_file_bytes=100))
        self.assertEqual(res.status, IngestionStatus.PARTIAL)
        self.assertTrue(any("exceeds limit" in e for e in res.errors))

    def test_file_count_limit(self) -> None:
        write_files(
            self.root, {f"f{i}.txt": "x" for i in range(10)} | {"requirements.txt": "a==1\n"}
        )
        res = self.scan(limits=IngestionLimits(max_files=3))
        self.assertEqual(
            res.status,
            IngestionStatus.FAILED if not res.discovered_files else IngestionStatus.PARTIAL,
        )
        self.assertTrue(any("File limit" in e for e in res.errors))

    def test_depth_limit(self) -> None:
        write_files(self.root, {"a/b/c/d/package.json": "{}", "package.json": "{}"})
        res = self.scan(limits=IngestionLimits(max_depth=2))
        self.assertEqual([f.path for f in res.discovered_files], ["package.json"])

    def test_missing_root_raises(self) -> None:
        with self.assertRaises(IngestionError):
            scan_repository(RepositoryInput(self.root / "nope"))

    def test_file_as_root_raises(self) -> None:
        f = self.root / "x"
        f.write_text("x")
        with self.assertRaises(IngestionError):
            scan_repository(RepositoryInput(f))

    def test_no_manifests_is_failed_not_ok(self) -> None:
        write_files(self.root, {"README.md": "hi"})
        res = self.scan()
        self.assertEqual(res.status, IngestionStatus.FAILED)

    def test_unsupported_formats_are_reported(self) -> None:
        write_files(self.root, {"package.json": "{}", "yarn.lock": "x", "go.mod": "module x"})
        res = self.scan()
        self.assertEqual(res.unsupported_files, ("go.mod", "yarn.lock"))

    def test_repository_id_is_deterministic_and_content_sensitive(self) -> None:
        write_files(self.root, {"requirements.txt": "a==1\n"})
        first = self.scan().repository_id
        self.assertEqual(first, self.scan().repository_id)
        (self.root / "requirements.txt").write_text("a==2\n")
        self.assertNotEqual(first, self.scan().repository_id)

    def test_load_file_detects_modification_after_ingestion(self) -> None:
        write_files(self.root, {"requirements.txt": "a==1\n"})
        res = self.scan()
        (self.root / "requirements.txt").write_text("a==666\n")
        with self.assertRaises(ValidationError):
            load_file(self.root, res.discovered_files[0], 1000)

    def test_requirements_variants_are_recognised(self) -> None:
        write_files(
            self.root,
            {"requirements-dev.txt": "a==1\n", "requirements/base.txt": "b==1\n", "notes.txt": "x"},
        )
        self.assertEqual(
            [f.path for f in self.scan().discovered_files],
            ["requirements-dev.txt", "requirements/base.txt"],
        )


if __name__ == "__main__":
    unittest.main()
