"""Security-boundary tests: hostile repository content must never crash or escape."""

import os
import tempfile
import unittest
from pathlib import Path

from aegischain.application.pipeline import AnalysisPipeline, AnalysisRequest
from aegischain.domain.status import Status
from aegischain.engines.ingestion.scanner import IngestionLimits
from aegischain.engines.policy import load_policy
from aegischain.exceptions import PolicyError

from tests.helpers import CLOCK, write_files


class HostileRepository(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def run_pipeline(self):
        return AnalysisPipeline(clock=CLOCK).run(
            AnalysisRequest(self.root, limits=IngestionLimits(max_file_bytes=1_000_000))
        )

    def test_deeply_nested_json_does_not_crash(self) -> None:
        write_files(self.root, {"package.json": "[" * 100000 + "]" * 100000})
        out = self.run_pipeline()
        self.assertEqual(out.report.dependency.status, Status.INDETERMINATE)

    def test_binary_garbage_in_every_manifest_type(self) -> None:
        write_files(
            self.root,
            {
                n: os.urandom(300)
                for n in (
                    "requirements.txt",
                    "pyproject.toml",
                    "poetry.lock",
                    "uv.lock",
                    "package.json",
                    "package-lock.json",
                )
            },
        )
        out = self.run_pipeline()
        self.assertNotEqual(out.report.decision, Status.PASS)
        self.assertEqual(out.report.dependency.components, ())

    def test_credential_files_are_not_read_or_leaked(self) -> None:
        write_files(
            self.root,
            {
                "requirements.txt": "a==1\n",
                ".env": "TOKEN=hunter2-super-secret",
                "deploy.key": "hunter2-super-secret",
            },
        )
        out = self.run_pipeline()
        from aegischain.application.report import render_markdown
        from aegischain.utils.serialization import canonical_json

        blob = canonical_json(out.report) + render_markdown(out.report)
        self.assertNotIn("hunter2", blob)
        self.assertEqual(sorted(out.report.ingestion.skipped_sensitive), [".env", "deploy.key"])

    def test_symlink_to_secret_outside_root_is_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            secret = Path(outside, "package.json")
            secret.write_text('{"dependencies": {"leaked-from-outside": "1.0.0"}}')
            write_files(self.root, {"requirements.txt": "a==1\n"})
            os.symlink(secret, self.root / "package.json")
            out = self.run_pipeline()
        self.assertNotIn("leaked-from-outside", {c.name for c in out.report.dependency.components})

    def test_path_like_package_names_do_not_affect_filesystem(self) -> None:
        write_files(
            self.root,
            {"package.json": '{"dependencies": {"../../etc/passwd": "1.0.0", "a\\u0000b": "1"}}'},
        )
        out = self.run_pipeline()
        self.assertTrue(out.report.dependency.components)  # handled as data
        self.assertTrue(out.sbom.valid)

    def test_hostile_lockfile_graph_with_huge_cycle_terminates(self) -> None:
        import json

        pk = {"": {}}
        n = 2000
        for i in range(n):
            pk[f"node_modules/p{i}"] = {
                "version": "1.0.0",
                "dependencies": {f"p{(i + 1) % n}": "1"},
            }
        write_files(
            self.root, {"package-lock.json": json.dumps({"lockfileVersion": 3, "packages": pk})}
        )
        out = self.run_pipeline()
        self.assertEqual(len(out.report.dependency.components), n)

    def test_huge_manifest_beyond_limit_is_rejected(self) -> None:
        write_files(self.root, {"package.json": "x" * 2_000_000})
        out = self.run_pipeline()
        self.assertEqual(out.report.decision, Status.INDETERMINATE)


class PolicyFileSecurity(unittest.TestCase):
    def test_yaml_code_execution_tags_are_refused(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("policy: !!python/object/apply:os.system ['echo pwned']\n")
        try:
            with self.assertRaises(PolicyError):
                load_policy(Path(f.name))
        finally:
            os.unlink(f.name)

    def test_empty_policy_is_refused_not_defaulted(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("")
        try:
            with self.assertRaises(PolicyError):
                load_policy(Path(f.name))
        finally:
            os.unlink(f.name)


if __name__ == "__main__":
    unittest.main()
