import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aegischain.domain.status import Status
from aegischain.engines.integrity import hasher
from aegischain.engines.integrity.hasher import hash_file, normalize_digest, verify_artifact


class IntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def make(self, data: bytes, name="a.bin") -> Path:
        p = self.dir / name
        p.write_bytes(data)
        return p

    def test_empty_file(self) -> None:
        self.assertEqual(hash_file(self.make(b"")), (hashlib.sha256(b"").hexdigest(), 0))

    def test_streaming_matches_hashlib_across_chunk_boundaries(self) -> None:
        data = os.urandom(1000)
        for chunk in (1, 7, 999, 1000, 4096):
            self.assertEqual(
                hash_file(self.make(data), chunk_size=chunk)[0], hashlib.sha256(data).hexdigest()
            )

    def test_match_pass_mismatch_fail(self) -> None:
        p, good = self.make(b"hello"), hashlib.sha256(b"hello").hexdigest()
        self.assertEqual(verify_artifact(p, good).status, Status.PASS)
        self.assertEqual(verify_artifact(p, "sha256:" + good.upper()).status, Status.PASS)
        self.assertEqual(verify_artifact(p, "0" * 64).status, Status.FAIL)

    def test_modified_artifact_is_detected(self) -> None:
        p, good = self.make(b"v1"), hashlib.sha256(b"v1").hexdigest()
        p.write_bytes(b"v1-tampered")
        self.assertEqual(verify_artifact(p, good).status, Status.FAIL)

    def test_no_reference_digest_is_not_a_pass(self) -> None:
        r = verify_artifact(self.make(b"x"), None)
        self.assertEqual(r.status, Status.INDETERMINATE)
        self.assertEqual(r.sha256, hashlib.sha256(b"x").hexdigest())

    def test_missing_invalid_and_non_regular(self) -> None:
        self.assertEqual(verify_artifact(self.dir / "nope", "0" * 64).status, Status.INDETERMINATE)
        self.assertEqual(verify_artifact(self.make(b"x"), "xyz").status, Status.INDETERMINATE)
        self.assertEqual(verify_artifact(self.dir, "0" * 64).status, Status.INDETERMINATE)
        self.assertEqual(verify_artifact(None, None).status, Status.INDETERMINATE)

    def test_symlink_is_refused(self) -> None:
        target = self.make(b"x")
        link = self.dir / "link"
        os.symlink(target, link)
        self.assertEqual(
            verify_artifact(link, hashlib.sha256(b"x").hexdigest()).status, Status.INDETERMINATE
        )

    def test_file_changing_during_hashing_is_indeterminate(self) -> None:
        p = self.make(b"a" * 100)
        original = hasher.os.fstat
        calls = {"n": 0}

        def flaky(fd):
            st = original(fd)
            calls["n"] += 1
            if calls["n"] >= 2:  # second fstat (after reading) sees a different size
                return mock.Mock(
                    st_size=st.st_size + 1, st_mtime_ns=st.st_mtime_ns, st_mode=st.st_mode
                )
            return st

        with mock.patch.object(hasher.os, "fstat", flaky):
            self.assertEqual(verify_artifact(p, "0" * 64).status, Status.INDETERMINATE)

    def test_normalize_digest(self) -> None:
        self.assertIsNone(normalize_digest("abc"))
        self.assertEqual(normalize_digest("SHA256:" + "A" * 64), "a" * 64)


if __name__ == "__main__":
    unittest.main()
