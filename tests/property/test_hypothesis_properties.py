"""Hypothesis-based properties. Skipped automatically when Hypothesis is not installed."""

import hashlib
import tempfile
import unittest
from pathlib import Path

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st
except ImportError as exc:  # pragma: no cover
    raise unittest.SkipTest("hypothesis is not installed") from exc

from aegischain.domain.status import Status
from aegischain.engines.dependency.parsers.common import normalize_pypi_name
from aegischain.engines.integrity.hasher import hash_file, verify_artifact


class HypothesisProperties(unittest.TestCase):
    @settings(max_examples=100, deadline=None)
    @given(st.binary(max_size=4096), st.integers(min_value=1, max_value=512))
    def test_streaming_hash_equals_reference(self, data: bytes, chunk: int) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f"
            p.write_bytes(data)
            self.assertEqual(hash_file(p, chunk_size=chunk)[0], hashlib.sha256(data).hexdigest())

    @settings(max_examples=100, deadline=None)
    @given(st.binary(min_size=1, max_size=2048), st.data())
    def test_single_bit_flip_is_always_detected(self, data: bytes, draw) -> None:
        index = draw.draw(st.integers(0, len(data) - 1))
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f"
            mutated = bytearray(data)
            mutated[index] ^= 1
            p.write_bytes(bytes(mutated))
            self.assertEqual(
                verify_artifact(p, hashlib.sha256(data).hexdigest()).status, Status.FAIL
            )

    @settings(max_examples=200)
    @given(st.text(alphabet="abcXYZ-_.0123", min_size=1, max_size=20))
    def test_pypi_normalisation_is_idempotent(self, name: str) -> None:
        once = normalize_pypi_name(name)
        self.assertEqual(normalize_pypi_name(once), once)
