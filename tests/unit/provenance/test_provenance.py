import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from aegischain.domain.status import Status
from aegischain.engines.provenance.parsers.slsa_provenance_parser import (
    load_provenance,
    normalize_repo_uri,
)
from aegischain.engines.provenance.verifiers.provenance_verifier import (
    ProvenanceExpectations,
    verify_provenance,
)
from aegischain.engines.provenance.verifiers.signature_verifier import (
    SigstoreCliVerifier,
    StaticSignatureVerifier,
    UnavailableSignatureVerifier,
)
from aegischain.exceptions import ParseError

from tests.helpers import dsse, slsa_statement

SHA = hashlib.sha256(b"artifact").hexdigest()
BUILDER = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.0.0"
TRUST = ProvenanceExpectations(
    trusted_builders=(
        "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/*",
    ),
    trusted_sources=("https://github.com/acme/app",),
    signer_identity="https://github.com/acme/app/.github/workflows/release.yml@refs/tags/v1",
    oidc_issuer="https://token.actions.githubusercontent.com",
)


class ProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.artifact = self.dir / "app.tar.gz"
        self.artifact.write_bytes(b"artifact")

    def prov(self, text: str, name="p.json") -> Path:
        p = self.dir / name
        p.write_text(text)
        return p

    def verify(self, p, sig=Status.PASS, expect=TRUST, bundle=None, sha=SHA):
        return verify_provenance(
            self.artifact, sha, p, bundle, expect, StaticSignatureVerifier(sig)
        )

    def checks(self, res):
        return {c.name: c.status for c in res.checks}

    def test_fully_valid_evidence_passes(self) -> None:
        res = self.verify(self.prov(dsse(slsa_statement(SHA))), bundle=self.dir / "b")
        self.assertEqual(res.status, Status.PASS, self.checks(res))
        self.assertTrue(res.signature_verified)
        self.assertEqual(res.source_uri, "https://github.com/acme/app")
        self.assertEqual(res.builder_id, BUILDER)

    def test_subject_digest_mismatch_fails(self) -> None:
        res = self.verify(self.prov(dsse(slsa_statement("0" * 64))), bundle=self.dir / "b")
        self.assertEqual(self.checks(res)["subject_digest_match"], Status.FAIL)
        self.assertEqual(res.status, Status.FAIL)

    def test_untrusted_builder_and_source_fail(self) -> None:
        stmt = slsa_statement(
            SHA, builder="https://evil.example/builder", source="https://github.com/evil/app"
        )
        c = self.checks(self.verify(self.prov(dsse(stmt)), bundle=self.dir / "b"))
        self.assertEqual(
            (c["builder_identity"], c["source_repository"]), (Status.FAIL, Status.FAIL)
        )

    def test_no_trust_policy_is_indeterminate_not_pass(self) -> None:
        res = self.verify(
            self.prov(dsse(slsa_statement(SHA))),
            expect=ProvenanceExpectations(),
            bundle=self.dir / "b",
        )
        c = self.checks(res)
        self.assertEqual(
            (c["builder_identity"], c["source_repository"]), (Status.INDETERMINATE,) * 2
        )
        self.assertEqual(res.status, Status.INDETERMINATE)

    def test_signature_states_are_not_conflated_with_digest_match(self) -> None:
        p = self.prov(dsse(slsa_statement(SHA)))
        for sig in (Status.FAIL, Status.INDETERMINATE):
            res = self.verify(p, sig=sig, bundle=self.dir / "b")
            self.assertEqual(self.checks(res)["subject_digest_match"], Status.PASS)
            self.assertEqual(res.status, sig)
            self.assertFalse(res.signature_verified)

    def test_missing_bundle_leaves_signature_indeterminate(self) -> None:
        res = self.verify(self.prov(dsse(slsa_statement(SHA))))
        self.assertEqual(self.checks(res)["sigstore_signature"], Status.INDETERMINATE)

    def test_sigstore_bundle_doubles_as_signature_bundle(self) -> None:
        bundle = {
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
            "dsseEnvelope": json.loads(dsse(slsa_statement(SHA))),
        }
        res = self.verify(self.prov(json.dumps(bundle)))
        self.assertEqual(self.checks(res)["sigstore_signature"], Status.PASS)

    def test_malformed_evidence_fails(self) -> None:
        for text in [
            "not json",
            "{}",
            json.dumps({"_type": "https://in-toto.io/Statement/v1", "subject": []}),
            json.dumps({"payloadType": "x", "payload": "!!!"}),
        ]:
            res = self.verify(self.prov(text), bundle=self.dir / "b")
            self.assertEqual(self.checks(res)["provenance_parsed"], Status.FAIL, text)

    def test_non_slsa_predicate_fails(self) -> None:
        stmt = slsa_statement(SHA)
        stmt["predicateType"] = "https://spdx.dev/Document"
        self.assertEqual(
            self.checks(self.verify(self.prov(dsse(stmt)), bundle=self.dir / "b"))[
                "predicate_type"
            ],
            Status.FAIL,
        )

    def test_slsa_v02_fields(self) -> None:
        stmt = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "subject": [{"name": "a", "digest": {"sha256": SHA}}],
            "predicate": {
                "builder": {"id": BUILDER},
                "invocation": {
                    "configSource": {"uri": "git+https://github.com/acme/app@refs/heads/main"}
                },
            },
        }
        s = load_provenance(self.prov(json.dumps(stmt)))
        self.assertEqual((s.builder_id, s.source_uri), (BUILDER, "https://github.com/acme/app"))

    def test_jsonlines_attestation_download(self) -> None:
        lines = json.dumps({"junk": 1}) + "\n" + dsse(slsa_statement(SHA)).replace("\n", "") + "\n"
        self.assertEqual(load_provenance(self.prov(lines)).subjects[0][1]["sha256"], SHA)

    def test_absent_provenance(self) -> None:
        res = verify_provenance(
            self.artifact, SHA, None, None, TRUST, UnavailableSignatureVerifier()
        )
        self.assertEqual((res.provided, res.status), (False, Status.INDETERMINATE))

    def test_unknown_artifact_digest_is_indeterminate(self) -> None:
        res = self.verify(self.prov(dsse(slsa_statement(SHA))), bundle=self.dir / "b", sha=None)
        self.assertEqual(self.checks(res)["subject_digest_match"], Status.INDETERMINATE)

    def test_repo_uri_normalisation(self) -> None:
        for raw in [
            "git+https://GitHub.com/acme/app.git@refs/heads/main",
            "https://github.com/acme/app/",
            "https://github.com/acme/app#frag",
        ]:
            self.assertEqual(normalize_repo_uri(raw), "https://github.com/acme/app", raw)
        self.assertIsNone(normalize_repo_uri("git@github.com:acme/app"))

    def test_oversized_provenance(self) -> None:
        with self.assertRaises(ParseError):
            load_provenance(self.dir / "missing.json")


class SigstoreCliTests(unittest.TestCase):
    def test_missing_identity_or_binary_never_passes(self) -> None:
        v = SigstoreCliVerifier(executable="definitely-not-installed-xyz")
        self.assertEqual(v.verify(Path("a"), Path("b"), None, None).status, Status.INDETERMINATE)
        self.assertEqual(v.verify(Path("a"), Path("b"), "id", "iss").status, Status.INDETERMINATE)


if __name__ == "__main__":
    unittest.main()
