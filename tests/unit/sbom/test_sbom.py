import copy
import json
import unittest

from aegischain.engines.sbom.service import generate_sboms
from aegischain.engines.sbom.validator import cross_check, validate_cyclonedx, validate_spdx

from tests.helpers import FIXED_NOW, npm, pypi


def sample():
    b = pypi("urllib3", "2.2.1", direct=False)
    a = pypi("requests", "2.32.0", deps=(b.purl,), lic="Apache-2.0")
    return [a, b, pypi("unpinned", None, lic="Weird License")]


class SbomTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bundle = generate_sboms("app", sample(), "0.1.0", FIXED_NOW)

    def test_valid_and_consistent(self) -> None:
        self.assertTrue(self.bundle.valid, [v.errors for v in self.bundle.validation])

    def test_deterministic(self) -> None:
        again = generate_sboms("app", list(reversed(sample())), "0.1.0", FIXED_NOW)
        self.assertEqual(
            json.dumps(self.bundle.cyclonedx, sort_keys=True),
            json.dumps(again.cyclonedx, sort_keys=True),
        )
        self.assertEqual(self.bundle.spdx["documentNamespace"], again.spdx["documentNamespace"])

    def test_no_invented_data(self) -> None:
        comps = {c["name"]: c for c in self.bundle.cyclonedx["components"]}
        self.assertNotIn("version", comps["unpinned"])  # unknown version stays unknown
        self.assertNotIn("hashes", comps["requests"])  # no evidence -> no hash
        self.assertEqual(comps["unpinned"]["licenses"], [{"license": {"name": "Weird License"}}])
        pk = {p["name"]: p for p in self.bundle.spdx["packages"]}
        self.assertEqual(pk["unpinned"]["licenseDeclared"], "NOASSERTION")
        self.assertEqual(pk["requests"]["licenseDeclared"], "Apache-2.0")
        self.assertNotIn("supplier", pk["requests"])

    def test_relationships(self) -> None:
        deps = {d["ref"]: d["dependsOn"] for d in self.bundle.cyclonedx["dependencies"]}
        self.assertEqual(deps["pkg:pypi/requests@2.32.0"], ["pkg:pypi/urllib3@2.2.1"])
        self.assertEqual(deps["root:app"], ["pkg:pypi/requests@2.32.0", "pkg:pypi/unpinned"])

    def test_scoped_npm_purl_and_hash(self) -> None:
        c = npm("@babel/core", "7.0.0")
        c = type(c)(**{**c.__dict__, "hashes": {"sha512": "ab" * 64}})
        b = generate_sboms("n", [c], "0.1.0", FIXED_NOW)
        self.assertEqual(
            b.cyclonedx["components"][0]["hashes"], [{"alg": "SHA-512", "content": "ab" * 64}]
        )
        self.assertEqual(
            b.spdx["packages"][1]["checksums"],
            [{"algorithm": "SHA512", "checksumValue": "ab" * 64}],
        )
        self.assertTrue(b.valid)

    def test_validator_detects_corruption(self) -> None:
        cdx = copy.deepcopy(self.bundle.cyclonedx)
        cdx["components"].append(copy.deepcopy(cdx["components"][0]))
        cdx["dependencies"][0]["dependsOn"].append("pkg:pypi/ghost@1")
        cdx["serialNumber"] = "nope"
        errors = validate_cyclonedx(cdx).errors
        self.assertTrue(any("duplicate bom-ref" in e for e in errors))
        self.assertTrue(any("not found" in e for e in errors))
        self.assertTrue(any("serialNumber" in e for e in errors))

        spdx = copy.deepcopy(self.bundle.spdx)
        spdx["relationships"].append(
            {
                "spdxElementId": "SPDXRef-nope",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": "SPDXRef-DOCUMENT",
            }
        )
        spdx["packages"][1]["SPDXID"] = spdx["packages"][2]["SPDXID"]
        self.assertTrue(any("unknown id" in e for e in validate_spdx(spdx).errors))
        self.assertTrue(any("duplicate SPDXID" in e for e in validate_spdx(spdx).errors))

    def test_cross_check_detects_divergence(self) -> None:
        spdx = copy.deepcopy(self.bundle.spdx)
        spdx["packages"] = [p for p in spdx["packages"] if p["name"] != "urllib3"]
        spdx["relationships"] = [
            r for r in spdx["relationships"] if "urllib3" not in r["relatedSpdxElement"]
        ]
        report = cross_check(self.bundle.cyclonedx, spdx)
        self.assertFalse(report.valid)

    def test_validator_is_honest_about_scope(self) -> None:
        self.assertFalse(any(v.schema_validated for v in self.bundle.validation))


if __name__ == "__main__":
    unittest.main()
