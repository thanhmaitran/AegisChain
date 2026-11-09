"""Seeded randomised property tests (stdlib only, so they run everywhere).

``test_hypothesis_properties.py`` expresses a subset with Hypothesis when it is installed.
"""

import hashlib
import json
import random
import tempfile
import unittest
from pathlib import Path

from aegischain.domain.models import Ecosystem
from aegischain.domain.status import Severity, Status, worst
from aegischain.engines.dependency.graph.builder import build_digraph
from aegischain.engines.dependency.graph.traversal import depths_from_roots
from aegischain.engines.integrity.hasher import hash_file, verify_artifact
from aegischain.engines.license.expression import parse_expression, to_string
from aegischain.engines.vulnerability.versioning import parse_version
from aegischain.utils.serialization import canonical_json, to_jsonable

from tests.helpers import npm
from tests.unit.policy.test_policy import decide, match, vuln_report

SEEDS = range(25)


def random_components(rng: random.Random):
    n = rng.randint(1, 30)
    purls = [f"pkg:npm/p{i}@1.0.0" for i in range(n)]
    comps = []
    for i in range(n):
        deps = tuple(
            sorted(set(rng.sample(purls + ["pkg:npm/ghost@1"], k=rng.randint(0, min(4, n)))))
        )
        comps.append(npm(f"p{i}", "1.0.0", direct=rng.random() < 0.3, deps=deps))
    return comps


class GraphProperties(unittest.TestCase):
    def test_no_edges_to_missing_nodes_and_consistent_depths(self) -> None:
        for seed in SEEDS:
            comps = random_components(random.Random(seed))
            g = build_digraph(comps)
            self.assertTrue(all(u in g and v in g for u, v in g.edges))
            roots = {c.purl for c in comps if c.direct}
            depth = depths_from_roots(g, roots)
            for node, d in depth.items():
                self.assertGreaterEqual(d, 1)
                if node in roots:
                    self.assertEqual(d, 1)
                else:  # some predecessor is exactly one step closer
                    self.assertTrue(any(depth.get(p) == d - 1 for p in g.predecessors(node)))


class HashProperties(unittest.TestCase):
    def test_hash_is_consistent_and_any_change_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            for seed in SEEDS:
                rng = random.Random(seed)
                data = rng.randbytes(rng.randint(0, 5000))
                p = Path(d) / f"f{seed}"
                p.write_bytes(data)
                digest = hashlib.sha256(data).hexdigest()
                self.assertEqual(hash_file(p, chunk_size=rng.randint(1, 700))[0], digest)
                self.assertEqual(verify_artifact(p, digest).status, Status.PASS)
                if data:
                    i = rng.randrange(len(data))
                    mutated = bytearray(data)
                    mutated[i] ^= 1 << rng.randrange(8)
                    p.write_bytes(bytes(mutated))
                    self.assertEqual(verify_artifact(p, digest).status, Status.FAIL)


class PolicyProperties(unittest.TestCase):
    def test_decision_is_independent_of_finding_order_and_deterministic(self) -> None:
        sevs = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN]
        for seed in SEEDS:
            rng = random.Random(seed)
            matches = [
                match(rng.choice(sevs), fixed=rng.choice([(), ("2",)]), vid=f"V-{i}")
                for i in range(rng.randint(0, 8))
            ]
            shuffled = matches[:]
            rng.shuffle(shuffled)
            a, b = (
                decide(vulnerability=vuln_report(matches)),
                decide(vulnerability=vuln_report(shuffled)),
            )
            self.assertEqual(a.status, b.status)
            self.assertEqual(a.status, decide(vulnerability=vuln_report(matches)).status)

    def test_adding_a_blocking_vulnerability_never_improves_the_decision(self) -> None:
        rank = {Status.PASS: 0, Status.WARN: 1, Status.INDETERMINATE: 2, Status.FAIL: 3}
        sevs = [Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        for seed in SEEDS:
            rng = random.Random(seed)
            base = [match(rng.choice(sevs), vid=f"V-{i}") for i in range(rng.randint(0, 5))]
            before = decide(vulnerability=vuln_report(base)).status
            after = decide(
                vulnerability=vuln_report(base + [match(Severity.CRITICAL, vid="NEW")])
            ).status
            self.assertGreaterEqual(rank[after], rank[before])
            self.assertEqual(after, Status.FAIL)

    def test_worst_is_order_independent(self) -> None:
        for seed in SEEDS:
            rng = random.Random(seed)
            items = [rng.choice(list(Status)) for _ in range(rng.randint(1, 8))]
            self.assertEqual(worst(items), worst(reversed(items)))


class SerializationAndParsingProperties(unittest.TestCase):
    def test_report_serialisation_round_trips_through_json(self) -> None:
        from aegischain.application.pipeline import AnalysisPipeline, AnalysisRequest

        from tests.helpers import CLOCK, EXAMPLE_NODE, EXAMPLE_PY

        for ex in (EXAMPLE_PY, EXAMPLE_NODE):
            report = AnalysisPipeline(clock=CLOCK).run(AnalysisRequest(ex)).report
            plain = to_jsonable(report)
            self.assertEqual(json.loads(json.dumps(plain)), plain)
            self.assertEqual(json.loads(canonical_json(report)), plain)

    def test_license_expression_round_trip(self) -> None:
        ids = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "GPL-3.0-only", "MPL-2.0"]

        def gen(rng: random.Random, depth: int) -> str:
            if depth == 0 or rng.random() < 0.3:
                return rng.choice(ids)
            op = rng.choice(["AND", "OR"])
            return f"({gen(rng, depth - 1)} {op} {gen(rng, depth - 1)})"

        for seed in SEEDS:
            text = gen(random.Random(seed), 3)
            once = to_string(parse_expression(text))
            self.assertEqual(to_string(parse_expression(once)), once)
            # AND/OR are associative, so tree shape may differ; the licence set must not.
            from aegischain.engines.license.expression import leaves

            self.assertEqual(
                sorted(leaf.id for leaf in leaves(parse_expression(once))),
                sorted(leaf.id for leaf in leaves(parse_expression(text))),
            )

    def test_semver_total_order_matches_tuple_order(self) -> None:
        for seed in SEEDS:
            rng = random.Random(seed)
            triples = [
                (rng.randint(0, 5), rng.randint(0, 20), rng.randint(0, 20)) for _ in range(20)
            ]
            versions = [parse_version(Ecosystem.NPM, ".".join(map(str, t))) for t in triples]
            order = sorted(range(len(triples)), key=lambda i: triples[i])
            self.assertEqual([versions[i] for i in order], sorted(versions))

    def test_parsers_never_crash_on_random_bytes(self) -> None:
        from aegischain.engines.dependency.parsers import get_parser
        from aegischain.exceptions import ParseError

        rng = random.Random(7)
        for name in (
            "requirements.txt",
            "pyproject.toml",
            "poetry.lock",
            "uv.lock",
            "package.json",
            "package-lock.json",
        ):
            parser = get_parser(name)
            for _ in range(60):
                blob = rng.randbytes(rng.randint(0, 200))
                try:
                    parser.parse(blob, name)
                except ParseError:
                    pass  # the only acceptable failure mode


if __name__ == "__main__":
    unittest.main()
