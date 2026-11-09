import tempfile
import unittest
from pathlib import Path

import networkx as nx
from aegischain.domain.status import Status
from aegischain.engines.dependency.graph.analyzer import find_cycles
from aegischain.engines.dependency.graph.builder import build_digraph
from aegischain.engines.dependency.service import analyze_dependencies, graph_view
from aegischain.engines.ingestion.scanner import RepositoryInput, scan_repository

from tests.helpers import EXAMPLE_NODE, EXAMPLE_PY, npm, pypi, write_files


def analyze(root: Path, **kw):
    return analyze_dependencies(root, scan_repository(RepositoryInput(root)), **kw)


class ExampleGroundTruth(unittest.TestCase):
    """Ground truth for the committed example projects (see docs/evaluation)."""

    def test_python_example(self) -> None:
        res = analyze(EXAMPLE_PY)
        direct = {c.name for c in res.components if c.direct}
        self.assertEqual(direct, {"requests", "fastapi", "pyyaml", "pytest"})
        self.assertEqual(len(res.components), 13)
        by = {c.name: c for c in res.components}
        self.assertEqual(by["anyio"].depth, 3)  # fastapi -> starlette -> anyio
        self.assertEqual(by["idna"].depth, 2)  # requests -> idna (shorter than via anyio)
        self.assertEqual(res.status, Status.PASS)

    def test_node_example_nested_versions(self) -> None:
        res = analyze(EXAMPLE_NODE)
        versions = sorted(c.version for c in res.components if c.name == "debug")
        self.assertEqual(versions, ["2.6.9", "4.3.4"])
        self.assertIn("DUPLICATE_VERSIONS", {f.code for f in res.findings})
        self.assertEqual(
            {c.name for c in res.components if c.direct}, {"express", "lodash", "mocha"}
        )
        edges = dict()
        for s, t in res.edges:
            edges.setdefault(s, []).append(t)
        self.assertEqual(edges["pkg:npm/mocha@10.2.0"], ["pkg:npm/debug@4.3.4"])
        self.assertEqual(edges["pkg:npm/debug@4.3.4"], ["pkg:npm/ms@2.1.2"])

    def test_exclude_dev(self) -> None:
        res = analyze(EXAMPLE_NODE, include_dev=False)
        self.assertNotIn("mocha", {c.name for c in res.components})
        self.assertNotIn("pkg:npm/ms@2.1.2", {c.purl for c in res.components})

    def test_graph_has_no_dangling_edges(self) -> None:
        for ex in (EXAMPLE_PY, EXAMPLE_NODE):
            res = analyze(ex)
            known = {c.purl for c in res.components}
            self.assertTrue(all(s in known and t in known for s, t in res.edges))
            self.assertEqual(len(graph_view(res)["nodes"]), len(res.components))

    def test_output_is_deterministic(self) -> None:
        self.assertEqual(analyze(EXAMPLE_PY), analyze(EXAMPLE_PY))


class Scenarios(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_manifest_without_lockfile_warns_and_does_not_invent_transitives(self) -> None:
        write_files(self.root, {"requirements.txt": "requests==2.32.0\nflask>=2\n"})
        res = analyze(self.root)
        codes = {f.code for f in res.findings}
        self.assertTrue({"NO_LOCKFILE", "UNPINNED_VERSION"} <= codes)
        self.assertEqual(len(res.components), 2)  # no urllib3 etc. invented
        self.assertEqual(res.status, Status.WARN)

    def test_lock_mismatch_and_missing(self) -> None:
        write_files(
            self.root,
            {
                "pyproject.toml": '[project]\nname="x"\ndependencies=["a>=2","ghost"]\n',
                "poetry.lock": '[[package]]\nname="a"\nversion="1.0"\ngroups=["main"]\n',
            },
        )
        codes = [f.code for f in analyze(self.root).findings]
        self.assertIn("LOCK_MISMATCH", codes)
        self.assertIn("DECLARED_NOT_LOCKED", codes)

    def test_pypi_multiple_versions_is_conflict(self) -> None:
        write_files(
            self.root,
            {
                "pyproject.toml": '[project]\nname="x"\ndependencies=["a"]\n',
                "poetry.lock": '[[package]]\nname="a"\nversion="1.0"\ngroups=["main"]\n[[package]]\nname="a"\nversion="2.0"\ngroups=["main"]\n',
            },
        )
        f = [f for f in analyze(self.root).findings if f.code == "VERSION_CONFLICT"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].status, Status.WARN)

    def test_parse_error_is_indeterminate_not_pass(self) -> None:
        write_files(self.root, {"package.json": "{broken"})
        res = analyze(self.root)
        self.assertEqual(res.status, Status.INDETERMINATE)
        self.assertEqual(res.components, ())

    def test_invalid_file_does_not_hide_valid_ones(self) -> None:
        write_files(self.root, {"package.json": "{broken", "requirements.txt": "a==1\n"})
        res = analyze(self.root)
        self.assertEqual([c.name for c in res.components], ["a"])
        self.assertEqual(res.status, Status.INDETERMINATE)

    def test_inferred_direct_without_manifest_is_flagged(self) -> None:
        write_files(
            self.root,
            {
                "poetry.lock": '[[package]]\nname="a"\nversion="1"\ngroups=["main"]\n[package.dependencies]\nb="*"\n[[package]]\nname="b"\nversion="1"\ngroups=["main"]\n'
            },
        )
        res = analyze(self.root)
        self.assertEqual([c.name for c in res.components if c.direct], ["a"])
        self.assertIn("DIRECT_INFERRED", {f.code for f in res.findings})

    def test_tampering_between_ingest_and_parse_is_detected(self) -> None:
        write_files(self.root, {"requirements.txt": "a==1\n"})
        ing = scan_repository(RepositoryInput(self.root))
        (self.root / "requirements.txt").write_text("evil==1\n")
        res = analyze_dependencies(self.root, ing)
        self.assertEqual(res.status, Status.INDETERMINATE)
        self.assertEqual(res.components, ())

    def test_monorepo_merges_by_purl(self) -> None:
        write_files(
            self.root, {"a/requirements.txt": "x==1\n", "b/requirements.txt": "x==1\ny==2\n"}
        )
        names = sorted(c.name for c in analyze(self.root).components)
        self.assertEqual(names, ["x", "y"])


class GraphTests(unittest.TestCase):
    def test_cycles_detected(self) -> None:
        a = npm("a", "1.0.0", deps=("pkg:npm/b@1.0.0",))
        b = npm("b", "1.0.0", direct=False, deps=("pkg:npm/a@1.0.0",))
        self.assertEqual(
            find_cycles(build_digraph([a, b])), [["pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0"]]
        )

    def test_edges_to_unknown_nodes_are_dropped(self) -> None:
        g = build_digraph([pypi("a", "1", deps=("pkg:pypi/ghost@1",))])
        self.assertEqual(g.number_of_edges(), 0)
        self.assertIsInstance(g, nx.DiGraph)


if __name__ == "__main__":
    unittest.main()
