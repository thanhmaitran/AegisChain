import json
import unittest

from aegischain.domain.models import Scope
from aegischain.engines.dependency.parsers.common import (
    normalize_pypi_name,
    npm_integrity_to_hash,
    npm_purl,
    pypi_purl,
)
from aegischain.engines.dependency.parsers.node_parsers import NpmLockParser, PackageJsonParser
from aegischain.engines.dependency.parsers.pyproject_parser import (
    PyprojectParser,
    poetry_to_specifier,
)
from aegischain.engines.dependency.parsers.python_locks import PoetryLockParser, UvLockParser
from aegischain.engines.dependency.parsers.requirements_parser import RequirementsParser
from aegischain.exceptions import ParseError


class CommonTests(unittest.TestCase):
    def test_pypi_normalisation(self) -> None:
        self.assertEqual(normalize_pypi_name("Foo_Bar.baz"), "foo-bar-baz")

    def test_purls(self) -> None:
        self.assertEqual(pypi_purl("PyYAML", "5.3"), "pkg:pypi/pyyaml@5.3")
        self.assertEqual(npm_purl("@babel/core", "7.0.0"), "pkg:npm/%40babel/core@7.0.0")
        self.assertEqual(npm_purl("lodash", None), "pkg:npm/lodash")

    def test_integrity_conversion(self) -> None:
        import base64
        import hashlib

        raw = hashlib.sha512(b"x").digest()
        self.assertEqual(
            npm_integrity_to_hash("sha512-" + base64.b64encode(raw).decode()), {"sha512": raw.hex()}
        )
        self.assertEqual(npm_integrity_to_hash("sha512-!!!"), {})
        self.assertEqual(npm_integrity_to_hash("sha512-AAAA"), {})  # wrong length
        self.assertEqual(npm_integrity_to_hash(None), {})


class RequirementsTests(unittest.TestCase):
    def parse(self, text: str, path: str = "requirements.txt"):
        return RequirementsParser().parse(text.encode(), path)

    def test_pinned_and_unpinned(self) -> None:
        res = self.parse("Requests==2.32.0\nflask>=2.0  # comment\n# only comment\n")
        d = {x.name: x for x in res.declared}
        self.assertEqual(d["requests"].pinned_version, "2.32.0")
        self.assertIsNone(d["flask"].pinned_version)
        self.assertTrue(any("not pinned" in w for w in res.warnings))

    def test_hash_options_and_continuations(self) -> None:
        digest = "a" * 64
        res = self.parse(f"pkg==1.0 \\\n    --hash=sha256:{digest}\n")
        self.assertEqual(res.declared[0].hashes, {"sha256": digest})

    def test_options_urls_and_garbage_are_warnings_not_crashes(self) -> None:
        res = self.parse(
            "-r other.txt\n--index-url https://x\nthis is not valid ===\npkg @ https://example.com/p.whl\n"
        )
        self.assertEqual([d.name for d in res.declared], ["pkg"])
        self.assertGreaterEqual(len(res.warnings), 3)

    def test_wildcard_is_not_pinned(self) -> None:
        self.assertIsNone(self.parse("a==1.*\n").declared[0].pinned_version)

    def test_markers_and_extras(self) -> None:
        res = self.parse("uvicorn[standard]==0.30.0 ; python_version >= '3.8'\n")
        self.assertEqual(res.declared[0].pinned_version, "0.30.0")

    def test_dev_scope_from_filename(self) -> None:
        self.assertEqual(self.parse("a==1\n", "requirements-dev.txt").declared[0].scope, Scope.DEV)

    def test_invalid_utf8(self) -> None:
        with self.assertRaises(ParseError):
            RequirementsParser().parse(b"\xff\xfe\x00", "requirements.txt")


class PyprojectTests(unittest.TestCase):
    def test_pep621_groups_and_optional(self) -> None:
        text = '[project]\nname="x"\ndependencies=["requests>=2.31","a==1.0"]\n[project.optional-dependencies]\nfast=["orjson"]\n[dependency-groups]\ndev=["pytest"]\n'
        res = PyprojectParser().parse(text.encode(), "pyproject.toml")
        scopes = {d.name: d.scope for d in res.declared}
        self.assertEqual(
            scopes,
            {
                "requests": Scope.RUNTIME,
                "a": Scope.RUNTIME,
                "orjson": Scope.OPTIONAL,
                "pytest": Scope.DEV,
            },
        )
        self.assertEqual({d.name: d.pinned_version for d in res.declared}["a"], "1.0")

    def test_poetry_sections(self) -> None:
        text = '[tool.poetry.dependencies]\npython="^3.12"\nrequests="^2.31"\nx={version="1.0", optional=true}\ngit={git="https://x"}\n[tool.poetry.group.dev.dependencies]\npytest="*"\n'
        res = PyprojectParser().parse(text.encode(), "pyproject.toml")
        by = {d.name: d for d in res.declared}
        self.assertNotIn("python", by)
        self.assertEqual(by["requests"].specifier, ">=2.31,<3.0")
        self.assertEqual(by["x"].scope, Scope.OPTIONAL)
        self.assertEqual(by["pytest"].scope, Scope.DEV)
        self.assertTrue(any("non-registry" in w for w in res.warnings))

    def test_poetry_constraint_translation(self) -> None:
        cases = {
            "^1.2.3": ">=1.2.3,<2.0.0",
            "^0.2.3": ">=0.2.3,<0.3.0",
            "^0.0.3": ">=0.0.3,<0.0.4",
            "~1.2.3": ">=1.2.3,<1.3.0",
            "~1": ">=1,<2",
            "1.2.3": "==1.2.3",
            ">=1,<2": ">=1,<2",
            "*": None,
        }
        for src, want in cases.items():
            self.assertEqual(poetry_to_specifier(src), want, src)

    def test_invalid_toml(self) -> None:
        with self.assertRaises(ParseError):
            PyprojectParser().parse(b"[[[", "pyproject.toml")


POETRY_LOCK = """
[[package]]
name = "A"
version = "1.0"
groups = ["main"]
files = [{file = "a.whl", hash = "sha256:%s"}]
[package.dependencies]
b = "*"
missing-optional = "*"

[[package]]
name = "b"
version = "2.0"
groups = ["dev"]
files = [{file = "b1", hash = "sha256:1"}, {file = "b2", hash = "sha256:2"}]
""" % ("c" * 64)


class PythonLockTests(unittest.TestCase):
    def test_poetry_lock(self) -> None:
        res = PoetryLockParser().parse(POETRY_LOCK.encode(), "poetry.lock")
        pk = {p.name: p for p in res.packages}
        self.assertEqual(pk["a"].depends_on, ("b@2.0",))
        self.assertEqual(pk["a"].hashes, {"sha256": "c" * 64})
        self.assertEqual(pk["b"].hashes, {})  # several files -> no single digest is claimed
        self.assertEqual(pk["b"].scope, Scope.DEV)
        self.assertIsNone(res.direct_keys)

    def test_poetry_lock_without_packages(self) -> None:
        with self.assertRaises(ParseError):
            PoetryLockParser().parse(b"x = 1", "poetry.lock")

    def test_uv_lock_roots_and_scopes(self) -> None:
        text = """
[[package]]
name = "app"
version = "0.1"
source = {virtual = "."}
dependencies = [{name = "a"}]
[package.dev-dependencies]
dev = [{name = "t"}]
[[package]]
name = "a"
version = "1.0"
source = {registry = "x"}
dependencies = [{name = "b"}]
[[package]]
name = "b"
version = "1.1"
[[package]]
name = "t"
version = "9"
"""
        res = UvLockParser().parse(text.encode(), "uv.lock")
        sc = {p.name: p.scope for p in res.packages}
        self.assertEqual(sc, {"a": Scope.RUNTIME, "b": Scope.RUNTIME, "t": Scope.DEV})
        self.assertEqual(res.direct_keys, frozenset({"a@1.0", "t@9"}))


class NodeTests(unittest.TestCase):
    def test_package_json(self) -> None:
        text = json.dumps(
            {
                "dependencies": {"a": "1.2.3", "b": "^2", "c": "git+https://x/c.git"},
                "devDependencies": {"d": "1.0.0"},
                "peerDependencies": {"p": "*"},
            }
        )
        res = PackageJsonParser().parse(text.encode(), "package.json")
        by = {d.name: d for d in res.declared}
        self.assertEqual(by["a"].pinned_version, "1.2.3")
        self.assertIsNone(by["b"].pinned_version)
        self.assertEqual(by["d"].scope, Scope.DEV)
        self.assertTrue(any("non-registry" in w for w in res.warnings))
        self.assertTrue(any("peerDependencies" in w for w in res.warnings))

    def test_package_json_rejects_wrong_types(self) -> None:
        with self.assertRaises(ParseError):
            PackageJsonParser().parse(b'{"dependencies": []}', "package.json")
        with self.assertRaises(ParseError):
            PackageJsonParser().parse(b"[1]", "package.json")
        with self.assertRaises(ParseError):
            PackageJsonParser().parse(b"{bad", "package.json")

    def lock(self, packages: dict) -> bytes:
        return json.dumps({"lockfileVersion": 3, "packages": packages}).encode()

    def test_nested_resolution(self) -> None:
        pk = {
            "": {"dependencies": {"a": "1"}},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"x": "1"}},
            "node_modules/x": {"version": "1.0.0"},
            "node_modules/a/node_modules/x": {"version": "2.0.0"},
            "node_modules/b": {"version": "1.0.0", "dependencies": {"x": "1"}, "dev": True},
        }
        res = NpmLockParser().parse(self.lock(pk), "package-lock.json")
        deps = {p.key: p.depends_on for p in res.packages}
        self.assertEqual(deps["node_modules/a"], ("node_modules/a/node_modules/x",))  # nearest wins
        self.assertEqual(deps["node_modules/b"], ("node_modules/x",))  # climbs to the parent
        self.assertEqual(res.direct_keys, frozenset({"node_modules/a"}))

    def test_scoped_packages_and_aliases(self) -> None:
        pk = {
            "": {},
            "node_modules/@s/p": {"version": "1.0.0"},
            "node_modules/alias": {"name": "real", "version": "1.0.0"},
        }
        res = NpmLockParser().parse(self.lock(pk), "package-lock.json")
        self.assertEqual({p.name for p in res.packages}, {"@s/p", "real"})

    def test_unresolved_dependency_recorded(self) -> None:
        pk = {
            "": {},
            "node_modules/a": {
                "version": "1.0.0",
                "dependencies": {"ghost": "1"},
                "optionalDependencies": {"opt": "1"},
            },
        }
        res = NpmLockParser().parse(self.lock(pk), "package-lock.json")
        self.assertEqual(res.packages[0].unresolved_dependencies, ("ghost",))

    def test_lockfile_v1_is_rejected_explicitly(self) -> None:
        with self.assertRaises(ParseError):
            NpmLockParser().parse(
                b'{"lockfileVersion": 1, "dependencies": {}}', "package-lock.json"
            )

    def test_workspace_links_are_skipped(self) -> None:
        pk = {
            "": {},
            "packages/w": {"version": "1.0.0"},
            "node_modules/w": {"resolved": "packages/w", "link": True},
        }
        res = NpmLockParser().parse(self.lock(pk), "package-lock.json")
        self.assertEqual(res.packages, ())


if __name__ == "__main__":
    unittest.main()
