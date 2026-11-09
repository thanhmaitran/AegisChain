"""Per-engine correctness evaluation against explicit ground truth.

Writes reports/<area>/*.json and reports/final/evaluation-summary.md.
Everything here is reproducible: `python benchmarks/run_evaluation.py`.
The cases are authored conformance cases, not a sample of real-world data; see
docs/evaluation/evaluation-methodology.md for what that does and does not show.
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "packages/aegischain-core/src"), str(Path(__file__).resolve().parent)]

from datetime import UTC, datetime  # noqa: E402

from aegischain.application.pipeline import AnalysisPipeline, AnalysisRequest  # noqa: E402
from aegischain.domain.models import Ecosystem, LicenseStatus  # noqa: E402
from aegischain.domain.status import Status  # noqa: E402
from aegischain.engines.dependency.parsers import get_parser  # noqa: E402
from aegischain.engines.dependency.service import analyze_dependencies  # noqa: E402
from aegischain.engines.ingestion.scanner import RepositoryInput, scan_repository  # noqa: E402
from aegischain.engines.integrity.hasher import verify_artifact  # noqa: E402
from aegischain.engines.license.evaluator import LicensePolicy, evaluate_license  # noqa: E402
from aegischain.engines.policy import parse_policy  # noqa: E402
from aegischain.engines.provenance.verifiers.provenance_verifier import (  # noqa: E402
    ProvenanceExpectations,
    verify_provenance,
)
from aegischain.engines.provenance.verifiers.signature_verifier import StaticSignatureVerifier  # noqa: E402
from aegischain.engines.sbom.service import generate_sboms  # noqa: E402
from aegischain.engines.vulnerability import cvss  # noqa: E402
from aegischain.engines.vulnerability.matcher import evaluate  # noqa: E402
from aegischain.engines.vulnerability.provider import StaticVulnerabilityProvider  # noqa: E402
from aegischain.exceptions import ParseError  # noqa: E402
from aegischain.utils.clock import FixedClock  # noqa: E402
from datasets import make_npm, make_poetry  # noqa: E402

CLOCK = FixedClock(datetime(2026, 1, 15, tzinfo=UTC))
OUT = ROOT / "reports"
summary: list[dict] = []


def record(area: str, name: str, passed: int, total: int, extra: dict | None = None) -> None:
    row = {"area": area, "evaluation": name, "passed": passed, "total": total, **(extra or {})}
    summary.append(row)
    d = OUT / area
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.json").write_text(json.dumps(row, indent=2) + "\n")
    print(f"{area:24s} {name:34s} {passed}/{total}")


def prf(got: set, want: set) -> dict:
    tp = len(got & want)
    return {
        "precision": round(tp / len(got), 4) if got else 1.0,
        "recall": round(tp / len(want), 4) if want else 1.0,
        "false_positives": len(got - want),
        "false_negatives": len(want - got),
    }


# 1. Dependency parsing + graph ------------------------------------------------------------
def eval_dependency() -> None:
    cases = []
    with tempfile.TemporaryDirectory() as tmp:
        for kind, maker in (("npm", make_npm), ("poetry", make_poetry)):
            for n, seed in ((20, 1), (200, 2), (1000, 3)):
                repo = Path(tmp) / f"{kind}{n}"
                truth = maker(repo, n, seed)
                res = analyze_dependencies(repo, scan_repository(RepositoryInput(repo)))
                comp = {c.purl for c in res.components}
                edges = set(res.edges)
                direct = {c.purl for c in res.components if c.direct}
                cases.append(
                    {
                        "dataset": f"{kind}-{n}-seed{seed}",
                        "components": prf(comp, set(truth.purls)),
                        "edges": prf(edges, set(truth.edges)),
                        "direct": prf(direct, set(truth.direct)),
                    }
                )
    exact = sum(
        all(
            c[k]["false_positives"] == 0 and c[k]["false_negatives"] == 0
            for k in ("components", "edges", "direct")
        )
        for c in cases
    )
    record("dependency-analysis", "graph-ground-truth", exact, len(cases), {"cases": cases})


# 2. SBOM ---------------------------------------------------------------------------------------
def eval_sbom() -> None:
    ok, total, rows = 0, 0, []
    with tempfile.TemporaryDirectory() as tmp:
        for kind, maker in (("npm", make_npm), ("poetry", make_poetry)):
            for n in (10, 300):
                repo = Path(tmp) / f"{kind}{n}"
                maker(repo, n, 5)
                dep = analyze_dependencies(repo, scan_repository(RepositoryInput(repo)))
                b = generate_sboms("bench", dep.components, "0.1.0", CLOCK.now())
                a = generate_sboms("bench", list(reversed(dep.components)), "0.1.0", CLOCK.now())
                same = json.dumps(a.cyclonedx, sort_keys=True) == json.dumps(
                    b.cyclonedx, sort_keys=True
                )
                covered = (
                    len(b.cyclonedx["components"])
                    == len(dep.components)
                    == len(b.spdx["packages"]) - 1
                )
                total += 1
                ok += int(b.valid and same and covered)
                rows.append(
                    {
                        "dataset": f"{kind}-{n}",
                        "valid": b.valid,
                        "input_order_independent": same,
                        "component_coverage": covered,
                    }
                )
    record(
        "sbom-validation",
        "structural-validity-and-coverage",
        ok,
        total,
        {"cases": rows, "schema_validated": False},
    )


# 3. Vulnerability matching + CVSS ---------------------------------------------------------------
def rec(
    eco: str, name: str, events: list, rtype: str = "ECOSYSTEM", versions: list | None = None
) -> dict:
    entry: dict = {"package": {"ecosystem": eco, "name": name}}
    if events is not None:
        entry["ranges"] = [{"type": rtype, "events": events}]
    if versions:
        entry["versions"] = versions
    return {"id": "T", "affected": [entry]}


def eval_vulnerability() -> None:
    INTRODUCED = "introduced"
    FIXED = "fixed"
    LAST_AFFECTED = "last_affected"
    cases = [
        (rec("PyPI", "p", [{INTRODUCED: "0"}, {FIXED: "2.0"}]), Ecosystem.PYPI, "1.9", True),
        (rec("PyPI", "p", [{INTRODUCED: "0"}, {FIXED: "2.0"}]), Ecosystem.PYPI, "2.0", False),
        (rec("PyPI", "p", [{INTRODUCED: "0"}, {FIXED: "2.0"}]), Ecosystem.PYPI, "2.0.post1", False),
        (rec("PyPI", "p", [{INTRODUCED: "1.0"}, {FIXED: "2.0"}]), Ecosystem.PYPI, "0.9", False),
        (rec("PyPI", "p", [{INTRODUCED: "1.0"}, {FIXED: "2.0"}]), Ecosystem.PYPI, "1.0", True),
        (rec("PyPI", "p", [{INTRODUCED: "1.0"}, {FIXED: "2.0"}]), Ecosystem.PYPI, "1.5rc1", True),
        (
            rec("PyPI", "p", [{INTRODUCED: "0"}, {LAST_AFFECTED: "1.5"}]),
            Ecosystem.PYPI,
            "1.5",
            True,
        ),
        (
            rec("PyPI", "p", [{INTRODUCED: "0"}, {LAST_AFFECTED: "1.5"}]),
            Ecosystem.PYPI,
            "1.5.1",
            False,
        ),
        (
            rec(
                "PyPI",
                "p",
                [{INTRODUCED: "0"}, {FIXED: "1.0"}, {INTRODUCED: "2.0"}, {FIXED: "3.0"}],
            ),
            Ecosystem.PYPI,
            "2.5",
            True,
        ),
        (
            rec(
                "PyPI",
                "p",
                [{INTRODUCED: "0"}, {FIXED: "1.0"}, {INTRODUCED: "2.0"}, {FIXED: "3.0"}],
            ),
            Ecosystem.PYPI,
            "1.5",
            False,
        ),
        (rec("PyPI", "My_Pkg", [{INTRODUCED: "0"}, {FIXED: "2"}]), Ecosystem.PYPI, "1", True),
        (
            rec("npm", "n", [{INTRODUCED: "0.0.0"}, {FIXED: "1.2.3"}], "SEMVER"),
            Ecosystem.NPM,
            "1.2.2",
            True,
        ),
        (
            rec("npm", "n", [{INTRODUCED: "0.0.0"}, {FIXED: "1.2.3"}], "SEMVER"),
            Ecosystem.NPM,
            "1.2.3",
            False,
        ),
        (
            rec("npm", "n", [{INTRODUCED: "0.0.0"}, {FIXED: "1.2.3"}], "SEMVER"),
            Ecosystem.NPM,
            "1.2.3-rc.1",
            True,
        ),
        (
            rec("npm", "n", [{INTRODUCED: "1.0.0-rc.1"}, {FIXED: "1.0.0"}], "SEMVER"),
            Ecosystem.NPM,
            "1.0.0-rc.2",
            True,
        ),
        (
            rec("npm", "n", [{INTRODUCED: "1.0.0"}, {FIXED: "2.0.0"}], "SEMVER"),
            Ecosystem.NPM,
            "1.10.0",
            True,
        ),
        (
            rec("npm", "n", [{INTRODUCED: "1.0.0"}, {FIXED: "1.9.0"}], "SEMVER"),
            Ecosystem.NPM,
            "1.10.0",
            False,
        ),
        (rec("npm", "n", None, versions=["1.0.0", "1.0.1"]), Ecosystem.NPM, "1.0.1", True),
        (rec("npm", "n", None, versions=["1.0.0"]), Ecosystem.NPM, "1.0.2", False),
        (
            rec("npm", "other", [{INTRODUCED: "0.0.0"}, {FIXED: "9.9.9"}], "SEMVER"),
            Ecosystem.NPM,
            "1.0.0",
            None,
        ),
        (rec("npm", "n", [{INTRODUCED: "abc"}], "GIT"), Ecosystem.NPM, "1.0.0", None),
        (
            rec("PyPI", "p", [{INTRODUCED: "0"}, {FIXED: "2.0"}]),
            Ecosystem.PYPI,
            "not-a-version",
            None,
        ),
    ]
    ok = 0
    rows = []
    for r, eco, ver, want in cases:
        pkg = r["affected"][0]["package"]["name"]
        query_name = "my-pkg" if pkg == "My_Pkg" else ("n" if pkg == "other" else pkg)
        got = evaluate(r, eco, query_name, ver).affected
        ok += int(got == want)
        rows.append({"package": pkg, "version": ver, "expected": want, "got": got})
    record("vulnerability-analysis", "affected-range-matching", ok, len(cases), {"cases": rows})
    vectors = {
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H": 7.5,
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L": 5.3,
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
    }
    got = {v: cvss.base_score(v) for v in vectors}
    record(
        "vulnerability-analysis",
        "cvss-v3-reference-vectors",
        sum(got[v] == s for v, s in vectors.items()),
        len(vectors),
        {
            "note": "Expected scores are the published values for these well-known vectors (FIRST CVSS v3.1 calculator)."
        },
    )


# 4. Licenses ----------------------------------------------------------------------------------------
def eval_license() -> None:
    p = LicensePolicy(denied=("GPL-3.0-*", "AGPL-*"))
    S = LicenseStatus
    table = [
        ("MIT", S.ALLOWED),
        ("MIT OR Apache-2.0", S.ALLOWED),
        ("MIT AND Apache-2.0", S.ALLOWED),
        ("GPL-3.0-only", S.DENIED),
        ("GPL-3.0", S.DENIED),
        ("GPL-3.0+", S.DENIED),
        ("MIT OR GPL-3.0-only", S.ALLOWED),
        ("MIT AND GPL-3.0-only", S.DENIED),
        ("(MIT OR ISC) AND GPL-3.0-or-later", S.DENIED),
        ("Apache-2.0 WITH LLVM-exception", S.ALLOWED),
        ("GPL-2.0-only WITH Classpath-exception-2.0", S.ALLOWED),
        ("LicenseRef-Acme", S.UNKNOWN),
        ("MIT OR LicenseRef-Acme", S.ALLOWED),
        ("GPL-3.0-only OR LicenseRef-Acme", S.UNKNOWN),
        (None, S.UNKNOWN),
        ("", S.UNKNOWN),
        ("Proprietary", S.INVALID),
        ("BSD", S.INVALID),
        ("MIT AND", S.INVALID),
        ("(MIT", S.INVALID),
        ("MIT License", S.ALLOWED),
        ("mit or apache-2.0", S.ALLOWED),
        ("AGPL-3.0-only", S.DENIED),
        ("Apache-2.0 AND (MIT OR GPL-3.0-only)", S.ALLOWED),
    ]
    got = [(t, evaluate_license("p", t, p).status, w) for t, w in table]
    record(
        "vulnerability-analysis",
        "license-expression-evaluation",
        sum(g == w for _, g, w in got),
        len(got),
        {"cases": [{"expression": t, "got": g.value, "expected": w.value} for t, g, w in got]},
    )


# 5. Integrity ---------------------------------------------------------------------------------------
def eval_integrity() -> None:
    rng = random.Random(0)
    detected = matched = 0
    trials = 500
    with tempfile.TemporaryDirectory() as tmp:
        for i in range(trials):
            data = rng.randbytes(rng.randint(1, 4000))
            f = Path(tmp) / f"f{i}"
            f.write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            matched += verify_artifact(f, digest).status is Status.PASS
            m = bytearray(data)
            m[rng.randrange(len(m))] ^= 1 << rng.randrange(8)
            f.write_bytes(bytes(m))
            detected += verify_artifact(f, digest).status is Status.FAIL
        empty = Path(tmp) / "empty"
        empty.write_bytes(b"")
        edge = [
            verify_artifact(empty, hashlib.sha256(b"").hexdigest()).status is Status.PASS,
            verify_artifact(Path(tmp) / "missing", "0" * 64).status is Status.INDETERMINATE,
            verify_artifact(empty, "zz").status is Status.INDETERMINATE,
            verify_artifact(empty, None).status is Status.INDETERMINATE,
        ]
    record(
        "provenance-verification",
        "integrity-digest-verification",
        matched + detected + sum(edge),
        2 * trials + len(edge),
        {
            "unmodified_accepted": matched,
            "single_bit_flips_detected": detected,
            "trials": trials,
            "edge_cases_ok": sum(edge),
        },
    )


# 6. Provenance ---------------------------------------------------------------------------------------
def _dsse(stmt: dict) -> str:
    return json.dumps(
        {
            "payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(json.dumps(stmt).encode()).decode(),
            "signatures": [{"sig": "x"}],
        }
    )


def eval_provenance() -> None:
    sha = hashlib.sha256(b"art").hexdigest()
    good_builder = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.0.0"

    def stmt(
        digest=sha,
        builder=good_builder,
        source="git+https://github.com/acme/app@refs/heads/main",
        pred="https://slsa.dev/provenance/v1",
    ):
        return {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "a", "digest": {"sha256": digest}}],
            "predicateType": pred,
            "predicate": {
                "buildDefinition": {"externalParameters": {"workflow": {"repository": source}}},
                "runDetails": {"builder": {"id": builder}},
            },
        }

    trust = ProvenanceExpectations(
        ("https://github.com/slsa-framework/slsa-github-generator/*",),
        ("https://github.com/acme/app",),
        "id",
        "iss",
    )
    P = Status.PASS
    F = Status.FAIL
    INDETERMINATE = Status.INDETERMINATE
    cases = [
        ("valid + valid signature", _dsse(stmt()), trust, P, P),
        ("valid + failed signature", _dsse(stmt()), trust, F, F),
        ("valid + unverifiable signature", _dsse(stmt()), trust, INDETERMINATE, INDETERMINATE),
        ("wrong subject digest", _dsse(stmt(digest="0" * 64)), trust, P, F),
        ("untrusted builder", _dsse(stmt(builder="https://evil/b")), trust, P, F),
        ("untrusted source", _dsse(stmt(source="https://github.com/evil/x")), trust, P, F),
        ("no trust policy configured", _dsse(stmt()), ProvenanceExpectations(), P, INDETERMINATE),
        ("non-SLSA predicate", _dsse(stmt(pred="https://spdx.dev/Document")), trust, P, F),
        ("garbage", "not json", trust, P, F),
        (
            "empty subjects",
            json.dumps(
                {"_type": "https://in-toto.io/Statement/v1", "subject": [], "predicateType": "x"}
            ),
            trust,
            P,
            F,
        ),
    ]
    ok, rows = 0, []
    with tempfile.TemporaryDirectory() as tmp:
        art = Path(tmp) / "art"
        art.write_bytes(b"art")
        for name, text, tr, sig, want in cases:
            pf = Path(tmp) / "p.json"
            pf.write_text(text)
            res = verify_provenance(
                art, sha, pf, Path(tmp) / "bundle", tr, StaticSignatureVerifier(sig)
            )
            ok += res.status is want
            rows.append({"case": name, "expected": want.value, "got": res.status.value})
        none = verify_provenance(art, sha, None, None, trust, StaticSignatureVerifier(P))
        ok += none.status is INDETERMINATE
        rows.append(
            {
                "case": "no provenance supplied",
                "expected": "INDETERMINATE",
                "got": none.status.value,
            }
        )
    record(
        "provenance-verification",
        "evidence-classification",
        ok,
        len(cases) + 1,
        {
            "cases": rows,
            "note": "Signature backend is a test double; Sigstore itself is not exercised offline.",
        },
    )


# 7. Policy decisions -----------------------------------------------------------------------------------
def eval_policy() -> None:
    def vrec(sev_vector: str | None, fixed: str | None = "2.0") -> dict:
        r = {
            "id": "T-1",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "pkg"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else []),
                        }
                    ],
                }
            ],
        }
        if sev_vector:
            r["severity"] = [{"type": "CVSS_V3", "score": sev_vector}]
        return r

    crit, high, low = (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/INDETERMINATE:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/INDETERMINATE:N/A:H",
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/INDETERMINATE:N/A:N",
    )
    P = Status.PASS
    F = Status.FAIL
    W = Status.WARN
    INDETERMINATE = Status.INDETERMINATE
    default = {"policy": {"name": "d"}}
    unfixed = {
        "policy": {
            "name": "u",
            "vulnerabilities": {
                "block_on": [],
                "warn_on": [],
                "fail_on_unfixed": True,
                "unfixed_min_severity": "HIGH",
            },
        }
    }
    waiver = {
        "policy": {
            "name": "w",
            "vulnerabilities": {
                "waivers": [{"id": "T-1", "justification": "n/a", "expires": "2027-01-01"}]
            },
        }
    }
    expired = {
        "policy": {
            "name": "e",
            "vulnerabilities": {
                "waivers": [{"id": "T-1", "justification": "n/a", "expires": "2025-01-01"}]
            },
        }
    }
    cases = [
        ("critical blocks", default, vrec(crit), False, F),
        ("high warns", default, vrec(high), False, W),
        ("low passes", default, vrec(low), False, P),
        ("no severity -> warn", default, vrec(None), False, W),
        ("unfixed high fails", unfixed, vrec(high, None), False, F),
        ("fixed high passes", unfixed, vrec(high), False, P),
        ("active waiver", waiver, vrec(crit), False, P),
        ("expired waiver", expired, vrec(crit), False, F),
        ("no vulns", default, None, False, P),
        ("offline never passes", default, None, True, INDETERMINATE),
    ]
    ok, rows = 0, []
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / "poetry.lock").write_text(
            '[[package]]\nname="pkg"\nversion="1.0"\ngroups=["main"]\n'
        )
        (repo / "pyproject.toml").write_text('[project]\nname="x"\ndependencies=["pkg"]\n')
        for name, pol, record_, offline, want in cases:
            provider = (
                None
                if offline
                else StaticVulnerabilityProvider(
                    {"pkg:pypi/pkg@1.0": [record_]} if record_ else {}, CLOCK
                )
            )
            out = AnalysisPipeline(provider, clock=CLOCK).run(
                AnalysisRequest(
                    repo, parse_policy(pol), license_evidence={"pkg:pypi/pkg@1.0": "MIT"}
                )
            )
            ok += out.report.decision is want
            rows.append({"case": name, "expected": want.value, "got": out.report.decision.value})
        det = {
            AnalysisPipeline(
                StaticVulnerabilityProvider({"pkg:pypi/pkg@1.0": [vrec(crit)]}, CLOCK), clock=CLOCK
            )
            .run(AnalysisRequest(repo))
            .report.evidence_digest
            for _ in range(10)
        }
    record("policy-evaluation", "decision-table", ok, len(cases), {"cases": rows})
    record("policy-evaluation", "determinism-10-runs", int(len(det) == 1), 1)


# 8. Reliability --------------------------------------------------------------------------------------------
def eval_reliability() -> None:
    rng = random.Random(42)
    names = [
        "requirements.txt",
        "pyproject.toml",
        "poetry.lock",
        "uv.lock",
        "package.json",
        "package-lock.json",
    ]
    crashes = parse_errors = total = 0
    for n in names:
        parser = get_parser(n)
        for _ in range(500):
            total += 1
            try:
                parser.parse(rng.randbytes(rng.randint(0, 300)), n)
            except ParseError:
                parse_errors += 1
            except Exception:  # noqa: BLE001
                crashes += 1
    record(
        "dependency-analysis",
        "parser-fuzz-random-bytes",
        total - crashes,
        total,
        {"clean_parse_errors": parse_errors, "unhandled_exceptions": crashes},
    )


if __name__ == "__main__":
    for fn in (
        eval_dependency,
        eval_sbom,
        eval_vulnerability,
        eval_license,
        eval_integrity,
        eval_provenance,
        eval_policy,
        eval_reliability,
    ):
        fn()
    lines = [
        "# Evaluation summary",
        "",
        "Generated by `python benchmarks/run_evaluation.py`.",
        "",
        "| Area | Evaluation | Passed | Total |",
        "|---|---|---|---|",
    ]
    lines += [
        f"| {r['area']} | {r['evaluation']} | {r['passed']} | {r['total']} |" for r in summary
    ]
    (OUT / "final").mkdir(parents=True, exist_ok=True)
    (OUT / "final" / "evaluation-summary.md").write_text("\n".join(lines) + "\n")
    bad = [r for r in summary if r["passed"] != r["total"]]
    print(
        "\nFAILED EVALUATIONS:" if bad else "\nAll evaluations match ground truth.",
        [r["evaluation"] for r in bad],
    )
    sys.exit(1 if bad else 0)
