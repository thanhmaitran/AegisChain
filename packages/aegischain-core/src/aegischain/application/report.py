"""Rendering and writing of analysis outputs."""

from __future__ import annotations

from pathlib import Path

from aegischain.application.pipeline import AnalysisOutput
from aegischain.domain.models import AnalysisReport
from aegischain.domain.status import Status
from aegischain.utils.serialization import pretty_json, to_jsonable

_MARK = {
    Status.PASS: "PASS",
    Status.FAIL: "FAIL",
    Status.WARN: "WARN",
    Status.INDETERMINATE: "INDETERMINATE",
}


def render_markdown(report: AnalysisReport) -> str:
    ev = report.policy_evaluation
    lines = [
        "# AegisChain Security Audit Report",
        "",
        f"**Final decision: {_MARK[ev.status]}**",
        "",
        f"- Repository: `{report.ingestion.root_name}` (`{report.repository_id}`)",
        f"- Policy: `{ev.policy_name}` v{ev.policy_version} (evaluated as of {ev.as_of.isoformat()})",
        f"- Tool: AegisChain {report.tool_version}, generated {report.generated_at.isoformat()}",
        f"- Evidence digest: `{report.evidence_digest}`",
        "",
        "## Engine results",
        "",
        "| Engine | Status | Evaluated |",
        "|---|---|---|",
    ]
    lines += [
        f"| {e.engine} | {_MARK[e.status]} | {'yes' if e.evaluated else 'no (not required)'} |"
        for e in ev.engines
    ]
    lines += ["", "## Reasons", ""]
    lines += [f"- {r}" for r in ev.reasons] or ["- None: every evaluated rule passed."]
    v = report.vulnerability
    lines += [
        "",
        "## Vulnerabilities",
        "",
        f"Source: {v.source}; lookup status: **{v.lookup_status.value}**"
        + (f"; queried at {v.queried_at.isoformat()}" if v.queried_at else ""),
    ]
    if v.matches:
        lines += [
            "",
            "| Component | Vulnerability | Severity | Fix available | Local verification |",
            "|---|---|---|---|---|",
        ]
        lines += [
            f"| `{m.component_purl}` | {m.osv_id} | {m.severity.value} | {', '.join(m.fixed_versions) or 'none'} | {m.local_verification} |"
            for m in v.matches
        ]
    else:
        lines += [
            "",
            "No matches were reported. This is not proof that the dependencies are free of vulnerabilities.",
        ]
    d = report.dependency
    direct = sum(1 for c in d.components if c.direct)
    lines += [
        "",
        "## Dependencies",
        "",
        f"{len(d.components)} components ({direct} direct, {len(d.components) - direct} transitive); "
        f"parsed files: {', '.join(d.parsed_files) or 'none'}",
    ]
    notable = [f for f in d.findings if f.status is not Status.PASS]
    lines += [f"- [{f.status.value}] {f.code}: {f.message}" for f in notable]
    if report.integrity:
        i = report.integrity
        lines += [
            "",
            "## Artifact integrity",
            "",
            f"- {i.filename}: **{i.status.value}** - {i.detail}",
            f"- SHA-256: `{i.sha256}`",
        ]
    if report.provenance and report.provenance.provided:
        lines += ["", "## Provenance", ""]
        lines += [
            f"- {c.name}: **{c.status.value}** - {c.detail}" for c in report.provenance.checks
        ]
    lines += ["", "## Metrics (seconds)", ""] + [
        f"- {k}: {v}" for k, v in sorted(report.metrics.items())
    ]
    if report.errors:
        lines += ["", "## Internal errors", ""] + [f"- {e}" for e in report.errors]
    return "\n".join(lines) + "\n"


def write_outputs(output: AnalysisOutput, out_dir: Path) -> list[Path]:
    """Write the documented artifact layout (``sbom/``, ``reports/``)."""
    written: list[Path] = []

    def put(rel: str, data: object | str) -> None:
        path = out_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data if isinstance(data, str) else pretty_json(data), encoding="utf-8")
        written.append(path)

    r = output.report
    if output.sbom is not None:
        put("sbom/sbom.cdx.json", output.sbom.cyclonedx)
        put("sbom/sbom.spdx.json", output.sbom.spdx)
        put("sbom/validation-report.json", output.sbom.validation)
    put("reports/component-inventory.json", [to_jsonable(c) for c in r.dependency.components])
    put("reports/dependency-graph.json", output.graph)
    put("reports/report.json", r)
    put("reports/report.md", render_markdown(r))
    return written
