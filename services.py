"""Application services for the API. Framework-free so they are unit-testable.

Security rules enforced here:
* clients never supply filesystem paths: uploads are spooled to a private temp dir,
  policies are chosen by *name* from a server-side directory;
* uploads are size-limited while streaming and extracted with zip-slip/bomb protection;
* uploaded file names are never used on disk.
"""

from __future__ import annotations

import re
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, cast

from aegischain.application.pipeline import AnalysisPipeline, AnalysisRequest
from aegischain.application.report import render_markdown
from aegischain.domain.interfaces import SignatureVerifier
from aegischain.domain.models import AnalysisReport
from aegischain.domain.status import worst
from aegischain.engines.integrity.hasher import verify_artifact
from aegischain.engines.policy import SecurityEvidence, SecurityPolicy, evaluate_policy, load_policy
from aegischain.engines.policy.rules import rules as R
from aegischain.engines.provenance.verifiers.provenance_verifier import (
    ProvenanceExpectations,
    verify_provenance,
)
from aegischain.exceptions import ArchiveError, ValidationError
from aegischain.infrastructure.archive import ArchiveLimits, extract_archive
from aegischain.infrastructure.repository import AnalysisRepository
from aegischain.utils.deserialization import from_jsonable
from aegischain.utils.serialization import to_jsonable

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_CHUNK = 64 * 1024


class NotFound(LookupError):
    pass


def _require_json_object(value: object, context: str) -> dict[str, Any]:
    """Validate a JSON object before exposing it through the API service."""
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValidationError(f"stored {context} is not a JSON object")
    return cast(dict[str, Any], value)


def _spool(stream: BinaryIO, dest: Path, max_bytes: int) -> int:
    total = 0
    with open(dest, "xb") as out:
        while chunk := stream.read(_CHUNK):
            total += len(chunk)
            if total > max_bytes:
                raise ValidationError(f"upload exceeds the {max_bytes} byte limit")
            out.write(chunk)
    return total


@dataclass
class AnalysisService:
    repo: AnalysisRepository
    pipeline_factory: Callable[[], AnalysisPipeline]
    policy_dir: Path
    max_upload_bytes: int = 50 * 1024 * 1024
    signature_verifier: SignatureVerifier | None = None

    # -- policies ---------------------------------------------------------------
    def list_policies(self) -> list[str]:
        if not self.policy_dir.is_dir():
            return []
        return sorted(p.stem for p in self.policy_dir.glob("*.yaml") if _NAME.match(p.stem))

    def get_policy(self, name: str | None) -> SecurityPolicy:
        if name is None:
            return SecurityPolicy()
        if not _NAME.match(name) or name not in self.list_policies():
            raise ValidationError(f"unknown policy: {name!r}")
        return load_policy(self.policy_dir / f"{name}.yaml")

    # -- projects ---------------------------------------------------------------
    def require_project(self, project_id: str) -> dict[str, Any]:
        project = self.repo.get_project(project_id)
        if project is None:
            raise NotFound("project not found")
        return project

    # -- analysis ---------------------------------------------------------------
    def analyze_archive(
        self, project_id: str, upload: BinaryIO, policy_name: str | None, include_dev: bool = True
    ) -> dict[str, Any]:
        self.require_project(project_id)
        policy = self.get_policy(policy_name)
        with tempfile.TemporaryDirectory(prefix="aegis-") as tmp:
            work = Path(tmp)
            archive, repo_dir = work / "upload.bin", work / "repo"
            repo_dir.mkdir()
            _spool(upload, archive, self.max_upload_bytes)
            try:
                extract_archive(
                    archive, repo_dir, ArchiveLimits(max_total_bytes=self.max_upload_bytes * 4)
                )
            except ArchiveError:
                self.repo.audit("analysis.rejected", None, f"project={project_id} unsafe archive")
                raise
            output = self.pipeline_factory().run(AnalysisRequest(repo_dir, policy, include_dev))
            sboms = (
                {"cyclonedx": output.sbom.cyclonedx, "spdx": output.sbom.spdx}
                if output.sbom
                else {}
            )
            run_id = self.repo.save_run(project_id, output.report, sboms)
        return self._summary(run_id, output.report)

    @staticmethod
    def _summary(run_id: str, report: AnalysisReport) -> dict[str, Any]:
        return {
            "id": run_id,
            "decision": report.decision.value,
            "evidence_digest": report.evidence_digest,
            "components": len(report.dependency.components),
            "vulnerabilities": len(report.vulnerability.matches),
            "reasons": list(report.policy_evaluation.reasons),
        }

    def get_run(self, run_id: str) -> dict[str, Any]:
        run = self.repo.get_run(run_id)
        if run is None:
            raise NotFound("analysis not found")
        return run

    def dependencies(self, run_id: str) -> dict[str, Any]:
        dep = self.get_run(run_id)["report"]["dependency"]
        nodes = [
            {
                "id": c["purl"],
                "name": c["name"],
                "version": c["version"],
                "direct": c["direct"],
                "depth": c["depth"],
                "scope": c["scope"],
                "ecosystem": c["ecosystem"],
            }
            for c in dep["components"]
        ]
        return {
            "components": dep["components"],
            "findings": dep["findings"],
            "status": dep["status"],
            "graph": {
                "nodes": nodes,
                "edges": [{"source": s, "target": t} for s, t in dep["edges"]],
            },
        }

    def vulnerabilities(self, run_id: str) -> dict[str, Any]:
        run = self.get_run(run_id)
        report = _require_json_object(run["report"], "analysis report")
        return _require_json_object(report.get("vulnerability"), "vulnerability report")

    def sbom(self, run_id: str, fmt: str) -> dict[str, Any]:
        if fmt not in ("cyclonedx", "spdx"):
            raise ValidationError("format must be 'cyclonedx' or 'spdx'")
        self.get_run(run_id)
        body = self.repo.get_sbom(run_id, fmt)
        if body is None:
            raise NotFound("no SBOM stored for this analysis")
        return _require_json_object(body, "SBOM")

    def report(self, run_id: str, fmt: str = "json") -> dict[str, Any] | str:
        run = self.get_run(run_id)
        if fmt == "markdown":
            return render_markdown(from_jsonable(AnalysisReport, run["report"]))
        if fmt != "json":
            raise ValidationError("format must be 'json' or 'markdown'")
        return _require_json_object(run["report"], "analysis report")

    # -- policy re-evaluation -----------------------------------------------------
    def reevaluate(self, run_id: str, policy_name: str) -> dict[str, Any]:
        """Evaluate stored evidence under another policy. Evidence is never re-collected."""
        report = from_jsonable(AnalysisReport, self.get_run(run_id)["report"])
        evidence = SecurityEvidence(
            report.ingestion,
            report.dependency,
            report.sbom_validation or None,
            report.vulnerability,
            report.licenses,
            report.integrity,
            report.provenance,
            report.policy_evaluation.as_of,
        )
        result = evaluate_policy(evidence, self.get_policy(policy_name))
        self.repo.audit("policy.reevaluated", run_id, f"{policy_name} -> {result.status.value}")
        return _require_json_object(to_jsonable(result), "policy evaluation")

    # -- artifact verification ------------------------------------------------------
    def verify_artifact_upload(
        self,
        artifact: BinaryIO,
        expected_sha256: str | None,
        policy_name: str | None,
        provenance: BinaryIO | None = None,
        bundle: BinaryIO | None = None,
    ) -> dict[str, Any]:
        policy = self.get_policy(policy_name)
        with tempfile.TemporaryDirectory(prefix="aegis-art-") as tmp:
            work = Path(tmp)
            art = work / "artifact.bin"
            _spool(artifact, art, self.max_upload_bytes)
            prov_path = bundle_path = None
            if provenance is not None:
                prov_path = work / "provenance.json"
                _spool(provenance, prov_path, 5 * 1024 * 1024)
            if bundle is not None:
                bundle_path = work / "bundle.json"
                _spool(bundle, bundle_path, 5 * 1024 * 1024)
            integrity = verify_artifact(art, expected_sha256)
            pp = policy.provenance
            from aegischain.engines.provenance.verifiers.signature_verifier import (
                UnavailableSignatureVerifier,
            )

            prov = verify_provenance(
                art,
                integrity.sha256,
                prov_path,
                bundle_path,
                ProvenanceExpectations(
                    pp.trusted_builders, pp.trusted_sources, pp.signer_identity, pp.oidc_issuer
                ),
                self.signature_verifier or UnavailableSignatureVerifier(),
            )
            i_rules, _ = R.integrity_rules(integrity, policy)
            p_rules, _ = R.provenance_rules(prov, policy)
        final = worst(r.status for r in [*i_rules, *p_rules])
        self.repo.audit("artifact.verified", None, f"{final.value} sha256={integrity.sha256}")
        return {
            "status": final.value,
            "integrity": to_jsonable(integrity),
            "provenance": to_jsonable(prov),
            "rules": to_jsonable([*i_rules, *p_rules]),
        }
