from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, Path, UploadFile

from aegischain_api.dependencies import get_service
from aegischain_api.schemas import UUID_PATTERN, AnalysisSummary
from aegischain_api.services import AnalysisService

router = APIRouter(tags=["analysis"])


@router.post("/analysis", response_model=AnalysisSummary, status_code=201)
def start_analysis(
    project_id: Annotated[str, Form(pattern=UUID_PATTERN)],
    archive: Annotated[UploadFile, File(description="zip / tar.gz of the repository")],
    policy: Annotated[str | None, Form(max_length=64)] = None,
    include_dev: Annotated[bool, Form()] = True,
    svc: AnalysisService = Depends(get_service),
) -> dict[str, object]:
    """Upload a repository archive; the analysis runs synchronously and is stored."""
    return svc.analyze_archive(project_id, archive.file, policy, include_dev)


@router.get("/analysis/{run_id}")
def get_analysis(
    run_id: str = Path(pattern=UUID_PATTERN), svc: AnalysisService = Depends(get_service)
) -> dict[str, object]:
    run = svc.get_run(run_id)
    return {
        k: run[k]
        for k in (
            "id",
            "project_id",
            "created_at",
            "decision",
            "evidence_digest",
            "repository_id",
            "policy_name",
            "policy_version",
        )
    } | {
        "policy_evaluation": run["report"]["policy_evaluation"],
        "metrics": run["report"]["metrics"],
    }
