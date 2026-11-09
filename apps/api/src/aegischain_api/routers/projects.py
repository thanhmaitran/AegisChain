from __future__ import annotations

from fastapi import APIRouter, Depends, Path

from aegischain_api.dependencies import get_service
from aegischain_api.schemas import UUID_PATTERN, ProjectCreate, ProjectOut
from aegischain_api.services import AnalysisService

router = APIRouter(tags=["projects"])


@router.post("/projects", response_model=ProjectOut, status_code=201)
def create_project(
    body: ProjectCreate, svc: AnalysisService = Depends(get_service)
) -> dict[str, str]:
    return svc.repo.create_project(body.name)


@router.get("/projects", response_model=list[ProjectOut])
def list_projects(svc: AnalysisService = Depends(get_service)) -> list[dict[str, str]]:
    return svc.repo.list_projects()


@router.get("/projects/{project_id}/runs")
def list_runs(
    project_id: str = Path(pattern=UUID_PATTERN), svc: AnalysisService = Depends(get_service)
) -> list[dict[str, object]]:
    svc.require_project(project_id)
    return svc.repo.list_runs(project_id)
