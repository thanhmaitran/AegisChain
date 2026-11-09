from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Path, Query
from fastapi.responses import PlainTextResponse

from aegischain_api.dependencies import get_service
from aegischain_api.schemas import UUID_PATTERN
from aegischain_api.services import AnalysisService

router = APIRouter(tags=["results"])
RunId = Path(pattern=UUID_PATTERN)


@router.get("/dependencies/{run_id}")
def dependencies(
    run_id: str = RunId, svc: AnalysisService = Depends(get_service)
) -> dict[str, Any]:
    return svc.dependencies(run_id)


@router.get("/sbom/{run_id}")
def sbom(
    run_id: str = RunId,
    format: str = Query("cyclonedx", pattern="^(cyclonedx|spdx)$"),
    svc: AnalysisService = Depends(get_service),
) -> dict[str, Any]:
    return svc.sbom(run_id, format)


@router.get("/vulnerabilities/{run_id}")
def vulnerabilities(
    run_id: str = RunId, svc: AnalysisService = Depends(get_service)
) -> dict[str, Any]:
    return svc.vulnerabilities(run_id)


@router.get("/reports/{run_id}", response_model=None)
def report(
    run_id: str = RunId,
    format: str = Query("json", pattern="^(json|markdown)$"),
    svc: AnalysisService = Depends(get_service),
) -> Any:
    body = svc.report(run_id, format)
    return PlainTextResponse(body, media_type="text/markdown") if isinstance(body, str) else body


@router.get("/provenance/{run_id}")
def provenance(run_id: str = RunId, svc: AnalysisService = Depends(get_service)) -> dict[str, Any]:
    r = svc.get_run(run_id)["report"]
    return {"integrity": r["integrity"], "provenance": r["provenance"]}
