from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from aegischain_api.dependencies import get_service
from aegischain_api.schemas import PolicyEvaluateRequest
from aegischain_api.services import AnalysisService

router = APIRouter(tags=["policies"])


@router.get("/policies")
def list_policies(svc: AnalysisService = Depends(get_service)) -> list[str]:
    return svc.list_policies()


@router.post("/policies/evaluate")
def evaluate(
    body: PolicyEvaluateRequest, svc: AnalysisService = Depends(get_service)
) -> dict[str, Any]:
    """Re-evaluate the stored evidence of a run under another named policy."""
    return svc.reevaluate(body.run_id, body.policy)
