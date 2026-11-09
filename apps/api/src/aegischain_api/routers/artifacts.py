from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, UploadFile

from aegischain_api.dependencies import get_service
from aegischain_api.services import AnalysisService

router = APIRouter(tags=["artifacts"])


@router.post("/artifacts/verify")
def verify_artifact(
    artifact: Annotated[UploadFile, File()],
    expected_sha256: Annotated[str | None, Form(max_length=71)] = None,
    policy: Annotated[str | None, Form(max_length=64)] = None,
    provenance: Annotated[UploadFile | None, File()] = None,
    signature_bundle: Annotated[UploadFile | None, File()] = None,
    svc: AnalysisService = Depends(get_service),
) -> dict[str, Any]:
    """Verify digest, provenance and signature evidence for an uploaded artifact."""
    return svc.verify_artifact_upload(
        artifact.file,
        expected_sha256,
        policy,
        provenance.file if provenance else None,
        signature_bundle.file if signature_bundle else None,
    )
