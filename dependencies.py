"""FastAPI dependencies: authentication and service access."""

from __future__ import annotations

import hmac

from fastapi import Depends, Header, HTTPException, Request, status

from aegischain_api.services import AnalysisService


def get_service(request: Request) -> AnalysisService:
    service: AnalysisService = request.app.state.service
    return service


def require_api_key(request: Request, x_api_key: str | None = Header(default=None)) -> None:
    expected: str = request.app.state.settings.api_key
    if x_api_key is None or not hmac.compare_digest(x_api_key.encode(), expected.encode()):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )


ServiceDep = Depends(get_service)
