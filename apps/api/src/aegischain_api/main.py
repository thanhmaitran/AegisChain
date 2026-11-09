"""FastAPI application factory.  Run: ``uvicorn aegischain_api.main:create_app --factory``."""

from __future__ import annotations

import sqlite3
from collections.abc import Awaitable, Callable

from aegischain.application.pipeline import AnalysisPipeline
from aegischain.engines.provenance.verifiers.signature_verifier import SigstoreCliVerifier
from aegischain.engines.vulnerability.provider import OsvProvider, SkippedVulnerabilityProvider
from aegischain.exceptions import ArchiveError, PolicyError, ValidationError
from aegischain.infrastructure.cache import VulnerabilityCache
from aegischain.infrastructure.osv_client import OsvClient
from aegischain.infrastructure.repository import AnalysisRepository, SqliteRepository
from aegischain.utils.logging import configure_logging
from fastapi import Depends, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from aegischain_api.dependencies import require_api_key
from aegischain_api.routers import analysis, artifacts, policies, projects, results
from aegischain_api.services import AnalysisService, NotFound
from aegischain_api.settings import Settings

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}


def build_repository(url: str) -> AnalysisRepository:
    if url.startswith("sqlite:///"):
        return SqliteRepository(url.removeprefix("sqlite:///") or ":memory:")
    from aegischain.infrastructure.sqlalchemy_repository import SqlAlchemyRepository

    return SqlAlchemyRepository(url)


def create_app(settings: Settings | None = None, service: AnalysisService | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    configure_logging()
    if service is None:
        cache = VulnerabilityCache(settings.osv_cache_dir)

        def factory() -> AnalysisPipeline:
            provider = (
                SkippedVulnerabilityProvider()
                if settings.offline
                else OsvProvider(OsvClient(), cache)
            )
            return AnalysisPipeline(provider, SigstoreCliVerifier())

        service = AnalysisService(
            build_repository(settings.database_url),
            factory,
            settings.policy_dir,
            settings.max_upload_bytes,
            SigstoreCliVerifier(),
        )

    app = FastAPI(
        title="AegisChain API",
        version="0.1.0",
        description="Software supply chain security and provenance platform",
    )
    app.state.settings, app.state.service = settings, service

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_origins),
            allow_methods=["GET", "POST"],
            allow_headers=["X-API-Key", "Content-Type"],
        )

    @app.middleware("http")
    async def harden(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > settings.max_upload_bytes + 1024 * 1024:
            return JSONResponse(
                {"detail": "request body too large"}, status_code=413, headers=_SECURITY_HEADERS
            )
        response = await call_next(request)
        for k, v in _SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        return response

    @app.exception_handler(NotFound)
    async def _nf(_: Request, exc: NotFound) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=404)

    @app.exception_handler(ArchiveError)
    async def _arch(_: Request, exc: ArchiveError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=400)

    @app.exception_handler(ValidationError)
    async def _val(_: Request, exc: ValidationError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=422)

    @app.exception_handler(PolicyError)
    async def _pol(_: Request, exc: PolicyError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=422)

    @app.exception_handler(sqlite3.IntegrityError)
    async def _dup(_: Request, exc: sqlite3.IntegrityError) -> JSONResponse:
        return JSONResponse(
            {"detail": "conflict: resource already exists or references a missing parent"},
            status_code=409,
        )

    @app.get("/health", tags=["meta"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    for r in (projects.router, analysis.router, results.router, artifacts.router, policies.router):
        app.include_router(r, prefix="/api/v1", dependencies=[Depends(require_api_key)])
    return app
