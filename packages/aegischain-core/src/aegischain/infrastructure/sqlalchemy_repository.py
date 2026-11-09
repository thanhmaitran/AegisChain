"""PostgreSQL (or any SQLAlchemy-supported) implementation of ``AnalysisRepository``.

Install with ``pip install 'aegischain[api]'``. Schema is managed by Alembic
(``database/migrations``); ``create_all`` is deliberately NOT called here.

NOTE: written against the SQLAlchemy 2.0 Core API. See docs/development/testing.md for
the status of the integration tests that exercise this class.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
    insert,
    select,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine

from aegischain.domain.models import AnalysisReport
from aegischain.utils.serialization import to_jsonable

metadata = MetaData()
_JSON = JSON().with_variant(JSONB(), "postgresql")
_TS = DateTime(timezone=True)

projects = Table(
    "projects",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("name", String(100), nullable=False, unique=True),
    Column("created_at", _TS, nullable=False),
)
analysis_runs = Table(
    "analysis_runs",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("project_id", String(36), ForeignKey("projects.id"), nullable=False, index=True),
    Column("created_at", _TS, nullable=False),
    Column("decision", String(16), nullable=False),
    Column("evidence_digest", String(80), nullable=False),
    Column("repository_id", String(80), nullable=False),
    Column("policy_name", String(100), nullable=False),
    Column("policy_version", String(32), nullable=False),
    Column("report", _JSON, nullable=False),
)
components = Table(
    "components",
    metadata,
    Column("run_id", String(36), ForeignKey("analysis_runs.id"), primary_key=True),
    Column("purl", Text, primary_key=True),
    Column("name", Text, nullable=False),
    Column("version", Text),
    Column("ecosystem", String(16), nullable=False),
    Column("direct", Boolean, nullable=False),
    Column("depth", Integer),
    Column("scope", String(16), nullable=False),
)
vulnerability_matches = Table(
    "vulnerability_matches",
    metadata,
    Column("run_id", String(36), ForeignKey("analysis_runs.id"), primary_key=True),
    Column("purl", Text, primary_key=True),
    Column("osv_id", Text, primary_key=True),
    Column("severity", String(16), nullable=False),
    Column("fix_available", Boolean, nullable=False),
)
sboms = Table(
    "sboms",
    metadata,
    Column("run_id", String(36), ForeignKey("analysis_runs.id"), primary_key=True),
    Column("fmt", String(16), primary_key=True),
    Column("body", _JSON, nullable=False),
)
audit_log = Table(
    "audit_log",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("ts", _TS, nullable=False),
    Column("event", String(64), nullable=False),
    Column("run_id", String(36)),
    Column("detail", Text, nullable=False),
)


def _row(row: Any) -> dict[str, Any]:
    out = dict(row._mapping)
    for k, v in out.items():
        if isinstance(v, datetime):
            out[k] = v.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return out


class SqlAlchemyRepository:
    def __init__(self, url: str, engine: Engine | None = None) -> None:
        self._engine = engine or create_engine(url, pool_pre_ping=True, future=True)

    @staticmethod
    def _now() -> datetime:
        return datetime.now(tz=UTC)

    def create_project(self, name: str) -> dict[str, Any]:
        pid = str(uuid.uuid4())
        with self._engine.begin() as conn:
            conn.execute(insert(projects).values(id=pid, name=name, created_at=self._now()))
        self.audit("project.created", None, name)
        return {"id": pid, "name": name}

    def get_project(self, project_id: str) -> dict[str, Any] | None:
        with self._engine.connect() as conn:
            row = conn.execute(select(projects).where(projects.c.id == project_id)).first()
        return _row(row) if row else None

    def list_projects(self) -> list[dict[str, Any]]:
        with self._engine.connect() as conn:
            return [
                _row(r)
                for r in conn.execute(
                    select(projects).order_by(projects.c.created_at, projects.c.name)
                )
            ]

    def save_run(
        self, project_id: str, report: AnalysisReport, sbom: dict[str, Any] | None = None
    ) -> str:
        run_id, ev = str(uuid.uuid4()), report.policy_evaluation
        with self._engine.begin() as conn:
            conn.execute(
                insert(analysis_runs).values(
                    id=run_id,
                    project_id=project_id,
                    created_at=self._now(),
                    decision=report.decision.value,
                    evidence_digest=report.evidence_digest,
                    repository_id=report.repository_id,
                    policy_name=ev.policy_name,
                    policy_version=ev.policy_version,
                    report=json.loads(json.dumps(to_jsonable(report))),
                )
            )
            if report.dependency.components:
                conn.execute(
                    insert(components),
                    [
                        {
                            "run_id": run_id,
                            "purl": c.purl,
                            "name": c.name,
                            "version": c.version,
                            "ecosystem": c.ecosystem.value,
                            "direct": c.direct,
                            "depth": c.depth,
                            "scope": c.scope.value,
                        }
                        for c in report.dependency.components
                    ],
                )
            seen: set[tuple[str, str]] = set()
            rows = []
            for m in report.vulnerability.matches:
                if (m.component_purl, m.osv_id) not in seen:
                    seen.add((m.component_purl, m.osv_id))
                    rows.append(
                        {
                            "run_id": run_id,
                            "purl": m.component_purl,
                            "osv_id": m.osv_id,
                            "severity": m.severity.value,
                            "fix_available": m.fix_available,
                        }
                    )
            if rows:
                conn.execute(insert(vulnerability_matches), rows)
            for fmt, body in (sbom or {}).items():
                conn.execute(
                    insert(sboms).values(
                        run_id=run_id, fmt=fmt, body=json.loads(json.dumps(to_jsonable(body)))
                    )
                )
        self.audit("analysis.saved", run_id, report.decision.value)
        return run_id

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._engine.connect() as conn:
            row = conn.execute(select(analysis_runs).where(analysis_runs.c.id == run_id)).first()
        if row is None:
            return None
        out = _row(row)
        out["report"] = out.pop("report")
        return out

    def list_runs(self, project_id: str) -> list[dict[str, Any]]:
        cols = [
            analysis_runs.c.id,
            analysis_runs.c.created_at,
            analysis_runs.c.decision,
            analysis_runs.c.evidence_digest,
            analysis_runs.c.policy_name,
        ]
        with self._engine.connect() as conn:
            q = (
                select(*cols)
                .where(analysis_runs.c.project_id == project_id)
                .order_by(analysis_runs.c.created_at.desc())
            )
            return [_row(r) for r in conn.execute(q)]

    def get_sbom(self, run_id: str, fmt: str) -> dict[str, Any] | None:
        with self._engine.connect() as conn:
            row = conn.execute(
                select(sboms.c.body).where(sboms.c.run_id == run_id, sboms.c.fmt == fmt)
            ).first()
        return row[0] if row else None

    def audit(self, event: str, run_id: str | None, detail: str) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                insert(audit_log).values(ts=self._now(), event=event, run_id=run_id, detail=detail)
            )

    def list_audit(self, run_id: str | None = None) -> list[dict[str, Any]]:
        q = select(audit_log).order_by(audit_log.c.id)
        if run_id is not None:
            q = q.where(audit_log.c.run_id == run_id)
        with self._engine.connect() as conn:
            return [_row(r) for r in conn.execute(q)]
