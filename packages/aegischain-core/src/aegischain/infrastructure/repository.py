"""Persistence: repository protocol plus a stdlib SQLite implementation."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import UTC, datetime
from typing import Any, Protocol

from aegischain.domain.models import AnalysisReport
from aegischain.utils.serialization import canonical_json, to_jsonable

_SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS analysis_runs (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id),
    created_at TEXT NOT NULL, decision TEXT NOT NULL, evidence_digest TEXT NOT NULL,
    repository_id TEXT NOT NULL, policy_name TEXT NOT NULL, policy_version TEXT NOT NULL,
    report_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_runs_project ON analysis_runs(project_id, created_at);
CREATE TABLE IF NOT EXISTS components (
    run_id TEXT NOT NULL REFERENCES analysis_runs(id), purl TEXT NOT NULL, name TEXT NOT NULL,
    version TEXT, ecosystem TEXT NOT NULL, direct INTEGER NOT NULL, depth INTEGER, scope TEXT NOT NULL,
    PRIMARY KEY (run_id, purl));
CREATE TABLE IF NOT EXISTS vulnerability_matches (
    run_id TEXT NOT NULL REFERENCES analysis_runs(id), purl TEXT NOT NULL, osv_id TEXT NOT NULL,
    severity TEXT NOT NULL, fix_available INTEGER NOT NULL, PRIMARY KEY (run_id, purl, osv_id));
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, event TEXT NOT NULL,
    run_id TEXT, detail TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
    BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
    BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS runs_no_update BEFORE UPDATE ON analysis_runs
    BEGIN SELECT RAISE(ABORT, 'analysis_runs are immutable'); END;
"""


class AnalysisRepository(Protocol):
    def create_project(self, name: str) -> dict[str, Any]: ...
    def get_project(self, project_id: str) -> dict[str, Any] | None: ...
    def list_projects(self) -> list[dict[str, Any]]: ...
    def save_run(
        self, project_id: str, report: AnalysisReport, sbom: dict[str, Any] | None = None
    ) -> str: ...
    def get_run(self, run_id: str) -> dict[str, Any] | None: ...
    def list_runs(self, project_id: str) -> list[dict[str, Any]]: ...
    def get_sbom(self, run_id: str, fmt: str) -> dict[str, Any] | None: ...
    def audit(self, event: str, run_id: str | None, detail: str) -> None: ...
    def list_audit(self, run_id: str | None = None) -> list[dict[str, Any]]: ...


def _now() -> str:
    return datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class SqliteRepository:
    """Single-connection SQLite store (development, tests, single-node use)."""

    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS sboms (run_id TEXT NOT NULL REFERENCES analysis_runs(id), fmt TEXT NOT NULL, body TEXT NOT NULL, PRIMARY KEY (run_id, fmt))"
            )
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def create_project(self, name: str) -> dict[str, Any]:
        pid = str(uuid.uuid4())
        with self._lock:
            self._conn.execute("INSERT INTO projects VALUES (?,?,?)", (pid, name, _now()))
            self._conn.commit()
        self.audit("project.created", None, name)
        return {"id": pid, "name": name}

    def get_project(self, project_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        return dict(row) if row else None

    def list_projects(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                dict(r)
                for r in self._conn.execute("SELECT * FROM projects ORDER BY created_at, name")
            ]

    def save_run(
        self, project_id: str, report: AnalysisReport, sbom: dict[str, Any] | None = None
    ) -> str:
        run_id = str(uuid.uuid4())
        ev = report.policy_evaluation
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO analysis_runs VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    run_id,
                    project_id,
                    _now(),
                    report.decision.value,
                    report.evidence_digest,
                    report.repository_id,
                    ev.policy_name,
                    ev.policy_version,
                    canonical_json(report),
                ),
            )
            self._conn.executemany(
                "INSERT INTO components VALUES (?,?,?,?,?,?,?,?)",
                [
                    (
                        run_id,
                        c.purl,
                        c.name,
                        c.version,
                        c.ecosystem.value,
                        int(c.direct),
                        c.depth,
                        c.scope.value,
                    )
                    for c in report.dependency.components
                ],
            )
            self._conn.executemany(
                "INSERT OR IGNORE INTO vulnerability_matches VALUES (?,?,?,?,?)",
                [
                    (run_id, m.component_purl, m.osv_id, m.severity.value, int(m.fix_available))
                    for m in report.vulnerability.matches
                ],
            )
            for fmt, body in (sbom or {}).items():
                self._conn.execute(
                    "INSERT INTO sboms VALUES (?,?,?)", (run_id, fmt, canonical_json(body))
                )
        self.audit("analysis.saved", run_id, report.decision.value)
        return run_id

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM analysis_runs WHERE id=?", (run_id,)).fetchone()
        if row is None:
            return None
        out = {k: row[k] for k in row.keys() if k != "report_json"}
        out["report"] = json.loads(row["report_json"])
        return out

    def list_runs(self, project_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, created_at, decision, evidence_digest, policy_name FROM analysis_runs "
                "WHERE project_id=? ORDER BY created_at DESC, id",
                (project_id,),
            )
            return [dict(r) for r in rows]

    def get_sbom(self, run_id: str, fmt: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT body FROM sboms WHERE run_id=? AND fmt=?", (run_id, fmt)
            ).fetchone()
        return json.loads(row["body"]) if row else None

    def audit(self, event: str, run_id: str | None, detail: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO audit_log (ts, event, run_id, detail) VALUES (?,?,?,?)",
                (_now(), event, run_id, detail),
            )

    def list_audit(self, run_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if run_id is None:
                rows = self._conn.execute("SELECT * FROM audit_log ORDER BY id")
            else:
                rows = self._conn.execute(
                    "SELECT * FROM audit_log WHERE run_id=? ORDER BY id", (run_id,)
                )
            return [dict(r) for r in rows]


def sbom_payload(cdx: dict[str, Any], spdx: dict[str, Any]) -> dict[str, Any]:
    return {"cyclonedx": to_jsonable(cdx), "spdx": to_jsonable(spdx)}
