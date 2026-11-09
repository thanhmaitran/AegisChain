# 01 - System Architecture Report

**Scope.** What was built, how it is structured and why. Details: `docs/architecture/`.

* **Overview.** A modular monolith: eight engines (ingestion, dependency, SBOM, vulnerability,
  license, integrity, provenance, policy) behind explicit Protocols, orchestrated by
  `AnalysisPipeline`, exposed through a CLI, a FastAPI service and a React dashboard.
* **Decisions.** ADR-0001..0007 (`docs/design-decisions/`). Notable deviations from the initial
  proposal: stdlib dataclasses in the core (ADR-0007) and hand-written SBOM adapters validated
  structurally (ADR-0003).
* **Responsibilities.** See the table in `component-architecture.md`.
* **Data flow.** Eight stages, content-addressed inputs (SHA-256 of every parsed file), a single
  pure policy evaluation; see `data-flow.md`.
* **API architecture.** Framework-free `AnalysisService` + thin routers; clients never supply paths.
* **Database architecture.** PostgreSQL via SQLAlchemy/Alembic, SQLite for development; runs
  immutable, audit log append-only; the full report is stored as JSONB (`database-design.md`).
* **Implementation status.** See "Verification status" in `docs/security/limitations.md`.
