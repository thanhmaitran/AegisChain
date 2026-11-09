-- Reference DDL equivalent to Alembic revision 0001 (PostgreSQL). Alembic is the source of truth.
CREATE TABLE projects (
    id TEXT PRIMARY KEY, name VARCHAR(100) NOT NULL UNIQUE, created_at TIMESTAMPTZ NOT NULL);
CREATE TABLE analysis_runs (
    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
    created_at TIMESTAMPTZ NOT NULL,
    decision VARCHAR(16) NOT NULL CHECK (decision IN ('PASS','FAIL','WARN','INDETERMINATE')),
    evidence_digest VARCHAR(80) NOT NULL, repository_id VARCHAR(80) NOT NULL,
    policy_name VARCHAR(100) NOT NULL, policy_version VARCHAR(32) NOT NULL, report JSONB NOT NULL);
CREATE INDEX ix_runs_project_created ON analysis_runs (project_id, created_at);
CREATE TABLE components (
    run_id TEXT REFERENCES analysis_runs(id), purl TEXT, name TEXT NOT NULL, version TEXT,
    ecosystem VARCHAR(16) NOT NULL, direct BOOLEAN NOT NULL, depth INTEGER, scope VARCHAR(16) NOT NULL,
    PRIMARY KEY (run_id, purl));
CREATE INDEX ix_components_name ON components (name);
CREATE TABLE vulnerability_matches (
    run_id TEXT REFERENCES analysis_runs(id), purl TEXT, osv_id TEXT,
    severity VARCHAR(16) NOT NULL, fix_available BOOLEAN NOT NULL, PRIMARY KEY (run_id, purl, osv_id));
CREATE INDEX ix_vuln_osv ON vulnerability_matches (osv_id);
CREATE TABLE sboms (
    run_id TEXT REFERENCES analysis_runs(id), fmt VARCHAR(16), body JSONB NOT NULL, PRIMARY KEY (run_id, fmt));
CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY, ts TIMESTAMPTZ NOT NULL, event VARCHAR(64) NOT NULL, run_id TEXT, detail TEXT NOT NULL);
-- Immutability triggers: see database/migrations/versions/0001_initial.py
