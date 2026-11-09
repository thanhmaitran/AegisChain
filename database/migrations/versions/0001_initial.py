"""Initial schema: projects, immutable analysis runs, evidence tables, append-only audit log.

Revision ID: 0001
Revises:
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

JSONX = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    ts = sa.DateTime(timezone=True)
    op.create_table(
        "projects",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("created_at", ts, nullable=False),
    )
    op.create_table(
        "analysis_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("created_at", ts, nullable=False),
        sa.Column("decision", sa.String(16), nullable=False),
        sa.Column("evidence_digest", sa.String(80), nullable=False),
        sa.Column("repository_id", sa.String(80), nullable=False),
        sa.Column("policy_name", sa.String(100), nullable=False),
        sa.Column("policy_version", sa.String(32), nullable=False),
        sa.Column("report", JSONX, nullable=False),
        sa.CheckConstraint(
            "decision IN ('PASS','FAIL','WARN','INDETERMINATE')", name="ck_runs_decision"
        ),
    )
    op.create_index("ix_runs_project_created", "analysis_runs", ["project_id", "created_at"])
    op.create_table(
        "components",
        sa.Column("run_id", sa.String(36), sa.ForeignKey("analysis_runs.id"), primary_key=True),
        sa.Column("purl", sa.Text, primary_key=True),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("version", sa.Text),
        sa.Column("ecosystem", sa.String(16), nullable=False),
        sa.Column("direct", sa.Boolean, nullable=False),
        sa.Column("depth", sa.Integer),
        sa.Column("scope", sa.String(16), nullable=False),
    )
    op.create_index("ix_components_name", "components", ["name"])
    op.create_table(
        "vulnerability_matches",
        sa.Column("run_id", sa.String(36), sa.ForeignKey("analysis_runs.id"), primary_key=True),
        sa.Column("purl", sa.Text, primary_key=True),
        sa.Column("osv_id", sa.Text, primary_key=True),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("fix_available", sa.Boolean, nullable=False),
    )
    op.create_index("ix_vuln_osv", "vulnerability_matches", ["osv_id"])
    op.create_table(
        "sboms",
        sa.Column("run_id", sa.String(36), sa.ForeignKey("analysis_runs.id"), primary_key=True),
        sa.Column("fmt", sa.String(16), primary_key=True),
        sa.Column("body", JSONX, nullable=False),
    )
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("ts", ts, nullable=False),
        sa.Column("event", sa.String(64), nullable=False),
        sa.Column("run_id", sa.String(36)),
        sa.Column("detail", sa.Text, nullable=False),
    )
    if op.get_bind().dialect.name == "postgresql":
        op.execute("""
            CREATE FUNCTION aegis_forbid_mutation() RETURNS trigger AS $$
            BEGIN RAISE EXCEPTION '% on % is not permitted (append-only / immutable)', TG_OP, TG_TABLE_NAME; END;
            $$ LANGUAGE plpgsql;
            CREATE TRIGGER audit_log_immutable BEFORE UPDATE OR DELETE ON audit_log
                FOR EACH ROW EXECUTE FUNCTION aegis_forbid_mutation();
            CREATE TRIGGER analysis_runs_immutable BEFORE UPDATE ON analysis_runs
                FOR EACH ROW EXECUTE FUNCTION aegis_forbid_mutation();
        """)


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS analysis_runs_immutable ON analysis_runs;"
            "DROP TRIGGER IF EXISTS audit_log_immutable ON audit_log; DROP FUNCTION IF EXISTS aegis_forbid_mutation();"
        )
    for table in (
        "audit_log",
        "sboms",
        "vulnerability_matches",
        "components",
        "analysis_runs",
        "projects",
    ):
        op.drop_table(table)
