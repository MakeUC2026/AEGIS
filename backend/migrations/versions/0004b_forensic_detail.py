"""Forensic worker detail (M3 C-01..C-05, C-09): failed reports keep their reason, reports carry
the event's mode, level, stage, decision and time (C3 counts and the Forensics screen filter on
them without joining M2's tables), and a draft keeps the redacted source event it is validated
against (approve re-runs validation, M3-X31).

Revision ID: 0004b_forensic_detail
Revises: 0004_firewall_intel
"""

from __future__ import annotations

from alembic import op

revision = "0004b_forensic_detail"
down_revision = "0004_firewall_intel"
branch_labels = None
depends_on = None

_DECISIONS = "'allow', 'deny', 'review', 'human_deny', 'divert'"

_UP = (
    "ALTER TABLE forensic_reports"
    " ADD COLUMN status text NOT NULL DEFAULT 'done' CHECK (status IN ('done', 'failed')),"
    " ADD COLUMN failure_reason text,"
    " ADD COLUMN mode text CHECK (mode IN ('off', 'basic', 'strict')),"
    " ADD COLUMN level_id text,"
    " ADD COLUMN stage text,"
    f" ADD COLUMN decision text CHECK (decision IN ({_DECISIONS})),"
    " ADD COLUMN event_time timestamptz,"
    " ALTER COLUMN attack_family DROP NOT NULL,"
    " ALTER COLUMN summary DROP NOT NULL",
    # A done report has its analysis; a failed one has a reason and no analysis (M3-X23).
    "ALTER TABLE forensic_reports ADD CONSTRAINT forensic_reports_status_shape CHECK ("
    " (status = 'done' AND attack_family IS NOT NULL AND summary IS NOT NULL)"
    " OR (status = 'failed' AND attack_family IS NULL AND failure_reason IS NOT NULL))",
    "CREATE INDEX forensic_reports_family_idx ON forensic_reports (attack_family, event_time)"
    " WHERE status = 'done'",
    "ALTER TABLE drafts ADD COLUMN source jsonb",
)

_DOWN = (
    "ALTER TABLE drafts DROP COLUMN source",
    "DROP INDEX forensic_reports_family_idx",
    "DELETE FROM forensic_reports WHERE status = 'failed'",
    "ALTER TABLE forensic_reports DROP CONSTRAINT forensic_reports_status_shape,"
    " ALTER COLUMN attack_family SET NOT NULL, ALTER COLUMN summary SET NOT NULL,"
    " DROP COLUMN status, DROP COLUMN failure_reason, DROP COLUMN mode, DROP COLUMN level_id,"
    " DROP COLUMN stage, DROP COLUMN decision, DROP COLUMN event_time",
)


def upgrade() -> None:
    for ddl in _UP:
        op.execute(ddl)


def downgrade() -> None:
    for ddl in _DOWN:
        op.execute(ddl)
