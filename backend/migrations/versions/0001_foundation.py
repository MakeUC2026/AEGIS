"""Foundation: extensions, users (C1), audit_log (M1 §0.1 note 1, §0.4).

Revision ID: 0001_foundation
"""

from __future__ import annotations

from alembic import op

revision = "0001_foundation"
down_revision = None
branch_labels = ("foundation",)
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS timescaledb")
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    op.execute(
        """
        CREATE TABLE users (
            id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            auth0_sub   text NOT NULL UNIQUE,
            name        text,
            email       text,
            role        text NOT NULL DEFAULT 'student'
                        CHECK (role IN ('student', 'teacher', 'firewall_admin')),
            created_at  timestamptz NOT NULL DEFAULT now(),
            updated_at  timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE audit_log (
            id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            time        timestamptz NOT NULL DEFAULT now(),
            actor_id    uuid REFERENCES users (id),
            entity      text NOT NULL,
            entity_id   text NOT NULL,
            action      text NOT NULL,
            before      jsonb,
            after       jsonb
        )
        """
    )
    op.execute("CREATE INDEX audit_log_entity_idx ON audit_log (entity, entity_id, time DESC)")
    op.execute("CREATE INDEX audit_log_time_idx ON audit_log (time DESC)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS audit_log")
    op.execute("DROP TABLE IF EXISTS users")
