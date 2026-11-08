"""Key hourly-cap slots by session too (QA finding: message_id reuse across sessions was free).

Revision ID: 0002b_arena_usage_session
Revises: 0002_arena
"""

from __future__ import annotations

from alembic import op

revision = "0002b_arena_usage_session"
down_revision = "0002_arena"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE usage ADD COLUMN session_id uuid")
    op.execute("DROP INDEX IF EXISTS usage_message_once_idx")
    op.execute(
        "CREATE UNIQUE INDEX usage_message_once_idx ON usage (user_id, session_id, message_id)"
        " WHERE kind = 'message'"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS usage_message_once_idx")
    op.execute(
        "CREATE UNIQUE INDEX usage_message_once_idx ON usage (user_id, message_id)"
        " WHERE kind = 'message'"
    )
    op.execute("ALTER TABLE usage DROP COLUMN session_id")
