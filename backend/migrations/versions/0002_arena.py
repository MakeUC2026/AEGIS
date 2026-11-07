"""Arena tables (M1 B-01): scenario, levels, secrets, arena_sessions, arena_turns, results, usage.

Revision ID: 0002_arena
Revises: 0001_foundation
"""

from __future__ import annotations

from alembic import op

revision = "0002_arena"
down_revision = "0001_foundation"
branch_labels = ("arena",)
depends_on = None

_TABLES = (
    """
    CREATE TABLE scenario (
        scenario_id        text PRIMARY KEY,
        company_profile    jsonb NOT NULL,
        bot_definition     jsonb NOT NULL,
        dataset            jsonb NOT NULL,
        attacker_mailbox   text NOT NULL,
        allowlist_domains  text[] NOT NULL,
        created_at         timestamptz NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE levels (
        level_id          text NOT NULL,
        level_version     int NOT NULL CHECK (level_version >= 1),
        number            int NOT NULL,
        name              text NOT NULL,
        mode              text NOT NULL CHECK (mode IN ('off', 'basic', 'strict')),
        secret_tier       text NOT NULL,
        rule_version      int NOT NULL DEFAULT 0 CHECK (rule_version >= 0),
        weights           jsonb NOT NULL,
        thresholds        jsonb NOT NULL,
        review_timeout_s  int NOT NULL CHECK (review_timeout_s BETWEEN 10 AND 3600),
        divert_enabled    boolean NOT NULL,
        created_at        timestamptz NOT NULL DEFAULT now(),
        created_by        uuid REFERENCES users (id),
        PRIMARY KEY (level_id, level_version)
    )
    """,
    """
    CREATE TABLE secrets (
        level_id                text NOT NULL,
        secret_version          int NOT NULL CHECK (secret_version >= 1),
        value                   text NOT NULL,
        created_at              timestamptz NOT NULL DEFAULT now(),
        created_by              uuid REFERENCES users (id),
        compromised_at          timestamptz,
        compromised_by_user     uuid REFERENCES users (id),
        compromised_by_session  uuid,
        PRIMARY KEY (level_id, secret_version)
    )
    """,
    """
    CREATE TABLE arena_sessions (
        id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id             uuid NOT NULL REFERENCES users (id),
        level_id            text NOT NULL,
        level_version       int NOT NULL,
        mode                text NOT NULL CHECK (mode IN ('off', 'basic', 'strict')),
        fw_session_id       text NOT NULL UNIQUE,
        manifest_id         text NOT NULL,
        secret_version      int NOT NULL,
        status              text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'closed')),
        pending_ticket_id   text,
        admin_test          boolean NOT NULL DEFAULT false,
        secret_obtained_at  timestamptz,
        recap_unlocked_at   timestamptz,
        started_at          timestamptz NOT NULL DEFAULT now(),
        closed_at           timestamptz,
        FOREIGN KEY (level_id, level_version) REFERENCES levels (level_id, level_version),
        FOREIGN KEY (level_id, secret_version) REFERENCES secrets (level_id, secret_version)
    )
    """,
    """
    CREATE TABLE arena_turns (
        session_id   uuid NOT NULL REFERENCES arena_sessions (id) ON DELETE CASCADE,
        message_id   text NOT NULL,
        text         text NOT NULL,
        status       text NOT NULL CONSTRAINT arena_turns_status_check CHECK (status IN
                     ('sent', 'replied', 'blocked', 'awaiting_review', 'human_denied', 'not_sent')),
        player_view  jsonb,
        ticket_id    text,
        created_at   timestamptz NOT NULL DEFAULT now(),
        updated_at   timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY (session_id, message_id)
    )
    """,
    """
    CREATE TABLE results (
        session_id      uuid PRIMARY KEY REFERENCES arena_sessions (id) ON DELETE CASCADE,
        user_id         uuid NOT NULL REFERENCES users (id),
        level_id        text NOT NULL,
        secret_version  int NOT NULL,
        message_id      text NOT NULL,
        delivered_at    timestamptz NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE usage (
        id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        time        timestamptz NOT NULL DEFAULT now(),
        kind        text NOT NULL CHECK (kind IN ('message', 'llm_call')),
        user_id     uuid REFERENCES users (id),
        message_id  text,
        provider    text
    )
    """,
)

_INDEXES = (
    "CREATE INDEX arena_sessions_user_idx ON arena_sessions (user_id, started_at DESC)",
    "CREATE INDEX arena_sessions_level_idx ON arena_sessions (level_id, status)",
    "CREATE INDEX arena_turns_ticket_idx ON arena_turns (ticket_id) WHERE ticket_id IS NOT NULL",
    "CREATE INDEX results_user_level_idx ON results (user_id, level_id)",
    # One hourly-cap slot per (user, message_id): a retry of the same message is free (M1-X10).
    "CREATE UNIQUE INDEX usage_message_once_idx ON usage (user_id, message_id)"
    " WHERE kind = 'message'",
    "CREATE INDEX usage_user_time_idx ON usage (user_id, time DESC) WHERE kind = 'message'",
    "CREATE INDEX usage_llm_time_idx ON usage (time DESC) WHERE kind = 'llm_call'",
)


def upgrade() -> None:
    for ddl in (*_TABLES, *_INDEXES):
        op.execute(ddl)


def downgrade() -> None:
    for table in (
        "usage",
        "results",
        "arena_turns",
        "arena_sessions",
        "secrets",
        "levels",
        "scenario",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table}")
