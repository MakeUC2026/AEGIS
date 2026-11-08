"""AFF intelligence tables (M3 B-01): risky_tool_patterns, risky_behavior_events (hypertable,
pgvector), forensic_reports, drafts. PRD §7.5, §10.2, §10.3, §14.7.

Foreign keys only to users.id (plan §0.2 rule 5); M2 IDs (events, sessions, traces) are text.

Revision ID: 0004_firewall_intel
Revises: 0001_foundation
"""

from __future__ import annotations

from alembic import op

revision = "0004_firewall_intel"
down_revision = "0001_foundation"
branch_labels = ("fw_intel",)
depends_on = None

_STAGES = (
    "'input_check', 'tool_call_check', 'tool_executed', 'output_check', 'review_resolved',"
    " 'finalize'"
)

_DDL = (
    """
    CREATE TABLE risky_tool_patterns (
        pattern_id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        tool                 text NOT NULL,
        conditions           jsonb NOT NULL DEFAULT '[]'
                             CHECK (jsonb_typeof(conditions) = 'array'),
        status               text NOT NULL DEFAULT 'candidate'
                             CHECK (status IN ('candidate', 'approved', 'rejected')),
        approved_in_version  int CHECK (approved_in_version >= 1),
        retired_in_version   int,
        source_event_id      text,
        source_user_id       uuid REFERENCES users (id),
        source_args          jsonb,
        source_args_hash     text,
        source_draft_id      uuid,
        created_at           timestamptz NOT NULL DEFAULT now(),
        decided_at           timestamptz,
        decided_by           uuid REFERENCES users (id),
        CHECK ((status = 'approved') = (approved_in_version IS NOT NULL)),
        CHECK (status <> 'approved' OR jsonb_array_length(conditions) > 0),
        CHECK (retired_in_version IS NULL
               OR (approved_in_version IS NOT NULL AND retired_in_version > approved_in_version))
    )
    """,
    # One version number is issued once (C-06, M3-X33); the lookup reads approved rows by tool.
    "CREATE UNIQUE INDEX risky_tool_patterns_approved_version_uq"
    " ON risky_tool_patterns (approved_in_version) WHERE approved_in_version IS NOT NULL",
    "CREATE UNIQUE INDEX risky_tool_patterns_retired_version_uq"
    " ON risky_tool_patterns (retired_in_version) WHERE retired_in_version IS NOT NULL",
    "CREATE UNIQUE INDEX risky_tool_patterns_source_uq"
    " ON risky_tool_patterns (tool, source_args_hash) WHERE source_args_hash IS NOT NULL",
    "CREATE INDEX risky_tool_patterns_lookup_idx"
    " ON risky_tool_patterns (tool, approved_in_version) WHERE status = 'approved'",
    # The ledger issues each pattern version once, approvals and retirements alike, so an
    # approve racing a retire cannot both take N+1 and change a pinned session's set (I-7).
    """
    CREATE TABLE risky_pattern_versions (
        version     int PRIMARY KEY CHECK (version >= 1),
        pattern_id  uuid NOT NULL REFERENCES risky_tool_patterns (pattern_id),
        change      text NOT NULL CHECK (change IN ('approve', 'retire')),
        created_at  timestamptz NOT NULL DEFAULT now(),
        created_by  uuid REFERENCES users (id)
    )
    """,
    f"""
    CREATE TABLE risky_behavior_events (
        time             timestamptz NOT NULL,
        user_id          uuid NOT NULL REFERENCES users (id),
        fw_session_id    text NOT NULL,
        event_id         text NOT NULL,
        stage            text NOT NULL CHECK (stage IN ({_STAGES})),
        tool             text,
        args_hash        text,
        action           text NOT NULL CHECK (action IN ('deny', 'human_deny', 'divert')),
        sentinel_score   int NOT NULL CHECK (sentinel_score BETWEEN 0 AND 100),
        rule_ids         text[] NOT NULL DEFAULT '{{}}',
        input_text_hash  text NOT NULL,
        input_embedding  vector(768),
        trace_id         text,
        shadow           boolean NOT NULL
    )
    """,
    "SELECT create_hypertable('risky_behavior_events', 'time',"
    " chunk_time_interval => INTERVAL '7 days')",
    # Per-user signals ignore shadow rows (M3-X07); partial indexes match those predicates.
    "CREATE INDEX risky_behavior_events_user_tool_idx"
    " ON risky_behavior_events (user_id, tool, time DESC) WHERE NOT shadow",
    "CREATE INDEX risky_behavior_events_user_divert_idx"
    " ON risky_behavior_events (user_id, time DESC) WHERE action = 'divert' AND NOT shadow",
    "CREATE INDEX risky_behavior_events_embedding_idx ON risky_behavior_events"
    " USING hnsw (input_embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64)",
    "CREATE INDEX risky_behavior_events_backfill_idx"
    " ON risky_behavior_events (time) WHERE input_embedding IS NULL",
    """
    CREATE TABLE forensic_reports (
        report_id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        event_id               text NOT NULL UNIQUE,
        fw_session_id          text,
        user_id                uuid REFERENCES users (id),
        attack_family          text NOT NULL CHECK (attack_family IN (
                                   'direct_override', 'indirect_injection',
                                   'authority_spoofing', 'forged_approval', 'goal_drift',
                                   'exfiltration_via_email', 'encoded_or_split_leak',
                                   'shell_abuse')),
        atlas_techniques       text[] NOT NULL DEFAULT '{}',
        summary                text NOT NULL,
        missed_signals         text[] NOT NULL DEFAULT '{}',
        would_have_blocked_in  text[] NOT NULL DEFAULT '{}'
                               CHECK (would_have_blocked_in <@ ARRAY['off', 'basic', 'strict']),
        model_id               text,
        created_at             timestamptz NOT NULL DEFAULT now()
    )
    """,
    "CREATE INDEX forensic_reports_session_idx ON forensic_reports (fw_session_id)",
    """
    CREATE TABLE drafts (
        draft_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        source_event_id  text NOT NULL UNIQUE,
        kind             text NOT NULL CHECK (kind IN ('rule', 'pattern')),
        body             jsonb NOT NULL,
        status           text NOT NULL DEFAULT 'pending' CHECK (status IN
                         ('pending', 'failed_validation', 'approved', 'rejected')),
        validation       jsonb,
        cluster_id       uuid,
        embedding        vector(768),
        result_ref       text,
        created_at       timestamptz NOT NULL DEFAULT now(),
        updated_at       timestamptz NOT NULL DEFAULT now(),
        decided_at       timestamptz,
        decided_by       uuid REFERENCES users (id)
    )
    """,
    "CREATE INDEX drafts_status_idx ON drafts (status, created_at DESC)",
    "CREATE INDEX drafts_cluster_idx ON drafts (cluster_id) WHERE cluster_id IS NOT NULL",
)


def upgrade() -> None:
    for ddl in _DDL:
        op.execute(ddl)


def downgrade() -> None:
    for table in (
        "drafts",
        "forensic_reports",
        "risky_behavior_events",
        "risky_pattern_versions",
        "risky_tool_patterns",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table}")
