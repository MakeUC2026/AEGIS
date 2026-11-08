"""AFF core tables (M2 B-01; PRD §10.1, §14.7, §15.1; spec AEGIS-DOM-106).

rule_sets, rules (append-only), fw_sessions, fw_manifests (immutable), fw_claims,
fw_conversation, fw_mock_state, fw_tool_calls, fw_tickets, fw_events (hypertable, NOTIFY on
pending forensics), trace_back.

Every table chains to `users` by foreign key, so a TRUNCATE of `users` with CASCADE clears
them (test isolation and the demo reset). Enum values are written here, not imported from
app code, so later code changes cannot alter this migration.

Revision ID: 0003_firewall_core
Revises: 0001_foundation
"""

from __future__ import annotations

from alembic import op

revision = "0003_firewall_core"
down_revision = "0001_foundation"
branch_labels = ("fw_core",)
depends_on = None

_MODES = "'off', 'basic', 'strict'"
_STAGES = (
    "'input_check', 'tool_call_check', 'tool_executed', 'output_check', "
    "'review_resolved', 'finalize'"
)
_DECISIONS = "'allow', 'deny', 'review', 'human_deny', 'divert'"
_EXECUTION = "'not_executed', 'executed', 'held', 'diverted'"
_TICKET_STATUS = "'pending', 'approved', 'human_denied', 'expired'"

_FUNCTIONS = (
    """
    CREATE FUNCTION fw_forbid_change() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        RAISE EXCEPTION '% is %', TG_TABLE_NAME, TG_ARGV[0];
    END $$
    """,
    """
    CREATE FUNCTION fw_events_notify() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
        IF NEW.forensic_status = 'pending' THEN
            PERFORM pg_notify('fw_events_forensic', NEW.event_id);
        END IF;
        RETURN NEW;
    END $$
    """,
)

_TABLES = (
    """
    CREATE TABLE rule_sets (
        version     int PRIMARY KEY CHECK (version >= 1),
        created_at  timestamptz NOT NULL DEFAULT now(),
        created_by  uuid REFERENCES users (id),
        note        text NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE TABLE rules (
        rule_id      text NOT NULL CHECK (rule_id ~ '^[RB]-[0-9]{3}$'),
        version      int NOT NULL CHECK (version >= 1),
        set_version  int NOT NULL REFERENCES rule_sets (version),
        builtin      boolean NOT NULL,
        enabled      boolean NOT NULL,
        deprecated   boolean NOT NULL,
        form         jsonb,
        created_at   timestamptz NOT NULL DEFAULT now(),
        created_by   uuid REFERENCES users (id),
        PRIMARY KEY (rule_id, version),
        CHECK (builtin = (form IS NULL))
    )
    """,
    f"""
    CREATE TABLE fw_sessions (
        fw_session_id  text PRIMARY KEY,
        owner_ref      uuid NOT NULL REFERENCES users (id),
        mode           text NOT NULL CHECK (mode IN ({_MODES})),
        secret         text NOT NULL,
        eval           boolean NOT NULL DEFAULT false,
        status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'closed')),
        created_at     timestamptz NOT NULL DEFAULT now(),
        closed_at      timestamptz,
        CHECK ((status = 'closed') = (closed_at IS NOT NULL))
    )
    """,
    f"""
    CREATE TABLE fw_manifests (
        manifest_id        text PRIMARY KEY,
        fw_session_id      text NOT NULL UNIQUE REFERENCES fw_sessions (fw_session_id),
        owner_ref          uuid NOT NULL REFERENCES users (id),
        level_id           text NOT NULL,
        level_version      int NOT NULL,
        mode               text NOT NULL CHECK (mode IN ({_MODES})),
        rule_set_version   int NOT NULL CHECK (rule_set_version >= 1),
        pattern_version    int NOT NULL CHECK (pattern_version >= 0),
        thresholds         jsonb NOT NULL,
        weights            jsonb NOT NULL,
        agent              jsonb NOT NULL,
        bot_model_id       text NOT NULL,
        judge_model_id     text,
        judge_policy_hash  text,
        review_timeout_s   int NOT NULL CHECK (review_timeout_s BETWEEN 10 AND 3600),
        divert_enabled     boolean NOT NULL,
        created_at         timestamptz NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE fw_claims (
        fw_session_id  text NOT NULL REFERENCES fw_sessions (fw_session_id),
        message_id     text NOT NULL,
        text_hash      text NOT NULL,
        status         text NOT NULL CHECK (status IN ('in_flight', 'held', 'done')),
        ticket_id      text,
        result         jsonb,
        created_at     timestamptz NOT NULL DEFAULT now(),
        updated_at     timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY (fw_session_id, message_id)
    )
    """,
    """
    CREATE TABLE fw_conversation (
        fw_session_id  text NOT NULL REFERENCES fw_sessions (fw_session_id),
        seq            int NOT NULL CHECK (seq >= 1),
        message_id     text NOT NULL,
        role           text NOT NULL
                       CHECK (role IN ('student', 'bot', 'tool_call', 'tool_result')),
        content        text NOT NULL,
        visible        boolean NOT NULL,
        is_decoy       boolean NOT NULL DEFAULT false,
        call_id        text,
        tool           text,
        model_payload  jsonb,
        created_at     timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY (fw_session_id, seq)
    )
    """,
    """
    CREATE TABLE fw_mock_state (
        fw_session_id      text PRIMARY KEY REFERENCES fw_sessions (fw_session_id),
        documents          jsonb NOT NULL DEFAULT '[]',
        emails             jsonb NOT NULL DEFAULT '[]',
        db_rows            jsonb NOT NULL DEFAULT '{}',
        filesystem         jsonb NOT NULL DEFAULT '{}',
        attacker_mailbox   text NOT NULL DEFAULT '',
        allowlist_domains  text[] NOT NULL DEFAULT '{}',
        updated_at         timestamptz NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE fw_tool_calls (
        fw_session_id   text NOT NULL REFERENCES fw_sessions (fw_session_id),
        call_id         text NOT NULL,
        message_id      text,
        tool            text NOT NULL,
        args_hash       text NOT NULL,
        canonical_args  jsonb,
        state           text NOT NULL CHECK (
                            state IN ('executed', 'diverted', 'blocked', 'held', 'human_denied')
                        ),
        result          text,
        is_decoy        boolean NOT NULL DEFAULT false,
        created_at      timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY (fw_session_id, call_id)
    )
    """,
    f"""
    CREATE TABLE fw_tickets (
        ticket_id        text PRIMARY KEY,
        fw_session_id    text NOT NULL REFERENCES fw_sessions (fw_session_id),
        message_id       text NOT NULL,
        stage            text NOT NULL CHECK (stage IN ({_STAGES})),
        call_id          text,
        payload_hash     text NOT NULL,
        manifest_id      text NOT NULL,
        status           text NOT NULL CHECK (status IN ({_TICKET_STATUS})),
        created_at       timestamptz NOT NULL DEFAULT now(),
        expires_at       timestamptz NOT NULL,
        decided_at       timestamptz,
        decided_by       uuid REFERENCES users (id),
        continuation     jsonb,
        sentinel_score   int CHECK (sentinel_score BETWEEN 0 AND 100),
        score_breakdown  jsonb,
        rule_ids         text[] NOT NULL DEFAULT '{{}}',
        priority_alert   boolean NOT NULL DEFAULT false,
        student_command  text,
        held_tool        text,
        held_args        jsonb,
        held_reply       text,
        CHECK ((status = 'pending') = (decided_at IS NULL))
    )
    """,
    f"""
    CREATE TABLE fw_events (
        event_id                   text NOT NULL,
        time                       timestamptz NOT NULL,
        trace_id                   text,
        fw_session_id              text NOT NULL,
        user_id                    uuid NOT NULL REFERENCES users (id),
        message_id                 text NOT NULL,
        manifest_id                text NOT NULL,
        level_id                   text NOT NULL,
        mode                       text NOT NULL CHECK (mode IN ({_MODES})),
        stage                      text NOT NULL CHECK (stage IN ({_STAGES})),
        source_trust               text NOT NULL
                                   CHECK (source_trust IN ('player', 'tool_result', 'bot_output')),
        tool                       text,
        call_id                    text,
        args_hash                  text,
        sentinel_score             int NOT NULL CHECK (sentinel_score BETWEEN 0 AND 100),
        score_breakdown            jsonb NOT NULL DEFAULT '{{}}',
        thresholds_used            jsonb NOT NULL DEFAULT '{{}}',
        rule_ids_fired             text[] NOT NULL DEFAULT '{{}}',
        risky_pattern_ids_matched  text[] NOT NULL DEFAULT '{{}}',
        judge_risk                 int CHECK (judge_risk BETWEEN 0 AND 100),
        judge_reason               text,
        shadow_decision            text CHECK (shadow_decision IN ({_DECISIONS})),
        decision                   text NOT NULL CHECK (decision IN ({_DECISIONS})),
        execution_status           text NOT NULL CHECK (execution_status IN ({_EXECUTION})),
        ticket_id                  text,
        secret_attempted           boolean NOT NULL DEFAULT false,
        secret_delivered           boolean NOT NULL DEFAULT false,
        diverted                   boolean NOT NULL DEFAULT false,
        trace_back_id              text,
        atlas_techniques           text[] NOT NULL DEFAULT '{{}}',
        latency_ms                 jsonb NOT NULL DEFAULT '{{}}',
        forensic_status            text CHECK (
                                       forensic_status IN ('pending', 'done', 'failed', 'skipped')
                                   ),
        client_ip_hash             text,
        priority_alert             boolean NOT NULL DEFAULT false,
        UNIQUE (event_id, time),
        CHECK (mode = 'off' OR shadow_decision IS NULL)
    )
    """,
    """
    CREATE TABLE trace_back (
        trace_id            text PRIMARY KEY,
        time                timestamptz NOT NULL DEFAULT now(),
        user_id             uuid NOT NULL REFERENCES users (id),
        fw_session_id       text NOT NULL,
        event_id            text,
        ip_hash             text,
        subnet              text,
        asn                 int,
        asn_org             text,
        country             text,
        user_agent          text,
        client_fingerprint  text,
        methods_used        text[] NOT NULL DEFAULT '{}',
        tools_called        text[] NOT NULL DEFAULT '{}'
    )
    """,
)

_AFTER = (
    "SELECT create_hypertable('fw_events', 'time', chunk_time_interval => INTERVAL '1 day')",
    "CREATE INDEX rules_set_version_idx ON rules (set_version)",
    "CREATE UNIQUE INDEX fw_claims_one_active ON fw_claims (fw_session_id)"
    " WHERE status IN ('in_flight', 'held')",
    "CREATE UNIQUE INDEX fw_tickets_one_pending ON fw_tickets (fw_session_id)"
    " WHERE status = 'pending'",
    "CREATE INDEX fw_tickets_pending_expiry_idx ON fw_tickets (expires_at)"
    " WHERE status = 'pending'",
    "CREATE INDEX fw_events_session_idx ON fw_events (fw_session_id, time DESC)",
    "CREATE INDEX fw_events_user_idx ON fw_events (user_id, time DESC)",
    "CREATE INDEX fw_events_forensic_pending_idx ON fw_events (time)"
    " WHERE forensic_status = 'pending'",
    "CREATE INDEX trace_back_time_idx ON trace_back (time)",
    "CREATE TRIGGER rules_append_only BEFORE UPDATE OR DELETE ON rules"
    " FOR EACH ROW EXECUTE FUNCTION fw_forbid_change('append-only')",
    "CREATE TRIGGER fw_manifests_immutable BEFORE UPDATE OR DELETE ON fw_manifests"
    " FOR EACH ROW EXECUTE FUNCTION fw_forbid_change('immutable')",
    "CREATE TRIGGER fw_events_forensic_notify AFTER INSERT ON fw_events"
    " FOR EACH ROW EXECUTE FUNCTION fw_events_notify()",
)

_DROP_ORDER = (
    "trace_back",
    "fw_events",
    "fw_tickets",
    "fw_tool_calls",
    "fw_mock_state",
    "fw_conversation",
    "fw_claims",
    "fw_manifests",
    "fw_sessions",
    "rules",
    "rule_sets",
)


def upgrade() -> None:
    for statement in (*_FUNCTIONS, *_TABLES, *_AFTER):
        op.execute(statement)


def downgrade() -> None:
    for table in _DROP_ORDER:
        op.execute(f"DROP TABLE IF EXISTS {table}")
    op.execute("DROP FUNCTION IF EXISTS fw_events_notify()")
    op.execute("DROP FUNCTION IF EXISTS fw_forbid_change()")
