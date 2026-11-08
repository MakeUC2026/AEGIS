"""Firewall continuous aggregates and the echo-exclusion fact (M2 C-11; PRD §10, §14.4).

- `fw_events.echo_excluded`: the bot's output held the secret but the student had typed 8 or
  more of its characters, so it did not count as delivered (E-53). The teacher's session
  detail shows it; it cannot be derived from the other columns.
- `fw_rule_fires_1m` and `fw_decisions_1m`: one-minute continuous aggregates over `fw_events`
  for the insight counts. They are real-time (`materialized_only = false`), so a count is
  never a minute stale, and each has a refresh policy every minute that also back-fills from
  the start of time. `tool_executed` and `finalize` events are left out: they repeat a check's
  rule IDs and are not decisions. The rule aggregate groups by the array of rule IDs; the read
  API unnests it, since a continuous aggregate cannot hold a set-returning function.

The views are created outside a transaction (`autocommit_block`), as Timescale requires.

Revision ID: 0003b_fw_cagg
Revises: 0003_firewall_core
"""

from __future__ import annotations

from alembic import op

revision = "0003b_fw_cagg"
down_revision = "0003_firewall_core"
branch_labels = None  # stays on the fw_core branch
depends_on = None

_COLUMN = "ALTER TABLE fw_events ADD COLUMN echo_excluded boolean NOT NULL DEFAULT false"

_VIEWS = (
    """
    CREATE MATERIALIZED VIEW fw_rule_fires_1m
    WITH (timescaledb.continuous, timescaledb.materialized_only = false) AS
    SELECT time_bucket(INTERVAL '1 minute', time) AS bucket, level_id, mode, rule_ids_fired,
           count(*) AS events
    FROM fw_events
    WHERE stage NOT IN ('tool_executed', 'finalize') AND cardinality(rule_ids_fired) > 0
    GROUP BY bucket, level_id, mode, rule_ids_fired
    WITH NO DATA
    """,
    """
    CREATE MATERIALIZED VIEW fw_decisions_1m
    WITH (timescaledb.continuous, timescaledb.materialized_only = false) AS
    SELECT time_bucket(INTERVAL '1 minute', time) AS bucket, level_id, mode, decision,
           count(*) AS events
    FROM fw_events
    WHERE stage NOT IN ('tool_executed', 'finalize')
    GROUP BY bucket, level_id, mode, decision
    WITH NO DATA
    """,
)

# The first run is ten minutes after creation: the views are real-time, so nothing is missing
# until then, and a job never competes with the app (or a test run) starting up.
_POLICIES = tuple(
    f"SELECT add_continuous_aggregate_policy('{view}', start_offset => NULL,"
    " end_offset => INTERVAL '1 minute', schedule_interval => INTERVAL '1 minute',"
    " initial_start => now() + INTERVAL '10 minutes')"
    for view in ("fw_rule_fires_1m", "fw_decisions_1m")
)

_DOWNGRADE_VIEWS = (
    "DROP MATERIALIZED VIEW IF EXISTS fw_decisions_1m",
    "DROP MATERIALIZED VIEW IF EXISTS fw_rule_fires_1m",
)


def upgrade() -> None:
    op.execute(_COLUMN)
    with op.get_context().autocommit_block():
        for statement in (*_VIEWS, *_POLICIES):
            op.execute(statement)


def downgrade() -> None:
    with op.get_context().autocommit_block():
        for statement in _DOWNGRADE_VIEWS:
            op.execute(statement)
    op.execute("ALTER TABLE fw_events DROP COLUMN IF EXISTS echo_excluded")
