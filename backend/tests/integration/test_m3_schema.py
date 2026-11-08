"""B-01: the `0004_firewall_intel` migration (plan §0.4, PRD §7.5, §10.2, §10.3, §14.7)."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.conftest import run_alembic
from tests.integration.m3_helpers import M3_TABLES, add_pattern, make_user


async def _tables(engine: AsyncEngine) -> set[str]:
    async with engine.connect() as conn:
        rows = await conn.execute(
            text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
        )
        return {r[0] for r in rows}


async def test_m3_tables_exist(engine: AsyncEngine) -> None:
    assert set(M3_TABLES) <= await _tables(engine)


async def test_behavior_events_is_hypertable_with_hnsw_cosine_index(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        hyper = await conn.execute(
            text(
                "SELECT hypertable_name FROM timescaledb_information.hypertables"
                " WHERE hypertable_name = 'risky_behavior_events'"
            )
        )
        assert hyper.scalar_one_or_none() == "risky_behavior_events"
        idx = await conn.execute(
            text(
                "SELECT indexdef FROM pg_indexes WHERE tablename = 'risky_behavior_events'"
                " AND indexdef ILIKE '%hnsw%'"
            )
        )
        defs = [r[0] for r in idx]
    assert len(defs) == 1
    assert "vector_cosine_ops" in defs[0]


async def test_no_foreign_keys_to_other_parts(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        rows = await conn.execute(
            text(
                "SELECT conrelid::regclass::text, confrelid::regclass::text FROM pg_constraint"
                " WHERE contype = 'f' AND conrelid::regclass::text = ANY(:t)"
            ),
            {"t": list(M3_TABLES)},
        )
        targets = {r[1] for r in rows}
    assert targets <= {"users", *M3_TABLES}  # plan §0.2 rule 5: only users.id across parts


def test_heads_include_fw_intel_and_downgrade_round_trips() -> None:
    heads = run_alembic("heads", "--verbose")
    assert heads.returncode == 0, heads.stderr
    assert "0004_firewall_intel" in heads.stdout
    assert "fw_intel" in heads.stdout
    labels = [ln for ln in heads.stdout.splitlines() if ln.startswith("Branch names:")]
    assert any("arena" in ln for ln in labels)  # alongside M1's arena head, whatever its rev
    down = run_alembic("downgrade", "fw_intel@-1")
    assert down.returncode == 0, down.stderr
    up = run_alembic("upgrade", "heads")
    assert up.returncode == 0, up.stderr


async def test_downgrade_drops_only_m3_tables(engine: AsyncEngine) -> None:
    down = run_alembic("downgrade", "fw_intel@-1")
    assert down.returncode == 0, down.stderr
    try:
        tables = await _tables(engine)
        assert not set(M3_TABLES) & tables
        assert {"users", "audit_log", "levels"} <= tables
    finally:
        up = run_alembic("upgrade", "heads")
        assert up.returncode == 0, up.stderr


@pytest.mark.parametrize(
    ("status", "approved", "retired"),
    [
        ("live", None, None),  # unknown status
        ("approved", None, None),  # approved without a version
        ("candidate", 3, None),  # candidate with a version
        ("approved", 3, 3),  # retired in the version it was approved in
        ("approved", 0, None),  # versions start at 1
    ],
)
async def test_pattern_status_and_version_checks(
    engine: AsyncEngine, status: str, approved: int | None, retired: int | None
) -> None:
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO risky_tool_patterns (tool, conditions, status,"
                    " approved_in_version, retired_in_version)"
                    # Valid conditions, so only the status/version check under test can fail.
                    ' VALUES (\'send_email\', \'[{"arg": "to", "op": "contains",'
                    ' "value": "@"}]\', :s, :a, :r)'
                ),
                {"s": status, "a": approved, "r": retired},
            )


async def test_approved_pattern_needs_conditions(engine: AsyncEngine) -> None:
    with pytest.raises(IntegrityError):  # an approved empty pattern would silently never match
        async with engine.begin() as conn:
            await add_pattern(conn, conditions=[], approved=7)


async def test_valid_conditions_insert_succeeds(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:  # control for the parametrized CHECK test above
        await add_pattern(conn, approved=1, retired=2)


async def test_approve_and_retire_cannot_share_a_version(engine: AsyncEngine) -> None:
    """One ledger issues each pattern version once, approvals and retirements alike (I-7)."""
    async with engine.begin() as conn:
        pid = await add_pattern(conn, approved=1)
        await conn.execute(
            text(
                "INSERT INTO risky_pattern_versions (version, pattern_id, change)"
                " VALUES (2, CAST(:p AS uuid), 'approve')"
            ),
            {"p": pid},
        )
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO risky_pattern_versions (version, pattern_id, change)"
                    " VALUES (2, CAST(:p AS uuid), 'retire')"
                ),
                {"p": pid},
            )


async def test_one_approval_version_cannot_be_issued_twice(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await add_pattern(conn, approved=4)
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await add_pattern(conn, tool="query_db", approved=4)


async def test_behavior_action_and_stage_checked(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        uid = await make_user(conn, "auth0|schema")
    insert = text(
        "INSERT INTO risky_behavior_events (time, user_id, fw_session_id, event_id, stage,"
        " action, sentinel_score, rule_ids, input_text_hash, shadow)"
        " VALUES (now(), CAST(:u AS uuid), 'f', 'e', :stage, :action, 50, '{}', 'h', false)"
    )
    for stage, action in (("input_check", "allow"), ("nowhere", "deny")):
        with pytest.raises(IntegrityError):
            async with engine.begin() as conn:
                await conn.execute(insert, {"u": uid, "stage": stage, "action": action})


async def test_draft_status_kind_and_one_per_event(engine: AsyncEngine) -> None:
    insert = text(
        "INSERT INTO drafts (source_event_id, kind, body, status) VALUES (:e, :k, '{}', :s)"
    )
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(insert, {"e": "evt-1", "k": "rule", "s": "applied"})
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(insert, {"e": "evt-1", "k": "prompt", "s": "pending"})
    async with engine.begin() as conn:
        await conn.execute(insert, {"e": "evt-1", "k": "rule", "s": "pending"})
    with pytest.raises(IntegrityError):  # at most one draft per event (PRD §10.3)
        async with engine.begin() as conn:
            await conn.execute(insert, {"e": "evt-1", "k": "pattern", "s": "pending"})


async def test_forensic_family_checked(engine: AsyncEngine) -> None:
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO forensic_reports (event_id, attack_family, summary)"
                    " VALUES ('evt-2', 'benign', 's')"
                )
            )
