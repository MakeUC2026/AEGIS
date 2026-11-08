"""Migrations: one Alembic history with part branch labels, always `upgrade heads`
(M1 §0.4, M1-X26 local half). Constraints that protect PRD invariants live in the schema too.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.conftest import M1_TABLES, run_alembic


async def test_extensions_installed(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        rows = await conn.execute(text("SELECT extname FROM pg_extension"))
        names = {r[0] for r in rows}
    assert {"timescaledb", "vector", "pgcrypto"} <= names


async def test_all_m1_tables_exist(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        rows = await conn.execute(
            text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
        )
        tables = {r[0] for r in rows}
    assert set(M1_TABLES) <= tables


def test_heads_have_branch_labels_and_upgrade_is_idempotent(engine: AsyncEngine) -> None:
    heads = run_alembic("heads", "--verbose")
    assert heads.returncode == 0, heads.stderr
    assert "0002_arena" in heads.stdout
    assert "arena" in heads.stdout  # branch label
    again = run_alembic("upgrade", "heads")
    assert again.returncode == 0, again.stderr


async def _user(conn, sub: str = "auth0|u1") -> str:  # type: ignore[no-untyped-def]
    row = await conn.execute(
        text("INSERT INTO users (auth0_sub, role) VALUES (:s, 'student') RETURNING id"),
        {"s": sub},
    )
    return str(row.scalar_one())


async def test_users_auth0_sub_unique(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await _user(conn)
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await _user(conn)


async def test_level_mode_and_session_status_are_checked(engine: AsyncEngine) -> None:
    insert_level = text(
        "INSERT INTO levels (level_id, level_version, number, name, mode, secret_tier,"
        " rule_version, weights, thresholds, review_timeout_s, divert_enabled)"
        " VALUES ('lvl-x', 1, 9, 'x', :mode, 't', 0, '{}', '{}', 120, false)"
    )
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(insert_level, {"mode": "allow"})  # D-07: no "Allow" mode
    async with engine.begin() as conn:
        await conn.execute(insert_level, {"mode": "off"})
        uid = await _user(conn)
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO arena_sessions (user_id, level_id, level_version, mode,"
                    " fw_session_id, manifest_id, secret_version, status)"
                    " VALUES (:u, 'lvl-x', 1, 'off', 'fws-1', 'man-1', 1, 'paused')"
                ),
                {"u": uid},
            )


async def test_usage_message_id_counted_once_per_user_and_session(engine: AsyncEngine) -> None:
    insert = text(
        "INSERT INTO usage (kind, user_id, session_id, message_id)"
        " VALUES ('message', :u, CAST(:s AS uuid), 'm1')"
    )
    s1, s2 = "00000000-0000-0000-0000-0000000000a1", "00000000-0000-0000-0000-0000000000a2"
    async with engine.begin() as conn:
        uid = await _user(conn)
        await conn.execute(insert, {"u": uid, "s": s1})
        await conn.execute(insert, {"u": uid, "s": s2})  # same id, other session: its own slot
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(insert, {"u": uid, "s": s1})


async def test_turn_status_values_are_checked(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        row = await conn.execute(
            text(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint"
                " WHERE conname = 'arena_turns_status_check'"
            )
        )
        definition = row.scalar_one()
    for status in ("sent", "replied", "blocked", "awaiting_review", "human_denied", "not_sent"):
        assert status in definition
    assert "redacted" not in definition  # D-09
