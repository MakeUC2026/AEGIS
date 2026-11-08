"""M2 B-01 migration 0003_firewall_core (spec AEGIS-DOM-106; PRD §10.1, §14.7, §15.1).

Every M2 table chains to `users` by foreign key, so M1's per-test TRUNCATE ... CASCADE on
`users` also cleans the M2 tables (no change to M1's conftest).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.conftest import run_alembic

M2_TABLES = (
    "rule_sets",
    "rules",
    "fw_sessions",
    "fw_manifests",
    "fw_claims",
    "fw_conversation",
    "fw_mock_state",
    "fw_tool_calls",
    "fw_tickets",
    "fw_events",
    "trace_back",
)


async def _exec(engine: AsyncEngine, sql: str, **params: Any) -> Any:
    async with engine.begin() as conn:
        return await conn.execute(text(sql), params)


async def _user(engine: AsyncEngine, sub: str = "auth0|fw") -> str:
    row = await _exec(
        engine,
        "INSERT INTO users (auth0_sub, role) VALUES (:s, 'student') RETURNING id",
        s=sub,
    )
    return str(row.scalar_one())


async def _session(engine: AsyncEngine, sid: str = "fws-1") -> str:
    owner = await _user(engine, f"auth0|{sid}")
    await _exec(
        engine,
        "INSERT INTO fw_sessions (fw_session_id, owner_ref, mode, secret) "
        "VALUES (:sid, CAST(:o AS uuid), 'basic', 'CONF-X')",
        sid=sid,
        o=owner,
    )
    return owner


async def _event(engine: AsyncEngine, **over: Any) -> None:
    owner = over.pop("user_id")
    row: dict[str, Any] = {
        "event_id": "evt-1",
        "fw_session_id": "fws-1",
        "message_id": "m1",
        "manifest_id": "man-1",
        "level_id": "lvl-2",
        "mode": "basic",
        "stage": "input_check",
        "source_trust": "player",
        "sentinel_score": 10,
        "decision": "allow",
        "shadow_decision": None,
        "execution_status": "not_executed",
        "forensic_status": None,
        **over,
    }
    await _exec(
        engine,
        "INSERT INTO fw_events (event_id, time, fw_session_id, user_id, message_id, manifest_id,"
        " level_id, mode, stage, source_trust, sentinel_score, score_breakdown, thresholds_used,"
        " decision, shadow_decision, execution_status, forensic_status) VALUES (:event_id, now(),"
        " :fw_session_id, CAST(:user_id AS uuid), :message_id, :manifest_id, :level_id, :mode,"
        " :stage, :source_trust, :sentinel_score, CAST(:breakdown AS jsonb),"
        " CAST(:thresholds AS jsonb), :decision, :shadow_decision, :execution_status,"
        " :forensic_status)",
        user_id=owner,
        breakdown=json.dumps({"keyword": 0, "judge": None}),
        thresholds=json.dumps({"review": 40, "deny": 70, "divert": 95, "alert": 99}),
        **row,
    )


# --- Layout ------------------------------------------------------------------------------------


def test_fw_core_is_its_own_head_with_its_label(engine: AsyncEngine) -> None:
    heads = run_alembic("heads", "--verbose")
    assert heads.returncode == 0, heads.stderr
    assert "0003_firewall_core" in heads.stdout
    assert "fw_core" in heads.stdout


async def test_every_m2_table_exists(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        rows = await conn.execute(
            text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
        )
        tables = {r[0] for r in rows}
    assert set(M2_TABLES) <= tables


async def test_fw_events_is_a_hypertable(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        found = await conn.execute(
            text(
                "SELECT count(*) FROM timescaledb_information.hypertables"
                " WHERE hypertable_name = 'fw_events'"
            )
        )
    assert found.scalar_one() == 1


# --- Append-only and immutable (PRD §9.1, §15.1 reproducibility) --------------------------------


async def test_rules_are_never_updated_or_deleted(engine: AsyncEngine) -> None:
    await _exec(engine, "INSERT INTO rule_sets (version) VALUES (1)")
    await _exec(
        engine,
        "INSERT INTO rules (rule_id, version, set_version, builtin, enabled, deprecated, form)"
        " VALUES ('R-001', 1, 1, false, true, false, '{}'::jsonb)",
    )
    with pytest.raises(DBAPIError, match="append-only"):
        await _exec(engine, "UPDATE rules SET enabled = false WHERE rule_id = 'R-001'")
    with pytest.raises(DBAPIError, match="append-only"):
        await _exec(engine, "DELETE FROM rules WHERE rule_id = 'R-001'")


async def test_manifests_are_immutable(engine: AsyncEngine) -> None:
    owner = await _session(engine)
    await _exec(
        engine,
        "INSERT INTO fw_manifests (manifest_id, fw_session_id, owner_ref, level_id,"
        " level_version, mode, rule_set_version, pattern_version, thresholds, weights, agent,"
        " bot_model_id, review_timeout_s, divert_enabled) VALUES ('man-1', 'fws-1',"
        " CAST(:o AS uuid), 'lvl-2', 1, 'basic', 1, 0, '{}', '{}', '{}', 'gemini-x', 120, true)",
        o=owner,
    )
    with pytest.raises(DBAPIError, match="immutable"):
        await _exec(engine, "UPDATE fw_manifests SET mode = 'off'")


# --- Concurrency invariants (PRD §15.1) ---------------------------------------------------------


async def test_one_in_flight_or_held_claim_per_session(engine: AsyncEngine) -> None:
    await _session(engine)
    insert = (
        "INSERT INTO fw_claims (fw_session_id, message_id, text_hash, status)"
        " VALUES ('fws-1', :m, 'h', :s)"
    )
    await _exec(engine, insert, m="m1", s="in_flight")
    with pytest.raises(IntegrityError):
        await _exec(engine, insert, m="m2", s="held")
    await _exec(engine, "UPDATE fw_claims SET status = 'done' WHERE message_id = 'm1'")
    await _exec(engine, insert, m="m2", s="in_flight")  # free again


async def test_a_call_id_is_recorded_once_per_session(engine: AsyncEngine) -> None:
    await _session(engine)
    insert = (
        "INSERT INTO fw_tool_calls (fw_session_id, call_id, tool, args_hash, state)"
        " VALUES ('fws-1', 'c1', 'send_email', 'sha256:x', 'executed')"
    )
    await _exec(engine, insert)
    with pytest.raises(IntegrityError):
        await _exec(engine, insert)


async def test_one_pending_ticket_per_session(engine: AsyncEngine) -> None:
    await _session(engine)
    insert = (
        "INSERT INTO fw_tickets (ticket_id, fw_session_id, message_id, stage, payload_hash,"
        " manifest_id, status, expires_at) VALUES (:t, 'fws-1', 'm1', 'tool_call_check', 'h',"
        " 'man-1', 'pending', now() + interval '120 seconds')"
    )
    await _exec(engine, insert, t="tkt-1")
    with pytest.raises(IntegrityError):
        await _exec(engine, insert, t="tkt-2")


# --- Event rows (PRD §10.1; M2-X46) ---------------------------------------------------------------


@pytest.mark.parametrize(
    "over",
    [
        {"decision": "maybe"},
        {"stage": "lunch"},
        {"execution_status": "teleported"},
        {"sentinel_score": 101},
        {"mode": "basic", "shadow_decision": "deny"},  # shadow only in Off
        {"source_trust": "rumour"},
    ],
)
async def test_event_values_are_checked(engine: AsyncEngine, over: dict[str, Any]) -> None:
    owner = await _session(engine)
    with pytest.raises(IntegrityError):
        await _event(engine, user_id=owner, **over)


async def test_off_events_carry_a_shadow_decision(engine: AsyncEngine) -> None:
    owner = await _session(engine)
    await _event(engine, user_id=owner, mode="off", shadow_decision="divert")


async def test_pending_forensic_rows_notify_in_the_same_transaction(engine: AsyncEngine) -> None:
    owner = await _session(engine)
    received: list[str] = []

    def on_notify(*args: Any) -> None:
        received.append(args[-1])

    async with engine.connect() as conn:
        raw = (await conn.get_raw_connection()).driver_connection
        await raw.add_listener("fw_events_forensic", on_notify)
        try:
            await _event(engine, user_id=owner, event_id="evt-quiet", forensic_status=None)
            await _event(
                engine,
                user_id=owner,
                event_id="evt-loud",
                decision="deny",
                forensic_status="pending",
            )
            for _ in range(20):
                if received:
                    break
                await asyncio.sleep(0.05)
        finally:
            await raw.remove_listener("fw_events_forensic", on_notify)
    assert received == ["evt-loud"]


@pytest.mark.parametrize(("rule_id", "ok"), [("R-001", True), ("B-01", True), ("B-001", False),
                                             ("R-01", False), ("X-001", False)])  # fmt: skip
async def test_rule_id_format_matches_the_prd(engine: AsyncEngine, rule_id: str, ok: bool) -> None:
    await _exec(engine, "INSERT INTO rule_sets (version) VALUES (1)")
    insert = (
        "INSERT INTO rules (rule_id, version, set_version, builtin, enabled, deprecated, form)"
        " VALUES (:r, 1, 1, true, true, false, NULL)"
    )
    if ok:
        await _exec(engine, insert, r=rule_id)
    else:
        with pytest.raises(IntegrityError):
            await _exec(engine, insert, r=rule_id)
