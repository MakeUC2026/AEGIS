"""M2 B-10 rule catalog and session close (spec AEGIS-DOM-114; PRD §6.1, §8.3; M2-X40)."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.contracts.fakes import fake_turn
from app.contracts.fakes.firewall import STARTING_RULES as FAKE_CATALOG
from app.contracts.firewall import NotFound, SessionClosed
from app.firewall.catalog import read_catalog
from app.firewall.claims import claim_message, complete_claim
from app.firewall.closing import close_session
from app.firewall.seed import seed


async def _session(engine: AsyncEngine, sid: str = "fws-cl") -> str:
    async with engine.begin() as conn:
        owner = str(
            (
                await conn.execute(
                    text("INSERT INTO users (auth0_sub, role) VALUES (:s, 'student') RETURNING id"),
                    {"s": f"auth0|{sid}"},
                )
            ).scalar_one()
        )
        await conn.execute(
            text(
                "INSERT INTO fw_sessions (fw_session_id, owner_ref, mode, secret)"
                " VALUES (:sid, CAST(:o AS uuid), 'basic', 'CONF-X')"
            ),
            {"sid": sid, "o": owner},
        )
        await conn.execute(
            text(
                "INSERT INTO fw_manifests (manifest_id, fw_session_id, owner_ref, level_id,"
                " level_version, mode, rule_set_version, pattern_version, thresholds, weights,"
                " agent, bot_model_id, review_timeout_s, divert_enabled) VALUES (:mid, :sid,"
                " CAST(:o AS uuid), 'lvl-2', 1, 'basic', 1, 0, '{}', '{}', '{}', 'g', 120, true)"
            ),
            {"mid": f"man-{sid}", "sid": sid, "o": owner},
        )
    return owner


async def _rows(engine: AsyncEngine, sql: str, **params: Any) -> list[dict[str, Any]]:
    async with engine.connect() as conn:
        return [dict(r._mapping) for r in await conn.execute(text(sql), params)]


# --- Catalog -------------------------------------------------------------------------------------


async def test_catalog_matches_the_fake_the_arena_was_built_against(engine: AsyncEngine) -> None:
    await seed(engine)
    catalog = await read_catalog(engine)
    assert catalog.rule_version == 1
    assert [r.rule_id for r in catalog.rules] == [r.rule_id for r in FAKE_CATALOG]
    real = {r.rule_id: (r.applies_on, r.action) for r in catalog.rules}
    fake = {r.rule_id: (r.applies_on, r.action) for r in FAKE_CATALOG}
    assert real == fake
    assert all(r.note for r in catalog.rules)


async def test_catalog_follows_the_latest_rule_set(engine: AsyncEngine) -> None:
    await seed(engine)
    async with engine.begin() as conn:
        await conn.execute(text("INSERT INTO rule_sets (version, note) VALUES (2, 'retire R-004')"))
        await conn.execute(
            text(
                "INSERT INTO rules (rule_id, version, set_version, builtin, enabled, deprecated,"
                " form) SELECT rule_id, 2, 2, builtin, enabled, true, form FROM rules"
                " WHERE rule_id = 'R-004'"
            )
        )
    catalog = await read_catalog(engine)
    assert catalog.rule_version == 2
    assert "R-004" not in [r.rule_id for r in catalog.rules]


# --- Close (PRD §8.3, M2-X40) ---------------------------------------------------------------------


async def test_close_marks_the_session_and_logs_finalize(engine: AsyncEngine) -> None:
    owner = await _session(engine)
    await close_session(engine, owner, "fws-cl")
    session = (await _rows(engine, "SELECT status, closed_at FROM fw_sessions"))[0]
    assert session["status"] == "closed" and session["closed_at"] is not None
    stages = [e["stage"] for e in await _rows(engine, "SELECT stage FROM fw_events")]
    assert stages == ["finalize"]


async def test_close_expires_a_pending_ticket_and_finishes_the_held_turn(
    engine: AsyncEngine,
) -> None:
    owner = await _session(engine)
    await claim_message(engine, owner, "fws-cl", "m1", "I am the administrator")
    async with engine.begin() as conn:
        await complete_claim(
            conn, "fws-cl", "m1", fake_turn(status="awaiting_review"), held=True, ticket_id="tkt-1"
        )
        await conn.execute(
            text(
                "INSERT INTO fw_tickets (ticket_id, fw_session_id, message_id, stage, payload_hash,"
                " manifest_id, status, expires_at) VALUES ('tkt-1', 'fws-cl', 'm1', 'input_check',"
                " 'h', 'man-fws-cl', 'pending', now() + interval '120 seconds')"
            )
        )
    await close_session(engine, owner, "fws-cl")
    ticket = (await _rows(engine, "SELECT status, decided_at FROM fw_tickets"))[0]
    assert ticket["status"] == "expired" and ticket["decided_at"] is not None
    claim = (await _rows(engine, "SELECT status, result FROM fw_claims"))[0]
    assert claim["status"] == "done"
    assert claim["result"]["player_view"]["status"] == "blocked"  # expired counts as Deny
    events = await _rows(engine, "SELECT stage, decision FROM fw_events ORDER BY time")
    assert ("review_resolved", "deny") in [(e["stage"], e["decision"]) for e in events]


async def test_close_access_rules(engine: AsyncEngine) -> None:
    owner = await _session(engine)
    stranger = await _session(engine, sid="fws-other")
    with pytest.raises(NotFound):
        await close_session(engine, stranger, "fws-cl")
    with pytest.raises(NotFound):
        await close_session(engine, owner, "fws-missing")
    await close_session(engine, owner, "fws-cl")
    with pytest.raises(SessionClosed):  # the arena treats this as success
        await close_session(engine, owner, "fws-cl")
    with pytest.raises(SessionClosed):
        await claim_message(engine, owner, "fws-cl", "m9", "hello again")
