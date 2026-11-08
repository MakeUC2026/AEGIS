"""M2 B-07 message claims and idempotency (spec AEGIS-DOM-111; PRD §15.1; E-01 to E-04)."""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.contracts.fakes import fake_turn
from app.contracts.firewall import MessageConflict, NotFound, SessionBusy, SessionClosed
from app.firewall.claims import claim_message, complete_claim, release_claim


async def _session(engine: AsyncEngine, sid: str = "fws-c1", status: str = "active") -> str:
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
                "INSERT INTO fw_sessions (fw_session_id, owner_ref, mode, secret, status,"
                " closed_at) VALUES (:sid, CAST(:o AS uuid), 'basic', 'CONF-X', :st,"
                " CASE WHEN :st = 'closed' THEN now() END)"
            ),
            {"sid": sid, "o": owner, "st": status},
        )
    return owner


async def _complete(engine: AsyncEngine, sid: str, mid: str, status: str = "done") -> None:
    result = fake_turn(status="replied" if status == "done" else "awaiting_review")
    async with engine.begin() as conn:
        await complete_claim(conn, sid, mid, result, held=status == "held")


async def test_a_new_message_is_claimed(engine: AsyncEngine) -> None:
    owner = await _session(engine)
    claim = await claim_message(engine, owner, "fws-c1", "m1", "hello")
    assert (claim.is_new, claim.stored) == (True, None)


async def test_e01_same_id_same_text_returns_the_stored_result(engine: AsyncEngine) -> None:
    owner = await _session(engine)
    await claim_message(engine, owner, "fws-c1", "m1", "hello")
    await _complete(engine, "fws-c1", "m1")
    again = await claim_message(engine, owner, "fws-c1", "m1", "hello")
    assert again.is_new is False
    assert again.stored is not None and again.stored.player_view.status == "replied"


async def test_e03_same_id_different_text_conflicts(engine: AsyncEngine) -> None:
    owner = await _session(engine)
    await claim_message(engine, owner, "fws-c1", "m1", "hello")
    with pytest.raises(MessageConflict):
        await claim_message(engine, owner, "fws-c1", "m1", "something else")


async def test_e04_a_new_message_while_one_is_in_flight_or_held_is_busy(
    engine: AsyncEngine,
) -> None:
    owner = await _session(engine)
    await claim_message(engine, owner, "fws-c1", "m1", "hello")
    with pytest.raises(SessionBusy):
        await claim_message(engine, owner, "fws-c1", "m2", "next")
    await _complete(engine, "fws-c1", "m1", status="held")
    with pytest.raises(SessionBusy):  # held through review
        await claim_message(engine, owner, "fws-c1", "m2", "next")
    held = await claim_message(engine, owner, "fws-c1", "m1", "hello")  # the pending result
    assert held.stored is not None and held.stored.player_view.status == "awaiting_review"
    await _complete(engine, "fws-c1", "m1")
    assert (await claim_message(engine, owner, "fws-c1", "m2", "next")).is_new


async def test_e02_concurrent_same_id_one_runs_the_other_gets_its_result(
    engine: AsyncEngine,
) -> None:
    owner = await _session(engine)
    first = await claim_message(engine, owner, "fws-c1", "m1", "hello")
    assert first.is_new

    async def finish_later() -> None:
        await asyncio.sleep(0.3)
        await _complete(engine, "fws-c1", "m1")

    waiter = claim_message(engine, owner, "fws-c1", "m1", "hello", wait_s=3.0)
    second, _ = await asyncio.gather(waiter, finish_later())
    assert second.is_new is False and second.stored is not None


async def test_e02_waiting_too_long_is_busy(engine: AsyncEngine) -> None:
    owner = await _session(engine)
    await claim_message(engine, owner, "fws-c1", "m1", "hello")
    with pytest.raises(SessionBusy):
        await claim_message(engine, owner, "fws-c1", "m1", "hello", wait_s=0.2)


async def test_two_new_messages_racing_only_one_wins(engine: AsyncEngine) -> None:
    owner = await _session(engine)
    outcomes = await asyncio.gather(
        claim_message(engine, owner, "fws-c1", "m1", "a"),
        claim_message(engine, owner, "fws-c1", "m2", "b"),
        return_exceptions=True,
    )
    assert sum(1 for o in outcomes if not isinstance(o, BaseException) and o.is_new) == 1
    assert sum(1 for o in outcomes if isinstance(o, SessionBusy)) == 1


async def test_release_lets_the_same_id_retry(engine: AsyncEngine) -> None:
    owner = await _session(engine)
    await claim_message(engine, owner, "fws-c1", "m1", "hello")
    await release_claim(engine, "fws-c1", "m1")  # BotUnavailable path
    assert (await claim_message(engine, owner, "fws-c1", "m1", "hello")).is_new


async def test_release_never_drops_a_finished_turn(engine: AsyncEngine) -> None:
    owner = await _session(engine)
    await claim_message(engine, owner, "fws-c1", "m1", "hello")
    await _complete(engine, "fws-c1", "m1")
    await release_claim(engine, "fws-c1", "m1")
    assert (await claim_message(engine, owner, "fws-c1", "m1", "hello")).is_new is False


async def test_access_checks(engine: AsyncEngine) -> None:
    owner = await _session(engine)
    stranger = await _session(engine, sid="fws-other")
    with pytest.raises(NotFound):
        await claim_message(engine, stranger, "fws-c1", "m1", "hello")  # someone else's session
    with pytest.raises(NotFound):
        await claim_message(engine, owner, "fws-missing", "m1", "hello")
    closed_owner = await _session(engine, sid="fws-closed", status="closed")
    with pytest.raises(SessionClosed):
        await claim_message(engine, closed_owner, "fws-closed", "m1", "hello")
