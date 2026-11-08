"""M2 C-04 `check_ticket` (PRD §8.3 step 7; C2; spec AEGIS-DOM-119).

The arena polls; the AFF never pushes. `check_ticket` returns the ticket's status, its
deadline and, once the turn has finished, the stored `TurnResult`. Someone else's ticket, or
an unknown one, is `NotFound`. A due pending ticket expires on the spot (C-03's lazy check).
"""

from __future__ import annotations

from datetime import datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from app.contracts.common import ClientMeta
from app.contracts.fakes import InMemoryRiskyHistory, StubJudge
from app.contracts.firewall import NotFound
from app.firewall.closing import close_session
from app.firewall.interface import RealFirewall
from app.firewall.pipeline import run_message
from app.firewall.tickets import check_ticket, decide_ticket
from app.llm.base import ChatResult
from app.llm.scripted import ScriptedLLM
from tests.integration.test_fw_decide_ticket import _admin
from tests.integration.test_fw_review_park import AUTHORITY, REPLY_REVIEW, _rows, _session
from tests.integration.test_fw_ticket_expiry import _due, _held_tool

CLIENT = ClientMeta()


async def _held_input(engine: AsyncEngine, **kw: object) -> tuple[str, str, str]:
    sid, owner = await _session(engine, **kw)  # type: ignore[arg-type]
    held = await run_message(engine, ScriptedLLM(), owner, sid, "m1", AUTHORITY, CLIENT)
    return sid, owner, held.player_view.ticket_id or ""


async def test_a_pending_ticket_has_no_result_yet(engine: AsyncEngine) -> None:
    _, owner, tid = await _held_input(engine)
    result = await check_ticket(engine, owner, tid)
    assert (result.ticket_id, result.status, result.turn_result) == (tid, "pending", None)
    expires = datetime.fromisoformat(result.expires_at)
    offset = expires.utcoffset()
    assert offset is not None and offset.total_seconds() == 0
    stored = await _rows(engine, "SELECT expires_at FROM fw_tickets WHERE ticket_id = :t", t=tid)
    assert expires == stored[0]["expires_at"]


async def test_only_the_owner_can_check_a_ticket(engine: AsyncEngine) -> None:
    _, _, tid = await _held_input(engine)
    with pytest.raises(NotFound):
        await check_ticket(engine, "00000000-0000-0000-0000-000000000000", tid)
    with pytest.raises(NotFound):
        await check_ticket(engine, "not-a-uuid", tid)


async def test_an_unknown_ticket_is_not_found(engine: AsyncEngine) -> None:
    _, owner, _ = await _held_input(engine)
    with pytest.raises(NotFound):
        await check_ticket(engine, owner, "tkt-missing")


async def test_an_approved_ticket_returns_the_final_turn(engine: AsyncEngine) -> None:
    _, owner, tid = await _held_input(engine)
    llm = ScriptedLLM(chat_answers=[ChatResult(content="Here you go.")])
    admin = await _admin(engine)
    final = await decide_ticket(engine, llm, InMemoryRiskyHistory(), tid, "ok", admin)
    result = await check_ticket(engine, owner, tid)
    assert result.status == "approved"
    assert result.turn_result == final
    assert final.player_view.reply == "Here you go."


async def test_a_human_denied_ticket_returns_the_denial(engine: AsyncEngine) -> None:
    _, owner, tid = await _held_input(engine)
    await decide_ticket(
        engine, ScriptedLLM(), InMemoryRiskyHistory(), tid, "not_ok", await _admin(engine)
    )
    result = await check_ticket(engine, owner, tid)
    assert result.status == "human_denied"
    assert result.turn_result is not None
    assert result.turn_result.player_view.status == "human_denied"


async def test_a_due_ticket_expires_when_checked(engine: AsyncEngine) -> None:
    sid, owner, tid = await _held_tool(engine)
    await _due(engine, tid)
    result = await check_ticket(engine, owner, tid)  # no sweep has run
    assert result.status == "expired"
    assert result.turn_result is not None
    assert result.turn_result.player_view.status == "blocked"
    assert await _rows(engine, "SELECT 1 FROM fw_tool_calls WHERE fw_session_id = :s", s=sid) == []


async def test_closing_the_session_shows_the_ticket_expired(engine: AsyncEngine) -> None:
    sid, owner, tid = await _held_input(engine)
    await close_session(engine, owner, sid)
    result = await check_ticket(engine, owner, tid)
    assert result.status == "expired"
    assert result.turn_result is not None
    assert result.turn_result.player_view.status == "blocked"


async def test_a_turn_held_again_finishes_under_the_first_ticket(engine: AsyncEngine) -> None:
    """The arena keeps polling the ticket it was given; it sees no result until the turn
    is really finished, even when the continuation is held for review a second time."""
    _, owner, first = await _held_input(engine, extra=REPLY_REVIEW)
    admin = await _admin(engine)
    llm = ScriptedLLM(chat_answers=[ChatResult(content="quarterly report attached")])
    again = await decide_ticket(engine, llm, InMemoryRiskyHistory(), first, "ok", admin)
    second = again.player_view.ticket_id or ""
    assert again.player_view.status == "awaiting_review" and second != first

    first_now = await check_ticket(engine, owner, first)
    assert (first_now.status, first_now.turn_result) == ("approved", None)
    assert (await check_ticket(engine, owner, second)).status == "pending"

    final = await decide_ticket(engine, llm, InMemoryRiskyHistory(), second, "ok", admin)
    assert final.player_view.status == "replied"
    assert (await check_ticket(engine, owner, first)).turn_result == final
    assert (await check_ticket(engine, owner, second)).turn_result == final


async def test_check_ticket_through_the_c2_interface(engine: AsyncEngine) -> None:
    _, owner, tid = await _held_input(engine)
    fw = RealFirewall(engine, ScriptedLLM(), InMemoryRiskyHistory(), StubJudge())
    result = await fw.check_ticket(owner, tid)
    assert result.status == "pending"
