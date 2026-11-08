"""M2 C-03 review expiry (PRD §8.3 step 6; E-47; spec AEGIS-DOM-118).

An expired review counts as Deny: the ticket becomes `expired`, a `review_resolved` deny
event is written, and the held turn finishes `blocked` with nothing executed. The sweep runs
every 5 s; `decide_ticket` also expires a due ticket itself before refusing the decision.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.contracts.common import ClientMeta
from app.contracts.fakes import InMemoryRiskyHistory
from app.contracts.firewall import NEUTRAL_REFUSAL, TurnResult
from app.contracts.firewall_admin import ConflictError
from app.firewall.pipeline import run_message
from app.firewall.tickets import TICKET_SWEEP_INTERVAL_S, decide_ticket, expire_due, sweep
from app.llm.base import ChatResult
from app.llm.scripted import ScriptedLLM
from tests.integration.test_fw_decide_ticket import _admin, _events
from tests.integration.test_fw_review_park import (
    AUTHORITY,
    TOOL_REVIEW,
    _rows,
    _session,
    _ticket,
    _tool,
)

CLIENT = ClientMeta()


async def _due(engine: AsyncEngine, ticket_id: str) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE fw_tickets SET expires_at = now() - interval '1 second'"
                " WHERE ticket_id = :t"
            ),
            {"t": ticket_id},
        )


async def _held_tool(engine: AsyncEngine) -> tuple[str, str, str]:
    sid, owner = await _session(engine, extra=TOOL_REVIEW)
    llm = ScriptedLLM(chat_answers=[_tool(1, "search_docs", query="payroll")])
    held = await run_message(engine, llm, owner, sid, "m1", "payroll please", CLIENT)
    return sid, owner, held.player_view.ticket_id or ""


async def _claim(engine: AsyncEngine, sid: str) -> tuple[str, TurnResult]:
    row = (
        await _rows(engine, "SELECT status, result FROM fw_claims WHERE fw_session_id = :s", s=sid)
    )[0]
    return row["status"], TurnResult.model_validate(row["result"])


async def test_the_sweep_expires_a_due_ticket_as_a_deny(engine: AsyncEngine) -> None:
    sid, owner, tid = await _held_tool(engine)
    await _due(engine, tid)

    assert await expire_due(engine) == 1

    ticket = await _ticket(engine, tid)
    assert ticket["status"] == "expired"
    assert ticket["decided_at"] is not None and ticket["decided_by"] is None
    assert ("review_resolved", "deny", "not_executed") in await _events(engine, sid)
    status, result = await _claim(engine, sid)
    assert status == "done"
    view = result.player_view
    assert (view.status, view.reply) == ("blocked", NEUTRAL_REFUSAL)
    assert [(e.tool, e.state) for e in view.tool_effects] == [("search_docs", "blocked")]
    assert [(f.stage, f.decision) for f in view.defense_feed] == [
        ("input_check", "allow"),
        ("tool_call_check", "review"),
        ("review_resolved", "deny"),
    ]
    assert result.facts.decision == "deny" and "R-010" in result.facts.rule_ids
    assert await _rows(engine, "SELECT 1 FROM fw_tool_calls WHERE fw_session_id = :s", s=sid) == []
    # the session is free again
    llm = ScriptedLLM(chat_answers=[ChatResult(content="hi")])
    nxt = await run_message(engine, llm, owner, sid, "m2", "hello", CLIENT)
    assert nxt.player_view.status == "replied"


async def test_the_sweep_leaves_live_and_decided_tickets_alone(engine: AsyncEngine) -> None:
    _, _, tid = await _held_tool(engine)
    assert await expire_due(engine) == 0
    assert (await _ticket(engine, tid))["status"] == "pending"
    async with engine.begin() as conn:  # a decided ticket past its deadline stays decided
        await conn.execute(
            text(
                "UPDATE fw_tickets SET status = 'approved', decided_at = now(),"
                " expires_at = now() - interval '1 second' WHERE ticket_id = :t"
            ),
            {"t": tid},
        )
    assert await expire_due(engine) == 0
    assert (await _ticket(engine, tid))["status"] == "approved"


async def test_deciding_after_the_deadline_expires_the_ticket_first(
    engine: AsyncEngine,
) -> None:
    sid, _, tid = await _held_tool(engine)
    admin = await _admin(engine)
    await _due(engine, tid)
    with pytest.raises(ConflictError):
        await decide_ticket(engine, ScriptedLLM(), InMemoryRiskyHistory(), tid, "ok", admin)
    assert (await _ticket(engine, tid))["status"] == "expired"
    status, result = await _claim(engine, sid)
    assert (status, result.player_view.status) == ("done", "blocked")
    assert await expire_due(engine) == 0  # nothing left for the sweep


async def test_an_expired_input_never_reaches_the_bot(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine)
    llm = ScriptedLLM(chat_answers=[ChatResult(content="never asked")])
    held = await run_message(engine, llm, owner, sid, "m1", AUTHORITY, CLIENT)
    await _due(engine, held.player_view.ticket_id or "")
    assert await expire_due(engine) == 1
    assert llm.chat_calls == []
    _, result = await _claim(engine, sid)
    assert result.player_view.status == "blocked"


async def test_the_sweep_loop_runs_until_stopped(engine: AsyncEngine) -> None:
    assert TICKET_SWEEP_INTERVAL_S == 5.0  # PRD §8.3 / M2 C-03
    _, _, tid = await _held_tool(engine)
    await _due(engine, tid)
    stop = asyncio.Event()
    task = asyncio.create_task(sweep(engine, stop, interval_s=0.05))
    for _ in range(100):
        if (await _ticket(engine, tid))["status"] == "expired":
            break
        await asyncio.sleep(0.05)
    stop.set()
    await asyncio.wait_for(task, timeout=2)
    assert (await _ticket(engine, tid))["status"] == "expired"


async def test_a_failing_sweep_keeps_running(
    engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Any] = []
    three = asyncio.Event()

    async def broken(_: AsyncEngine) -> int:
        calls.append(1)
        if len(calls) >= 3:
            three.set()
        raise RuntimeError("db down")

    monkeypatch.setattr("app.firewall.tickets.expire_due", broken)
    stop = asyncio.Event()
    task = asyncio.create_task(sweep(engine, stop, interval_s=0.01))
    await asyncio.wait_for(three.wait(), timeout=2)
    stop.set()
    await asyncio.wait_for(task, timeout=2)
    assert len(calls) >= 3
