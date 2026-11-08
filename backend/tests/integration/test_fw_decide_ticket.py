"""M2 C-02 `decide_ticket` (PRD §8.3 steps 3-6; E-46, E-46b; spec AEGIS-DOM-117).

ok: the held item continues exactly once (input to the bot, the held tool runs, the held
reply is released with no new model call); new items get normal checks; a bot failure ends
`blocked`. not ok: nothing runs, `human_denied`, a risky-behaviour row, and a pattern
candidate for a held tool call. A ticket no longer pending, or past its deadline, is a
`ConflictError`.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.arena.scenario_data import ATTACKER_MAILBOX
from app.contracts.common import ClientMeta
from app.contracts.fakes import InMemoryRiskyHistory
from app.contracts.firewall import HUMAN_DENIED_MESSAGE, NotFound, TurnResult
from app.contracts.firewall_admin import ConflictError
from app.firewall.pipeline import run_message
from app.firewall.tickets import decide_ticket
from app.llm.base import ChatResult, LLMError, ToolCall
from app.llm.scripted import ScriptedLLM
from tests.integration.test_fw_review_park import (
    AUTHORITY,
    REPLY_REVIEW,
    TOOL_REVIEW,
    _rows,
    _session,
    _ticket,
    _tool,
)

CLIENT = ClientMeta()


async def _admin(engine: AsyncEngine) -> str:
    async with engine.begin() as conn:
        return str(
            (
                await conn.execute(
                    text(
                        "INSERT INTO users (auth0_sub, role) VALUES ('auth0|adm', 'firewall_admin')"
                        " RETURNING id"
                    )
                )
            ).scalar_one()
        )


async def _claim(engine: AsyncEngine, sid: str, mid: str = "m1") -> tuple[str, TurnResult]:
    rows = await _rows(
        engine,
        "SELECT status, result FROM fw_claims WHERE fw_session_id = :s AND message_id = :m",
        s=sid,
        m=mid,
    )
    return rows[0]["status"], TurnResult.model_validate(rows[0]["result"])


async def _events(engine: AsyncEngine, sid: str) -> list[tuple[str, str, str]]:
    rows = await _rows(
        engine,
        "SELECT stage, decision, execution_status FROM fw_events WHERE fw_session_id = :s"
        " ORDER BY time, event_id",
        s=sid,
    )
    return [(r["stage"], r["decision"], r["execution_status"]) for r in rows]


# --- ok ----------------------------------------------------------------------------------------


async def test_approving_a_held_input_sends_it_to_the_bot(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine)
    admin = await _admin(engine)
    llm = ScriptedLLM(chat_answers=[ChatResult(content="Here are the docs.")])
    held = await run_message(engine, llm, owner, sid, "m1", AUTHORITY, CLIENT)
    tid = held.player_view.ticket_id or ""

    result = await decide_ticket(engine, llm, InMemoryRiskyHistory(), tid, "ok", admin)

    assert result.player_view.status == "replied"
    assert result.player_view.reply == "Here are the docs."
    assert [(f.stage, f.decision) for f in result.player_view.defense_feed] == [
        ("input_check", "review"),
        ("review_resolved", "allow"),
        ("output_check", "allow"),
    ]
    assert "R-002" in result.facts.rule_ids
    assert llm.chat_calls[0].messages[-1].content == AUTHORITY  # the held input, as checked
    ticket = await _ticket(engine, tid)
    assert ticket["status"] == "approved" and str(ticket["decided_by"]) == admin
    assert await _claim(engine, sid) == ("done", result)
    convo = await _rows(
        engine,
        "SELECT role, model_payload->>'in_history' AS h FROM fw_conversation"
        " WHERE fw_session_id = :s ORDER BY seq",
        s=sid,
    )
    assert [(r["role"], r["h"]) for r in convo] == [("student", "true"), ("bot", "true")]
    assert ("review_resolved", "allow", "executed") in await _events(engine, sid)
    # the next message works: the session is free again
    nxt = await run_message(
        engine, ScriptedLLM(chat_answers=[ChatResult(content="hi")]), owner, sid, "m2", "hi", CLIENT
    )
    assert nxt.player_view.status == "replied"


async def test_approving_a_held_tool_call_runs_it_once_and_resumes_the_bot(
    engine: AsyncEngine,
) -> None:
    sid, owner = await _session(engine, extra=TOOL_REVIEW)
    admin = await _admin(engine)
    llm = ScriptedLLM(
        chat_answers=[
            _tool(1, "read_file", path="docs/faq.md"),
            _tool(2, "search_docs", query="payroll"),
            ChatResult(content="Found the payroll doc."),
        ]
    )
    held = await run_message(engine, llm, owner, sid, "m1", "find payroll", CLIENT)
    result = await decide_ticket(
        engine, llm, InMemoryRiskyHistory(), held.player_view.ticket_id or "", "ok", admin
    )

    assert result.player_view.status == "replied"
    assert result.player_view.reply == "Found the payroll doc."
    effects = [(e.call_id, e.tool, e.state) for e in result.player_view.tool_effects]
    assert effects == [
        ("m1-r0-c0", "read_file", "executed"),
        ("m1-r1-c1", "search_docs", "executed"),
    ]
    ran = await _rows(
        engine,
        "SELECT call_id, tool FROM fw_tool_calls WHERE fw_session_id = :s ORDER BY created_at",
        s=sid,
    )
    assert ran == [
        {"call_id": "m1-r0-c0", "tool": "read_file"},
        {"call_id": "m1-r1-c1", "tool": "search_docs"},
    ]
    resumed = llm.chat_calls[-1].messages
    assert [m.role for m in resumed[-4:]] == ["assistant", "tool", "assistant", "tool"]
    assert resumed[-1].tool_call_id == "g2"  # the held call's result went back to the bot
    assert len(llm.chat_calls) == 3


async def test_calls_queued_after_the_held_one_get_normal_checks(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine, extra=TOOL_REVIEW)
    admin = await _admin(engine)
    both = ChatResult(
        content=None,
        tool_calls=[
            ToolCall(id="g1", name="search_docs", arguments={"query": "payroll"}),
            ToolCall(
                id="g2",
                name="send_email",
                arguments={"to": ATTACKER_MAILBOX, "subject": "x", "body": "y"},
            ),
        ],
    )
    llm = ScriptedLLM(chat_answers=[both])
    held = await run_message(engine, llm, owner, sid, "m1", "payroll then mail", CLIENT)
    result = await decide_ticket(
        engine, llm, InMemoryRiskyHistory(), held.player_view.ticket_id or "", "ok", admin
    )
    assert result.player_view.status == "blocked"  # R-003 denies the queued email
    assert "R-003" in result.facts.rule_ids
    states = [(e.tool, e.state) for e in result.player_view.tool_effects]
    assert states == [("search_docs", "executed"), ("send_email", "blocked")]
    ran = await _rows(engine, "SELECT tool FROM fw_tool_calls WHERE fw_session_id = :s", s=sid)
    assert ran == [{"tool": "search_docs"}]


async def test_an_approved_reply_is_released_exactly_with_no_model_call(
    engine: AsyncEngine,
) -> None:
    sid, owner = await _session(engine, extra=REPLY_REVIEW)
    admin = await _admin(engine)
    reply = "The quarterly numbers are up 4%."
    llm = ScriptedLLM(chat_answers=[ChatResult(content=reply)])
    held = await run_message(engine, llm, owner, sid, "m1", "how are we doing?", CLIENT)
    calls_before = len(llm.chat_calls)
    result = await decide_ticket(
        engine, llm, InMemoryRiskyHistory(), held.player_view.ticket_id or "", "ok", admin
    )
    assert result.player_view.status == "replied" and result.player_view.reply == reply
    assert len(llm.chat_calls) == calls_before  # E-46b: zero new bot model calls
    convo = await _rows(
        engine,
        "SELECT role, visible FROM fw_conversation WHERE fw_session_id = :s ORDER BY seq",
        s=sid,
    )
    assert [(r["role"], r["visible"]) for r in convo] == [("student", False), ("bot", True)]


async def test_a_new_review_during_the_continuation_parks_again(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine, extra=REPLY_REVIEW)
    admin = await _admin(engine)
    llm = ScriptedLLM(chat_answers=[ChatResult(content="quarterly results attached")])
    first = await run_message(engine, llm, owner, sid, "m1", AUTHORITY, CLIENT)  # input held
    second = await decide_ticket(
        engine, llm, InMemoryRiskyHistory(), first.player_view.ticket_id or "", "ok", admin
    )
    assert second.player_view.status == "awaiting_review"  # now the reply is held
    assert second.player_view.ticket_id not in (None, first.player_view.ticket_id)
    assert [(f.stage, f.decision) for f in second.player_view.defense_feed] == [
        ("input_check", "review"),
        ("review_resolved", "allow"),
        ("output_check", "review"),
    ]
    final = await decide_ticket(
        engine, llm, InMemoryRiskyHistory(), second.player_view.ticket_id or "", "ok", admin
    )
    assert final.player_view.reply == "quarterly results attached"
    assert len(llm.chat_calls) == 1


async def test_a_bot_failure_after_approval_fails_closed(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine)
    admin = await _admin(engine)
    llm = ScriptedLLM(chat_answers=[LLMError("down")])
    held = await run_message(engine, llm, owner, sid, "m1", AUTHORITY, CLIENT)
    result = await decide_ticket(
        engine, llm, InMemoryRiskyHistory(), held.player_view.ticket_id or "", "ok", admin
    )
    assert result.player_view.status == "blocked"
    assert await _claim(engine, sid) == ("done", result)


async def test_a_tampered_held_call_never_runs(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine, extra=TOOL_REVIEW)
    admin = await _admin(engine)
    llm = ScriptedLLM(chat_answers=[_tool(1, "search_docs", query="payroll")])
    held = await run_message(engine, llm, owner, sid, "m1", "payroll", CLIENT)
    tid = held.player_view.ticket_id or ""
    async with engine.begin() as conn:  # the stored call no longer matches what was reviewed
        await conn.execute(
            text(
                "UPDATE fw_tickets SET continuation = jsonb_set(continuation,"
                " '{held_call,arguments}', CAST(:a AS jsonb)) WHERE ticket_id = :t"
            ),
            {"a": json.dumps({"query": "secrets"}), "t": tid},
        )
    result = await decide_ticket(engine, llm, InMemoryRiskyHistory(), tid, "ok", admin)
    assert result.player_view.status == "blocked"
    assert await _rows(engine, "SELECT 1 FROM fw_tool_calls WHERE fw_session_id = :s", s=sid) == []


# --- not ok ------------------------------------------------------------------------------------


async def test_not_ok_on_a_held_tool_call_is_a_human_deny(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine, extra=TOOL_REVIEW)
    admin = await _admin(engine)
    risky = InMemoryRiskyHistory()
    llm = ScriptedLLM(chat_answers=[_tool(1, "search_docs", query="payroll")])
    held = await run_message(engine, llm, owner, sid, "m1", "payroll", CLIENT)
    tid = held.player_view.ticket_id or ""
    result = await decide_ticket(engine, llm, risky, tid, "not_ok", admin)

    view = result.player_view
    assert (view.status, view.reply) == ("human_denied", HUMAN_DENIED_MESSAGE)
    assert [(e.tool, e.state) for e in view.tool_effects] == [("search_docs", "human_denied")]
    assert view.defense_feed[-1].stage == "review_resolved"
    assert view.defense_feed[-1].decision == "human_deny"
    assert result.facts.decision == "human_deny" and result.facts.diverted is False
    assert len(llm.chat_calls) == 1
    assert await _rows(engine, "SELECT 1 FROM fw_tool_calls WHERE fw_session_id = :s", s=sid) == []
    assert (await _ticket(engine, tid))["status"] == "human_denied"
    assert await _claim(engine, sid) == ("done", result)
    assert ("review_resolved", "human_deny", "not_executed") in await _events(engine, sid)

    [record] = risky.records
    assert (record.action, record.stage, record.tool) == (
        "human_deny",
        "tool_call_check",
        "search_docs",
    )
    assert record.user_id == owner and record.shadow is False
    [candidate] = risky.candidates
    assert (candidate.tool, candidate.canonical_args) == ("search_docs", {"query": "payroll"})
    assert candidate.source_event_id == record.event_id


async def test_not_ok_on_a_held_input_adds_no_candidate(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine)
    admin = await _admin(engine)
    risky = InMemoryRiskyHistory()
    held = await run_message(engine, ScriptedLLM(), owner, sid, "m1", AUTHORITY, CLIENT)
    result = await decide_ticket(
        engine, ScriptedLLM(), risky, held.player_view.ticket_id or "", "not_ok", admin
    )
    assert result.player_view.status == "human_denied"
    assert [r.action for r in risky.records] == ["human_deny"]
    assert risky.records[0].input_text == AUTHORITY
    assert risky.candidates == []


# --- conflicts ---------------------------------------------------------------------------------


async def _held_input(engine: AsyncEngine) -> tuple[str, str, str]:
    sid, owner = await _session(engine)
    held = await run_message(engine, ScriptedLLM(), owner, sid, "m1", AUTHORITY, CLIENT)
    return sid, held.player_view.ticket_id or "", await _admin(engine)


async def test_a_ticket_is_decided_only_once(engine: AsyncEngine) -> None:
    _, tid, admin = await _held_input(engine)
    llm = ScriptedLLM(chat_answers=[ChatResult(content="ok")])
    await decide_ticket(engine, llm, InMemoryRiskyHistory(), tid, "ok", admin)
    with pytest.raises(ConflictError):
        await decide_ticket(engine, llm, InMemoryRiskyHistory(), tid, "not_ok", admin)


async def test_concurrent_decisions_let_exactly_one_win(engine: AsyncEngine) -> None:
    _, tid, admin = await _held_input(engine)
    llm = ScriptedLLM(chat_answers=[ChatResult(content="ok")])
    outcomes: list[Any] = await asyncio.gather(
        decide_ticket(engine, llm, InMemoryRiskyHistory(), tid, "ok", admin),
        decide_ticket(engine, llm, InMemoryRiskyHistory(), tid, "not_ok", admin),
        return_exceptions=True,
    )
    assert sum(isinstance(o, ConflictError) for o in outcomes) == 1
    assert sum(isinstance(o, TurnResult) for o in outcomes) == 1


async def test_expiry_wins_at_the_deadline(engine: AsyncEngine) -> None:
    _, tid, admin = await _held_input(engine)
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE fw_tickets SET expires_at = now() WHERE ticket_id = :t"), {"t": tid}
        )
    with pytest.raises(ConflictError):
        await decide_ticket(engine, ScriptedLLM(), InMemoryRiskyHistory(), tid, "ok", admin)
    assert (await _ticket(engine, tid))["status"] == "expired"  # expired on the spot (C-03)


async def test_an_unknown_ticket_is_not_found(engine: AsyncEngine) -> None:
    _, _, admin = await _held_input(engine)
    with pytest.raises(NotFound):
        await decide_ticket(engine, ScriptedLLM(), InMemoryRiskyHistory(), "tkt-x", "ok", admin)
