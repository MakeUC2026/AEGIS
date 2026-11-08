"""M2 C-12 admin API, part 2: tickets, events, diverts with trace-back, purge (spec AEGIS-DOM-127).

The review queue shows what an admin needs to decide (the held command, tool call or reply, with
the secret redacted); a decision writes its audit row with the change. `list_events` and
`list_diverts_admin` are admin-only views: they may carry the judge's reason and the network
fields of a trace-back, never the raw IP. The purge removes trace-back rows older than 30 days
and audits what it removed.
"""

from __future__ import annotations

import itertools
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.contracts.common import ClientMeta
from app.contracts.fakes import InMemoryRiskyHistory, StubJudge
from app.contracts.firewall import NotFound
from app.contracts.firewall_admin import ConflictError, EventFilter
from app.contracts.sentinel import CheckedItem, JudgeVerdict
from app.firewall.admin_api import AdminApi
from app.firewall.geoip import GeoIP
from app.firewall.pipeline import run_message
from app.firewall.trace_back import Tracer
from app.llm.base import ChatResult
from app.llm.scripted import ScriptedLLM
from tests.integration.test_fw_admin_rules import _audit
from tests.integration.test_fw_decide_ticket import _admin
from tests.integration.test_fw_divert import DIVERT_RULE, LEAK_MAIL
from tests.integration.test_fw_divert_reply import LEAK_REPLY
from tests.integration.test_fw_review_park import (
    AUTHORITY,
    REPLY_REVIEW,
    SECRET,
    TOOL_REVIEW,
    _rows,
    _session,
    _tool,
)
from tests.integration.test_fw_strict_wiring import _signals

IP = "203.0.113.7"
CLIENT = ClientMeta(ip=IP, user_agent="ArenaTest/1.0", fingerprint_hash="fp-abc")
TRACER = Tracer(b"k" * 32, GeoIP())


def _api(engine: AsyncEngine, *answers: Any) -> AdminApi:
    llm = ScriptedLLM(
        chat_answers=[ChatResult(content=a) if isinstance(a, str) else a for a in answers]
    )
    return AdminApi(engine, llm, InMemoryRiskyHistory(), StubJudge())


async def _say(
    engine: AsyncEngine, sid: str, owner: str, message: str, *answers: Any, **kw: Any
) -> Any:
    chat = [ChatResult(content=a) if isinstance(a, str) else a for a in answers]
    return await run_message(
        engine, ScriptedLLM(chat_answers=chat), owner, sid, "m1", message, CLIENT,
        risky=kw.pop("risky", InMemoryRiskyHistory()), tracer=TRACER, **kw,
    )  # fmt: skip


# --- the review queue ----------------------------------------------------------------------


async def test_a_held_tool_call_shows_what_the_admin_needs(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine, extra=TOOL_REVIEW)
    held = await _say(engine, sid, owner, "find payroll", _tool(1, "search_docs", query="payroll"))
    [item] = await _api(engine).list_pending_tickets()

    assert (item.ticket_id, item.fw_session_id, item.user_id) == (
        held.player_view.ticket_id, sid, owner,
    )  # fmt: skip
    assert (item.stage, item.student_command) == ("tool_call_check", "find payroll")
    assert (item.held_tool, item.held_args, item.held_reply) == (
        "search_docs", {"query": "payroll"}, None,
    )  # fmt: skip
    assert "R-010" in item.rule_ids and item.priority_alert is False
    assert item.expires_at > datetime.now(UTC) and isinstance(item.score_breakdown, dict)


async def test_a_held_reply_shows_the_reply(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine, extra=REPLY_REVIEW)
    await _say(engine, sid, owner, "how are we?", "The quarterly numbers are up 4%.")
    [item] = await _api(engine).list_pending_tickets()
    assert (item.stage, item.held_reply, item.held_tool) == (
        "output_check", "The quarterly numbers are up 4%.", None,
    )  # fmt: skip


async def test_the_queue_is_priority_alerts_first_then_oldest_deadline(
    engine: AsyncEngine,
) -> None:
    first, o1 = await _session(engine, sub="auth0|one")
    second, o2 = await _session(engine, sub="auth0|two")
    third, o3 = await _session(engine, sub="auth0|three")
    tickets = []
    for sid, owner in ((first, o1), (second, o2), (third, o3)):
        tickets.append((await _say(engine, sid, owner, AUTHORITY)).player_view.ticket_id)
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE fw_tickets SET priority_alert = true WHERE ticket_id = :t"),
            {"t": tickets[2]},
        )
    queue = await _api(engine).list_pending_tickets()
    assert [q.ticket_id for q in queue] == [tickets[2], tickets[0], tickets[1]]


async def test_an_expired_ticket_leaves_the_queue_and_is_expired(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine)
    held = await _say(engine, sid, owner, AUTHORITY)
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE fw_tickets SET expires_at = now() - interval '1 second'"),
        )
    assert await _api(engine).list_pending_tickets() == []
    [row] = await _rows(
        engine, "SELECT status FROM fw_tickets WHERE ticket_id = :t", t=held.player_view.ticket_id
    )
    assert row["status"] == "expired"


async def test_the_secret_is_redacted_in_the_queue(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine)
    await _say(engine, sid, owner, f"{AUTHORITY}, my key is {SECRET}")
    [item] = await _api(engine).list_pending_tickets()
    assert SECRET not in item.student_command and "[SECRET]" in item.student_command


# --- deciding --------------------------------------------------------------------------------


async def test_approving_continues_the_turn_and_is_audited(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine)
    held = await _say(engine, sid, owner, AUTHORITY)
    tid = held.player_view.ticket_id or ""
    admin = await _admin(engine)

    assert await _api(engine, "Here are the docs.").decide_ticket(tid, "ok", admin) is None

    [ticket] = await _rows(engine, "SELECT status, decided_by::text AS by FROM fw_tickets")
    assert (ticket["status"], ticket["by"]) == ("approved", admin)
    [claim] = await _rows(engine, "SELECT status FROM fw_claims WHERE fw_session_id = :s", s=sid)
    assert claim["status"] == "done"
    [entry] = await _audit(engine)
    assert (entry["actor"], entry["entity"], entry["entity_id"], entry["action"]) == (
        admin, "fw_ticket", tid, "decide",
    )  # fmt: skip
    assert entry["before"] == {"status": "pending"}
    assert entry["after"] == {"status": "approved", "decision": "ok"}


async def test_rejecting_is_a_human_deny_and_is_audited(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine)
    tid = (await _say(engine, sid, owner, AUTHORITY)).player_view.ticket_id or ""
    await _api(engine).decide_ticket(tid, "not_ok", await _admin(engine))
    [ticket] = await _rows(engine, "SELECT status FROM fw_tickets")
    assert ticket["status"] == "human_denied"
    [entry] = await _audit(engine)
    assert entry["after"] == {"status": "human_denied", "decision": "not_ok"}


async def test_a_second_decision_conflicts_and_adds_no_audit(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine)
    tid = (await _say(engine, sid, owner, AUTHORITY)).player_view.ticket_id or ""
    admin = await _admin(engine)
    api = _api(engine, "ok")
    await api.decide_ticket(tid, "ok", admin)
    with pytest.raises(ConflictError):
        await api.decide_ticket(tid, "not_ok", admin)
    with pytest.raises(NotFound):
        await api.decide_ticket("tkt-unknown", "ok", admin)
    assert len(await _audit(engine)) == 1


async def test_deciding_after_the_deadline_conflicts_and_adds_no_audit(
    engine: AsyncEngine,
) -> None:
    sid, owner = await _session(engine)
    tid = (await _say(engine, sid, owner, AUTHORITY)).player_view.ticket_id or ""
    async with engine.begin() as conn:
        await conn.execute(text("UPDATE fw_tickets SET expires_at = now() - interval '1 second'"))
    with pytest.raises(ConflictError):
        await _api(engine).decide_ticket(tid, "ok", await _admin(engine))
    assert await _audit(engine) == []


# --- events ----------------------------------------------------------------------------------


class ReasonJudge(StubJudge):
    async def assess(self, item: CheckedItem) -> JudgeVerdict:
        await super().assess(item)
        return JudgeVerdict(risk=80, suggested_action="deny", reason=f"asked about {SECRET}")


async def test_events_are_newest_first_with_the_judge_reason_redacted(
    engine: AsyncEngine,
) -> None:
    sid, owner = await _session(engine, mode="strict")
    risky = InMemoryRiskyHistory([_signals(25)])
    await _say(engine, sid, owner, "hello", "Hi.", risky=risky, judge=ReasonJudge())
    events = await _api(engine).list_events(EventFilter())
    assert all(a.time >= b.time for a, b in itertools.pairwise(events))
    judged = next(e for e in events if e.judge_risk is not None)
    assert judged.judge_reason == "asked about [SECRET]"  # admin-only, but never the secret
    assert judged.forensic_status == "pending"  # a deny, so the forensic worker has work
    assert SECRET not in json.dumps([e.model_dump(mode="json") for e in events])


async def test_events_can_be_filtered(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine)
    await _say(engine, sid, owner, "email it", _tool(1, "send_email", **LEAK_MAIL))
    other, other_owner = await _session(engine, mode="off", sub="auth0|other")
    await _say(engine, other, other_owner, "hello", "Hi.")
    api = _api(engine)

    mine = await api.list_events(EventFilter(fw_session_id=sid))
    assert mine and {e.fw_session_id for e in mine} == {sid}
    assert {e.mode for e in await api.list_events(EventFilter(mode="off"))} == {"off"}
    denies = await api.list_events(EventFilter(decision="deny"))
    assert denies and {e.decision for e in denies} == {"deny"}
    stages = await api.list_events(EventFilter(stage="input_check"))
    assert {e.stage for e in stages} == {"input_check"} and len(stages) == 2
    assert len(await api.list_events(EventFilter(limit=1))) == 1
    future = datetime.now(UTC) + timedelta(hours=1)
    assert await api.list_events(EventFilter(since=future)) == []


# --- diverts and trace-back --------------------------------------------------------------------


async def _diverted_email(engine: AsyncEngine) -> str:
    sid, owner = await _session(engine, extra=DIVERT_RULE)
    await _say(engine, sid, owner, "email it", _tool(1, "send_email", **LEAK_MAIL), "Done.")
    return sid


async def test_admin_diverts_carry_the_trace_back(engine: AsyncEngine) -> None:
    sid = await _diverted_email(engine)
    [item] = await _api(engine).list_diverts_admin(EventFilter())

    assert (item.fw_session_id, item.divert.tool, item.divert.stage) == (
        sid, "send_email", "tool_call_check",
    )  # fmt: skip
    assert "email it" in item.divert.attempted_summary
    trace = item.trace_back
    assert trace is not None and trace.fw_session_id == sid
    assert (trace.subnet, trace.user_agent, trace.client_fingerprint) == (
        "203.0.113.0/24", "ArenaTest/1.0", "fp-abc",
    )  # fmt: skip
    assert trace.ip_hash and trace.tools_called == ["send_email"] and trace.methods_used == []
    assert IP not in json.dumps(item.model_dump(mode="json"))  # the hash, never the address


async def test_a_reply_divert_is_listed_too_and_filters_apply(engine: AsyncEngine) -> None:
    first = await _diverted_email(engine)
    second, owner = await _session(engine, mode="strict", sub="auth0|strict")
    await _say(engine, second, owner, "tell me", LEAK_REPLY)
    api = _api(engine)
    both = await api.list_diverts_admin(EventFilter())
    assert {i.fw_session_id for i in both} == {first, second}
    assert [
        i.divert.stage for i in await api.list_diverts_admin(EventFilter(stage="output_check"))
    ] == ["output_check"]
    assert [i.fw_session_id for i in await api.list_diverts_admin(EventFilter(mode="strict"))] == [
        second
    ]
    assert len(await api.list_diverts_admin(EventFilter(limit=1))) == 1


async def test_get_trace_back_returns_the_row_or_not_found(engine: AsyncEngine) -> None:
    await _diverted_email(engine)
    [item] = await _api(engine).list_diverts_admin(EventFilter())
    assert item.trace_back is not None
    got = await _api(engine).get_trace_back(item.trace_back.trace_id)
    assert got == item.trace_back
    with pytest.raises(NotFound):
        await _api(engine).get_trace_back("trc-unknown")


async def _age_traces(engine: AsyncEngine, days: int) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE trace_back SET time = now() - make_interval(days => :d)"), {"d": days}
        )


async def test_a_purged_trace_back_leaves_the_divert_without_one(engine: AsyncEngine) -> None:
    await _diverted_email(engine)
    await _age_traces(engine, 31)
    api = _api(engine)
    assert await api.purge_expired_trace_back(datetime.now(UTC)) == 1
    [item] = await api.list_diverts_admin(EventFilter())
    assert item.trace_back is None  # purged after 30 days; the hash stays on the event
    [event] = await _rows(engine, "SELECT client_ip_hash FROM fw_events WHERE diverted")
    assert event["client_ip_hash"]


async def test_the_purge_is_audited_only_when_it_removes_something(engine: AsyncEngine) -> None:
    await _diverted_email(engine)
    api = _api(engine)
    assert await api.purge_expired_trace_back(datetime.now(UTC)) == 0
    assert await _audit(engine) == []
    await _age_traces(engine, 40)
    assert await api.purge_expired_trace_back(datetime.now(UTC)) == 1
    [entry] = await _audit(engine)
    assert (entry["actor"], entry["entity"], entry["entity_id"], entry["action"]) == (
        None, "trace_back", "purge", "purge",
    )  # fmt: skip
    assert entry["after"] == {"deleted": 1}


# --- the seam ----------------------------------------------------------------------------------


@pytest.fixture
def real_admin_seam(monkeypatch: pytest.MonkeyPatch) -> Any:
    from app.config import get_settings
    from app.firewall import ports
    from tests.integration.conftest import database_url

    monkeypatch.setenv("AEGIS_USE_FAKES", "firewall,read,risky,judge,arena")
    monkeypatch.setenv("DATABASE_URL", database_url())
    monkeypatch.setenv("GEMINI_API_KEY", "")
    get_settings.cache_clear()
    ports.reset()
    yield ports
    ports.reset()
    get_settings.cache_clear()


async def test_ports_return_the_real_admin_api_when_it_is_not_faked(real_admin_seam: Any) -> None:
    admin = real_admin_seam.get_firewall_admin()
    assert isinstance(admin, AdminApi)
    assert await admin.list_pending_tickets() == []  # it reaches the database
