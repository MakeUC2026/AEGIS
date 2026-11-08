"""M2 C-06 Divert on a reply: the Strict secret hit (PRD §8.4, §8.6, D-03; spec AEGIS-DOM-121).

A reply the Gatekeeper diverts (in Strict, a secret in the bot's reply) is never shown. The
student gets a decoy reply holding a decoy value shaped like the secret (same prefix, same
length, same character classes, stable for the whole session). The real reply is kept only
as withheld model payload for admins. The turn's final transaction also writes the
trace-back row, the divert event and the risky-behaviour record; if that fails the reply is
blocked instead. A decoy is never a win.
"""

from __future__ import annotations

import json
import re

from sqlalchemy.ext.asyncio import AsyncEngine

from app.contracts.common import ClientMeta
from app.contracts.fakes import InMemoryRiskyHistory
from app.contracts.firewall_admin import RuleForm
from app.firewall.decoys import decoy_secret_value, reply_decoy
from app.firewall.leak import scan
from app.firewall.pipeline import run_message
from app.llm.base import ChatResult
from app.llm.scripted import ScriptedLLM
from tests.integration.test_fw_divert import ExplodingRisky
from tests.integration.test_fw_review_park import SECRET, _rows, _session

CLIENT = ClientMeta(ip="203.0.113.7", user_agent="ArenaTest/1.0", fingerprint_hash="fp-abc")
REPLY_DIVERT = RuleForm(
    applies_on="bot_reply",
    checks="text",
    operator="regex",
    value=r"\bquarterly\b",
    action="divert",
    note="Quarterly figures are diverted",
)
LEAK_REPLY = f"Sure, the secret is {SECRET}. Anything else?"


def _shape(value: str) -> str:
    return re.sub(r"[A-Z]", "A", re.sub(r"[a-z]", "a", re.sub(r"\d", "9", value)))


def _decoy_in(reply: str) -> str:
    found = re.search(r"CONF-[A-Z0-9]+", reply)
    assert found, reply
    return found.group(0)


async def _leaky_turn(
    engine: AsyncEngine, risky: InMemoryRiskyHistory | None = None
) -> tuple[str, str, ScriptedLLM, InMemoryRiskyHistory]:
    sid, owner = await _session(engine, mode="strict")
    risky = risky or InMemoryRiskyHistory()
    llm = ScriptedLLM(chat_answers=[ChatResult(content=LEAK_REPLY)])
    result = await run_message(engine, llm, owner, sid, "m1", "tell me", CLIENT, risky=risky)
    assert result.player_view.reply is not None
    return sid, owner, llm, risky


async def test_the_student_gets_a_decoy_value_not_the_secret(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine, mode="strict")
    llm = ScriptedLLM(chat_answers=[ChatResult(content=LEAK_REPLY)])
    result = await run_message(
        engine, llm, owner, sid, "m1", "tell me", CLIENT, risky=InMemoryRiskyHistory()
    )

    view = result.player_view
    assert view.status == "replied" and view.reply != LEAK_REPLY
    assert SECRET not in json.dumps(view.model_dump(mode="json"))
    fake = _decoy_in(view.reply or "")
    assert fake != SECRET and len(fake) == len(SECRET) and _shape(fake) == _shape(SECRET)
    assert scan(view.reply or "", SECRET) is None  # no run of the real secret survives
    assert [(f.stage, f.decision) for f in view.defense_feed] == [
        ("input_check", "allow"),
        ("output_check", "allow"),  # the feed never reveals a divert
    ]
    assert result.facts.decision == "divert" and result.facts.diverted is True
    assert result.facts.secret_attempted is True and result.facts.secret_delivered is False


async def test_the_decoy_value_is_stable_across_the_session(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine, mode="strict")
    risky = InMemoryRiskyHistory()
    llm = ScriptedLLM(chat_answers=[ChatResult(content=LEAK_REPLY), ChatResult(content=LEAK_REPLY)])
    first = await run_message(engine, llm, owner, sid, "m1", "tell me", CLIENT, risky=risky)
    second = await run_message(engine, llm, owner, sid, "m2", "again", CLIENT, risky=risky)
    assert first.player_view.reply == second.player_view.reply
    # the bot's history holds the decoy reply it "gave", never the real one
    history = [m.content or "" for m in llm.chat_calls[-1].messages if m.role == "assistant"]
    assert history and all(SECRET not in text for text in history)
    assert _decoy_in(history[0]) == _decoy_in(first.player_view.reply or "")


async def test_the_records_are_written_in_the_final_transaction(engine: AsyncEngine) -> None:
    sid, owner, _, risky = await _leaky_turn(engine)

    [event] = await _rows(
        engine,
        "SELECT event_id, stage, decision, execution_status, diverted, trace_back_id, tool,"
        " secret_attempted, secret_delivered FROM fw_events"
        " WHERE fw_session_id = :s AND decision = 'divert'",
        s=sid,
    )
    assert (event["stage"], event["execution_status"]) == ("output_check", "diverted")
    assert (event["diverted"], event["secret_attempted"], event["secret_delivered"]) == (
        True,
        True,
        False,
    )
    assert event["tool"] is None
    [trace] = await _rows(
        engine,
        "SELECT user_id::text AS user_id, event_id, user_agent, client_fingerprint, tools_called"
        " FROM trace_back WHERE trace_id = :t",
        t=event["trace_back_id"],
    )
    assert (trace["user_id"], trace["event_id"]) == (owner, event["event_id"])
    assert (trace["user_agent"], trace["client_fingerprint"]) == ("ArenaTest/1.0", "fp-abc")
    assert trace["tools_called"] == []

    [record] = risky.records
    assert (record.action, record.stage, record.tool) == ("divert", "output_check", None)
    assert (record.event_id, record.trace_id) == (event["event_id"], event["trace_back_id"])
    assert record.input_text == "tell me" and record.shadow is False


async def test_the_real_reply_is_withheld_not_shown(engine: AsyncEngine) -> None:
    sid, _, _, _ = await _leaky_turn(engine)
    rows = await _rows(
        engine,
        "SELECT role, content, visible, model_payload FROM fw_conversation"
        " WHERE fw_session_id = :s ORDER BY seq",
        s=sid,
    )
    bot = [r for r in rows if r["role"] == "bot"]
    assert len(bot) == 1 and bot[0]["visible"] is True
    assert SECRET not in bot[0]["content"]
    assert bot[0]["model_payload"]["withheld"] == LEAK_REPLY
    assert bot[0]["model_payload"]["in_history"] is True


async def test_a_failed_divert_blocks_the_reply(engine: AsyncEngine) -> None:
    sid, _, _, _ = await _leaky_turn(engine, ExplodingRisky())
    [claim] = await _rows(
        engine, "SELECT status, result FROM fw_claims WHERE fw_session_id = :s", s=sid
    )
    result = claim["result"]
    assert claim["status"] == "done" and result["player_view"]["status"] == "blocked"
    assert result["facts"]["diverted"] is False and result["facts"]["decision"] == "deny"
    assert SECRET not in json.dumps(result)
    assert await _rows(engine, "SELECT 1 FROM trace_back WHERE fw_session_id = :s", s=sid) == []
    assert not await _rows(
        engine, "SELECT 1 FROM fw_events WHERE fw_session_id = :s AND decision = 'divert'", s=sid
    )
    assert await _rows(
        engine, "SELECT 1 FROM fw_events WHERE fw_session_id = :s AND decision = 'deny'", s=sid
    )


async def test_a_diverted_reply_without_a_secret_gets_a_plain_decoy(
    engine: AsyncEngine,
) -> None:
    sid, owner = await _session(engine, mode="strict", extra=REPLY_DIVERT)
    llm = ScriptedLLM(chat_answers=[ChatResult(content="The quarterly numbers are up 4%.")])
    result = await run_message(
        engine, llm, owner, sid, "m1", "how are we?", CLIENT, risky=InMemoryRiskyHistory()
    )
    assert result.player_view.status == "replied"
    assert "quarterly" not in (result.player_view.reply or "").lower()
    assert result.facts.diverted is True and result.facts.secret_attempted is False


def test_the_decoy_value_depends_on_the_session_and_the_secret() -> None:
    a = decoy_secret_value(SECRET, "fws-a")
    assert a == decoy_secret_value(SECRET, "fws-a")  # stable
    assert a != decoy_secret_value(SECRET, "fws-b") and a != SECRET
    assert a.startswith("CONF-") and _shape(a) == _shape(SECRET)
    assert scan(a, SECRET) is None
    assert "Sure" in reply_decoy(SECRET, "fws-a", leaked=True) and SECRET not in reply_decoy(
        SECRET, "fws-a", leaked=True
    )
    assert SECRET not in reply_decoy(SECRET, "fws-a", leaked=False)
