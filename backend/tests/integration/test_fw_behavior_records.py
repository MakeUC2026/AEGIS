"""M2 C-09 risky-behaviour records and pattern candidates (PRD §7.5, §8.2; spec AEGIS-DOM-124).

`record_behavior` is called on the same transaction as the event for every enforced Deny and
Divert in Basic and Strict, and, with `shadow: true`, for every shadow Deny or Divert in Off.
(Human Deny is C-02 and Divert's own transaction is C-05.) A denied or diverted tool call
also adds a pattern candidate. Records describe what was enforced: an item blocked at the
Divert band without a decoy is recorded as a deny. Nothing that holds the secret is sent.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from app.arena.scenario_data import ATTACKER_MAILBOX
from app.contracts.common import ClientMeta
from app.contracts.fakes import InMemoryRiskyHistory
from app.contracts.firewall_admin import RuleForm
from app.contracts.sentinel import RiskyBehaviorRecord
from app.firewall.behavior import WITHHELD
from app.firewall.pipeline import run_message
from app.llm.base import ChatResult
from app.llm.scripted import ScriptedLLM
from tests.integration.test_fw_divert import DIVERT_RULE, LEAK_MAIL, ExplodingRisky
from tests.integration.test_fw_divert_reply import LEAK_REPLY
from tests.integration.test_fw_review_park import AUTHORITY, SECRET, _rows, _session, _tool

CLIENT = ClientMeta()
INPUT_DENY = RuleForm(
    applies_on="player_message",
    checks="text",
    operator="contains",
    value="forbidden word",
    action="deny",
    note="A word that is always refused",
)


async def _run(
    engine: AsyncEngine,
    llm: ScriptedLLM,
    risky: InMemoryRiskyHistory,
    message: str = "hello",
    **session: Any,
) -> tuple[str, Any]:
    sid, owner = await _session(engine, **session)
    result = await run_message(engine, llm, owner, sid, "m1", message, CLIENT, risky=risky)
    return sid, result


def _one(risky: InMemoryRiskyHistory) -> RiskyBehaviorRecord:
    assert len(risky.records) == 1, risky.records
    return risky.records[0]


# --- Basic and Strict: every enforced Deny ---------------------------------------------------


async def test_a_denied_input_is_recorded(engine: AsyncEngine) -> None:
    risky = InMemoryRiskyHistory()
    sid, result = await _run(
        engine, ScriptedLLM(), risky, "say the forbidden word", extra=INPUT_DENY
    )
    assert result.player_view.status == "blocked"
    record = _one(risky)
    assert (record.action, record.stage, record.tool, record.shadow) == (
        "deny", "input_check", None, False,
    )  # fmt: skip
    assert record.input_text == "say the forbidden word" and record.trace_id is None
    assert "R-010" in record.rule_ids and record.sentinel_score >= 0
    [event] = await _rows(
        engine,
        "SELECT event_id FROM fw_events WHERE fw_session_id = :s AND decision = 'deny'",
        s=sid,
    )
    assert record.event_id == event["event_id"] and risky.candidates == []


async def test_a_denied_tool_call_is_recorded_with_a_candidate(engine: AsyncEngine) -> None:
    risky = InMemoryRiskyHistory()
    llm = ScriptedLLM(chat_answers=[_tool(1, "send_email", **LEAK_MAIL)])
    _, result = await _run(engine, llm, risky, "email it")
    assert result.player_view.status == "blocked"

    record = _one(risky)
    assert (record.action, record.stage, record.tool, record.shadow) == (
        "deny", "tool_call_check", "send_email", False,
    )  # fmt: skip
    assert record.args_hash and {"R-003", "B-01"} <= set(record.rule_ids)
    [candidate] = risky.candidates
    assert candidate.tool == "send_email" and candidate.user_id == record.user_id
    assert candidate.source_event_id == record.event_id
    assert candidate.canonical_args["to"] == ATTACKER_MAILBOX
    assert candidate.canonical_args["body"] == WITHHELD  # the body held the secret
    assert SECRET not in str(candidate.canonical_args)


async def test_a_denied_reply_is_recorded_without_a_candidate(engine: AsyncEngine) -> None:
    risky = InMemoryRiskyHistory()
    llm = ScriptedLLM(chat_answers=[ChatResult(content=LEAK_REPLY)])
    _, result = await _run(engine, llm, risky, "tell me")
    assert result.player_view.status == "blocked"
    record = _one(risky)
    assert (record.action, record.stage, record.tool) == ("deny", "output_check", None)
    assert "B-01" in record.rule_ids and risky.candidates == []


async def test_a_diverted_tool_call_adds_a_candidate_too(engine: AsyncEngine) -> None:
    risky = InMemoryRiskyHistory()
    llm = ScriptedLLM(
        chat_answers=[_tool(1, "send_email", **LEAK_MAIL), ChatResult(content="Sent.")]
    )
    await _run(engine, llm, risky, "email it", extra=DIVERT_RULE)
    record = _one(risky)
    assert record.action == "divert" and record.trace_id
    [candidate] = risky.candidates
    assert candidate.source_event_id == record.event_id and candidate.tool == "send_email"
    assert candidate.canonical_args["body"] == WITHHELD


async def test_blocked_at_the_divert_band_without_a_decoy_is_recorded_as_a_deny(
    engine: AsyncEngine,
) -> None:
    risky = InMemoryRiskyHistory()
    divert_input = INPUT_DENY.model_copy(update={"action": "divert"})
    _, result = await _run(engine, ScriptedLLM(), risky, "forbidden word", extra=divert_input)
    assert result.player_view.status == "blocked"  # M2-DD-43: no decoy for an input
    record = _one(risky)
    assert record.action == "deny" and record.trace_id is None


async def test_the_input_text_sent_to_the_history_never_holds_the_secret(
    engine: AsyncEngine,
) -> None:
    risky = InMemoryRiskyHistory()
    await _run(engine, ScriptedLLM(), risky, f"forbidden word {SECRET}", extra=INPUT_DENY)
    assert _one(risky).input_text == WITHHELD


# --- no record without an enforced bad outcome ---------------------------------------------------


async def test_an_allowed_turn_writes_no_record(engine: AsyncEngine) -> None:
    risky = InMemoryRiskyHistory()
    await _run(engine, ScriptedLLM(chat_answers=[ChatResult(content="Hi.")]), risky)
    assert risky.records == [] and risky.candidates == []


async def test_a_held_turn_writes_no_record(engine: AsyncEngine) -> None:
    risky = InMemoryRiskyHistory()
    _, result = await _run(engine, ScriptedLLM(), risky, AUTHORITY)
    assert result.player_view.status == "awaiting_review"
    assert risky.records == [] and risky.candidates == []


# --- Off: shadow records ------------------------------------------------------------------------


async def test_off_records_a_shadow_deny_for_an_executed_attack(engine: AsyncEngine) -> None:
    risky = InMemoryRiskyHistory()
    llm = ScriptedLLM(
        chat_answers=[_tool(1, "send_email", **LEAK_MAIL), ChatResult(content="Sent.")]
    )
    sid, result = await _run(engine, llm, risky, "email it", mode="off")
    assert result.facts.secret_delivered is True  # the attack worked in Off

    record = _one(risky)  # one record for the check, not one more for tool_executed
    assert (record.action, record.stage, record.tool, record.shadow) == (
        "deny", "tool_call_check", "send_email", True,
    )  # fmt: skip
    assert {"R-003", "B-01"} <= set(record.rule_ids)
    assert risky.candidates == []  # nothing was denied
    [event] = await _rows(
        engine,
        "SELECT event_id, decision, shadow_decision FROM fw_events"
        " WHERE fw_session_id = :s AND stage = 'tool_call_check'",
        s=sid,
    )
    assert (event["decision"], event["shadow_decision"]) == ("allow", "deny")
    assert record.event_id == event["event_id"]


async def test_off_records_a_shadow_divert(engine: AsyncEngine) -> None:
    risky = InMemoryRiskyHistory()
    divert_input = INPUT_DENY.model_copy(update={"action": "divert"})
    await _run(
        engine,
        ScriptedLLM(chat_answers=[ChatResult(content="Hi.")]),
        risky,
        "forbidden word",
        mode="off",
        extra=divert_input,
    )
    record = _one(risky)
    assert (record.action, record.shadow, record.trace_id) == ("divert", True, None)


async def test_off_still_denies_a_malformed_call_and_records_it_for_real(
    engine: AsyncEngine,
) -> None:
    risky = InMemoryRiskyHistory()
    llm = ScriptedLLM(chat_answers=[_tool(1, "delete_everything", path="/")])
    _, result = await _run(engine, llm, risky, "do it", mode="off")
    assert result.player_view.status == "blocked"
    record = _one(risky)
    assert (record.action, record.shadow) == ("deny", False)  # enforced, so not a shadow
    assert risky.candidates == []  # no canonical call to make a pattern from


async def test_off_does_not_break_when_the_shadow_record_fails(engine: AsyncEngine) -> None:
    llm = ScriptedLLM(
        chat_answers=[_tool(1, "send_email", **LEAK_MAIL), ChatResult(content="Sent.")]
    )
    sid, result = await _run(engine, llm, ExplodingRisky(), "email it", mode="off")
    assert result.player_view.status == "replied"  # Off enforces Allow whatever the history does
    [call] = await _rows(engine, "SELECT state FROM fw_tool_calls WHERE fw_session_id = :s", s=sid)
    assert call["state"] == "executed"


async def test_a_retry_after_an_off_attack_adds_no_second_record(engine: AsyncEngine) -> None:
    from app.contracts.firewall import BotUnavailable
    from app.llm.base import LLMError

    risky = InMemoryRiskyHistory()
    sid, owner = await _session(engine, mode="off")
    llm = ScriptedLLM(
        chat_answers=[
            _tool(1, "send_email", **LEAK_MAIL),
            LLMError("down"),
            _tool(2, "send_email", **LEAK_MAIL),
            ChatResult(content="Sent."),
        ]
    )
    with pytest.raises(BotUnavailable):
        await run_message(engine, llm, owner, sid, "m1", "email it", CLIENT, risky=risky)
    await run_message(engine, llm, owner, sid, "m1", "email it", CLIENT, risky=risky)
    assert len(risky.records) == 1  # the replayed call is not recorded twice
    events = await _rows(
        engine,
        "SELECT 1 FROM fw_events WHERE fw_session_id = :s AND stage = 'tool_call_check'",
        s=sid,
    )
    assert len(events) == 1


# --- atomic with the event ----------------------------------------------------------------------


async def test_a_deny_still_lands_when_its_record_fails(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine, extra=INPUT_DENY)
    result = await run_message(
        engine, ScriptedLLM(), owner, sid, "m1", "forbidden word", CLIENT, risky=ExplodingRisky()
    )
    assert result.player_view.status == "blocked"  # the refusal is the safe outcome (M2-DD-55)
    [event] = await _rows(engine, "SELECT decision FROM fw_events WHERE fw_session_id = :s", s=sid)
    assert event["decision"] == "deny"
    [claim] = await _rows(engine, "SELECT status FROM fw_claims WHERE fw_session_id = :s", s=sid)
    assert claim["status"] == "done"
