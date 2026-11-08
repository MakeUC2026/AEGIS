"""M2 C-08 Strict wiring: risky history and the judge (PRD §7.2, §7.3, §18.2; spec AEGIS-DOM-123).

Strict looks up the user's risky history for every checked item and asks the judge only when
layers 1 + 2 reach 20 (`judge_needed`). The judge can only raise the score; a judge error, a
timeout (8 s) or an unusable answer raises it to at least the Deny band; a history error is
Deny. Off reads history in shadow and has the judge off by default; Basic uses neither. The
judge's reason and the per-layer latency are stored on the event, never in the turn result.
Nothing sent to a model holds the secret.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from app.contracts.common import ClientMeta
from app.contracts.fakes import InMemoryRiskyHistory, StubJudge
from app.contracts.sentinel import (
    CheckedItem,
    JudgeError,
    JudgeTimeout,
    JudgeVerdict,
    RiskyHistoryError,
    RiskyHistorySignals,
)
from app.firewall import sentinel
from app.firewall.leak import secret_core
from app.firewall.pipeline import run_message
from app.llm.base import ChatResult
from app.llm.scripted import ScriptedLLM
from tests.integration.test_fw_review_park import SECRET, _rows, _session, _tool

CLIENT = ClientMeta()


def _signals(points: int = 0, forced: bool = False, ids: list[str] | None = None) -> Any:
    return RiskyHistorySignals(
        forced_deny=forced,
        matched_pattern_ids=ids or [],
        user_tool_events_points=points,
        prior_divert_points=0,
        similarity_points=0,
        similarity_top=None,
        latency_ms=1,
    )


class SlowJudge(StubJudge):
    async def assess(self, item: CheckedItem) -> JudgeVerdict:
        await asyncio.sleep(5)
        return await super().assess(item)


async def _turn(
    engine: AsyncEngine,
    mode: str,
    llm: ScriptedLLM,
    risky: InMemoryRiskyHistory,
    judge: StubJudge,
    text: str = "hello",
    pattern_version: int = 0,
    **kw: Any,
) -> tuple[str, Any]:
    sid, owner = await _session(engine, mode=mode, pattern_version=pattern_version)
    result = await run_message(
        engine, llm, owner, sid, "m1", text, CLIENT, risky=risky, judge=judge, **kw
    )
    return sid, result


def _answer(text: str = "Hi.") -> ScriptedLLM:
    return ScriptedLLM(chat_answers=[ChatResult(content=text)])


# --- when each port is used -------------------------------------------------------------------


async def test_strict_looks_up_history_for_every_checked_item(engine: AsyncEngine) -> None:
    risky, judge = InMemoryRiskyHistory(), StubJudge()
    llm = ScriptedLLM(
        chat_answers=[_tool(1, "search_docs", query="faq"), ChatResult(content="Found it.")]
    )
    sid, result = await _turn(engine, "strict", llm, risky, judge, "find the faq", 7)

    assert result.player_view.status == "replied"
    assert [i.stage for i in risky.lookups] == ["input_check", "tool_call_check", "output_check"]
    first, tool_item, last = risky.lookups
    assert (first.mode, first.fw_session_id, first.pattern_version) == ("strict", sid, 7)
    assert first.text == "find the faq" and first.tool is None
    assert (tool_item.tool, tool_item.canonical_args) == ("search_docs", {"query": "faq"})
    assert tool_item.args_hash and last.text == "found it."  # normalized text under check
    ids = await _rows(
        engine,
        "SELECT event_id FROM fw_events WHERE fw_session_id = :s AND stage <> 'tool_executed'",
        s=sid,
    )
    assert {i.event_id for i in risky.lookups} == {r["event_id"] for r in ids}
    assert judge.assessed == []  # nothing reached 20


async def test_basic_uses_neither_port(engine: AsyncEngine) -> None:
    risky, judge = InMemoryRiskyHistory([_signals(30)] * 3), StubJudge()
    await _turn(engine, "basic", _answer(), risky, judge)
    assert risky.lookups == [] and judge.assessed == []


async def test_off_reads_history_in_shadow_and_leaves_the_judge_off(engine: AsyncEngine) -> None:
    risky, judge = InMemoryRiskyHistory([_signals(forced=True, ids=["p-1"])]), StubJudge([90])
    sid, result = await _turn(engine, "off", _answer(), risky, judge)

    assert result.player_view.status == "replied"  # Off enforces Allow
    assert len(risky.lookups) == 2 and judge.assessed == []
    [event] = await _rows(
        engine,
        "SELECT decision, shadow_decision, risky_pattern_ids_matched FROM fw_events"
        " WHERE fw_session_id = :s AND stage = 'input_check'",
        s=sid,
    )
    assert (event["decision"], event["shadow_decision"]) == ("allow", "deny")
    assert event["risky_pattern_ids_matched"] == ["p-1"]


async def test_the_judge_can_be_switched_on_for_off(engine: AsyncEngine) -> None:
    judge = StubJudge([10])
    await _turn(
        engine, "off", _answer(), InMemoryRiskyHistory([_signals(25)]), judge, judge_in_off=True
    )
    assert len(judge.assessed) == 1


# --- the judge threshold ---------------------------------------------------------------------


@pytest.mark.parametrize(("points", "asked"), [(19, 0), (20, 1)])
async def test_the_judge_runs_only_from_a_layer_1_2_score_of_20(
    engine: AsyncEngine, points: int, asked: int
) -> None:
    judge = StubJudge()
    await _turn(engine, "strict", _answer(), InMemoryRiskyHistory([_signals(points)]), judge)
    assert len(judge.assessed) == asked


async def test_the_judge_sees_a_delimited_untrusted_excerpt(engine: AsyncEngine) -> None:
    judge = StubJudge()
    await _turn(engine, "strict", _answer(), InMemoryRiskyHistory([_signals(25)]), judge, "Hello!")
    [item] = judge.assessed
    assert item.stage == "input_check" and item.text == "hello!"
    assert item.layer1_score == 0 and item.user_id and item.manifest_id
    assert "untrusted" in item.context_excerpt


# --- the judge can only raise ----------------------------------------------------------------


async def test_a_high_judge_risk_raises_the_decision_and_is_stored(engine: AsyncEngine) -> None:
    judge = StubJudge([65])
    risky = InMemoryRiskyHistory([_signals(25)])
    sid, result = await _turn(engine, "strict", _answer(), risky, judge)

    assert result.player_view.status == "blocked"  # 65 is in the Strict Deny band
    assert "stub" not in json.dumps(result.model_dump(mode="json"))  # reasons never reach C2
    [event] = await _rows(
        engine,
        "SELECT sentinel_score, judge_risk, judge_reason, latency_ms, decision FROM fw_events"
        " WHERE fw_session_id = :s AND stage = 'input_check'",
        s=sid,
    )
    assert (event["sentinel_score"], event["judge_risk"], event["decision"]) == (65, 65, "deny")
    assert event["judge_reason"] == "stub"
    assert {"rules", "history", "judge"} <= set(event["latency_ms"])


async def test_a_low_judge_risk_never_lowers_the_score(engine: AsyncEngine) -> None:
    sid, _ = await _turn(
        engine, "strict", _answer(), InMemoryRiskyHistory([_signals(25)]), StubJudge([3])
    )
    [event] = await _rows(
        engine,
        "SELECT sentinel_score, judge_risk FROM fw_events"
        " WHERE fw_session_id = :s AND stage = 'input_check'",
        s=sid,
    )
    assert (event["sentinel_score"], event["judge_risk"]) == (25, 3)  # E-52


async def test_latency_without_a_judge_has_no_judge_entry(engine: AsyncEngine) -> None:
    sid, _ = await _turn(engine, "strict", _answer(), InMemoryRiskyHistory(), StubJudge())
    [event] = await _rows(
        engine,
        "SELECT judge_risk, judge_reason, latency_ms FROM fw_events"
        " WHERE fw_session_id = :s AND stage = 'input_check'",
        s=sid,
    )
    assert (event["judge_risk"], event["judge_reason"]) == (None, None)  # the layer did not run
    assert set(event["latency_ms"]) == {"rules", "history"}


# --- fail closed -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "error", [JudgeTimeout("slow"), JudgeError("unparseable"), RuntimeError("boom")]
)
async def test_a_judge_failure_is_at_least_the_deny_band(
    engine: AsyncEngine, error: Exception
) -> None:
    sid, result = await _turn(
        engine,
        "strict",
        _answer(),
        InMemoryRiskyHistory([_signals(25)]),
        StubJudge(errors=[error]),
    )
    assert result.player_view.status == "blocked"
    [event] = await _rows(
        engine,
        "SELECT sentinel_score, judge_risk, decision FROM fw_events"
        " WHERE fw_session_id = :s AND stage = 'input_check'",
        s=sid,
    )
    assert event["sentinel_score"] >= 60 and event["decision"] == "deny"
    assert event["judge_risk"] is None  # no verdict to record


async def test_a_judge_that_takes_too_long_is_a_failure(
    engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sentinel, "JUDGE_TIMEOUT_S", 0.05)  # the real limit is 8 s
    _, result = await _turn(
        engine, "strict", _answer(), InMemoryRiskyHistory([_signals(25)]), SlowJudge()
    )
    assert result.player_view.status == "blocked"


async def test_a_history_error_is_deny_and_skips_the_judge(engine: AsyncEngine) -> None:
    judge = StubJudge()
    risky = InMemoryRiskyHistory([RiskyHistoryError("db down")])
    _, result = await _turn(engine, "strict", _answer(), risky, judge)
    assert result.player_view.status == "blocked" and judge.assessed == []


async def test_an_approved_pattern_forces_deny(engine: AsyncEngine) -> None:
    risky = InMemoryRiskyHistory([_signals(forced=True, ids=["pat-9"])])
    sid, result = await _turn(engine, "strict", _answer(), risky, StubJudge())
    assert result.player_view.status == "blocked"
    [event] = await _rows(
        engine,
        "SELECT risky_pattern_ids_matched FROM fw_events"
        " WHERE fw_session_id = :s AND stage = 'input_check'",
        s=sid,
    )
    assert event["risky_pattern_ids_matched"] == ["pat-9"]


# --- a diverted turn is not re-scored by its own divert ----------------------------------------


async def test_the_rest_of_a_diverted_turn_ignores_its_own_divert_and_record(
    engine: AsyncEngine,
) -> None:
    from app.arena.scenario_data import ATTACKER_MAILBOX
    from app.contracts.firewall_admin import RuleForm

    divert = RuleForm(
        applies_on="bot_tool_call", checks="named_argument", argument_name="to",
        operator="domain_not_in", value=["company.example"], action="divert", note="outside mail",
    )  # fmt: skip
    own_record = RiskyHistorySignals(
        forced_deny=False,
        matched_pattern_ids=[],
        user_tool_events_points=0,
        prior_divert_points=20,
        similarity_points=25,
        similarity_top=1.0,
        latency_ms=1,
    )  # what the real history says once the divert's own row exists
    risky = InMemoryRiskyHistory([_signals(0), _signals(0), own_record])
    sid, owner = await _session(engine, mode="strict", extra=divert)
    llm = ScriptedLLM(
        chat_answers=[
            _tool(1, "send_email", to=ATTACKER_MAILBOX, subject="s", body="b"),
            ChatResult(content="Done."),
        ]
    )
    result = await run_message(
        engine, llm, owner, sid, "m1", "email it", CLIENT, risky=risky, judge=StubJudge()
    )
    assert result.facts.diverted is True and result.player_view.status == "replied"
    [reply_check] = await _rows(
        engine,
        "SELECT sentinel_score, score_breakdown FROM fw_events"
        " WHERE fw_session_id = :s AND stage = 'output_check'",
        s=sid,
    )
    breakdown = reply_check["score_breakdown"]
    assert reply_check["sentinel_score"] == 0
    assert (breakdown["prior_divert"], breakdown["similarity"]) == (0, 0)


# --- the secret never goes to a model --------------------------------------------------------


async def test_a_secret_in_the_message_never_reaches_the_judge(engine: AsyncEngine) -> None:
    judge, risky = StubJudge(), InMemoryRiskyHistory([_signals(25)])
    await _turn(engine, "strict", _answer(), risky, judge, f"my key is {SECRET}, is it valid?")
    [item] = judge.assessed
    shown = json.dumps(item.model_dump(mode="json")).lower()
    assert secret_core(SECRET).lower() not in shown and SECRET.lower() not in shown
    lookup_text = risky.lookups[0].text.lower()  # the similarity query may call an embedder
    assert secret_core(SECRET).lower() not in lookup_text
