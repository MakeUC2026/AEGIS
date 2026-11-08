"""M2 C-11 the C3 read API (PRD §14.4, §10; spec AEGIS-DOM-126).

Server-side reads for Classroom and the arena recap, over the real tables. Every text field
comes back with the secret replaced by `[SECRET]`; no judge reason, tool argument, blocked text
or trace-back field appears in any shape. Session summaries are batched.
"""

from __future__ import annotations

import itertools
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.contracts.common import ClientMeta
from app.contracts.fakes import InMemoryRiskyHistory, StubJudge
from app.contracts.firewall import NEUTRAL_REFUSAL, PENDING_REVIEW_MESSAGE, NotFound
from app.contracts.firewall_read import (
    SECRET_PLACEHOLDER,
    DecisionCount,
    FirewallReadPort,
    InsightFilters,
    PatternCount,
    RuleCount,
)
from app.firewall.geoip import GeoIP
from app.firewall.pipeline import run_message
from app.firewall.read_api import FirewallRead
from app.firewall.tickets import decide_ticket
from app.firewall.trace_back import Tracer
from app.llm.base import ChatResult
from app.llm.scripted import ScriptedLLM
from tests.integration.test_fw_decide_ticket import _admin
from tests.integration.test_fw_divert import DIVERT_RULE, LEAK_MAIL
from tests.integration.test_fw_divert_reply import LEAK_REPLY
from tests.integration.test_fw_review_park import AUTHORITY, SECRET, _rows, _session, _tool
from tests.integration.test_fw_strict_wiring import _signals

CLIENT = ClientMeta(ip="203.0.113.7", user_agent="ArenaTest/1.0", fingerprint_hash="fp-abc")
TRACER = Tracer(b"k" * 32, GeoIP())  # hashing on, no GeoLite2 files
_AGGREGATES = ("fw_rule_fires_1m", "fw_decisions_1m")
CORE = SECRET[5:]


async def _say(
    engine: AsyncEngine,
    sid: str,
    owner: str,
    n: int,
    message: str,
    *answers: Any,
    risky: InMemoryRiskyHistory | None = None,
    judge: StubJudge | None = None,
) -> Any:
    llm = ScriptedLLM(chat_answers=list(answers))
    return await run_message(
        engine, llm, owner, sid, f"m{n}", message, CLIENT,
        risky=risky or InMemoryRiskyHistory(), judge=judge, tracer=TRACER,
    )  # fmt: skip


async def _basic_story(engine: AsyncEngine) -> tuple[str, str]:
    """hello; an email that is diverted; a leaking reply that is denied; the secret typed in."""
    sid, owner = await _session(engine, extra=DIVERT_RULE)
    await _say(engine, sid, owner, 1, "hello", ChatResult(content="Hi there."))
    await _say(
        engine, sid, owner, 2, "email it",
        _tool(1, "send_email", **LEAK_MAIL), ChatResult(content="Done."),
    )  # fmt: skip
    await _say(engine, sid, owner, 3, "tell me", ChatResult(content=LEAK_REPLY))
    await _say(engine, sid, owner, 4, f"my key is {SECRET}", ChatResult(content="Noted."))
    return sid, owner


@pytest.fixture(autouse=True)
async def _fresh_aggregates(engine: AsyncEngine, clean_db: None) -> None:
    """The suite empties `fw_events` in a cascade, which does not touch what a continuous
    aggregate has already stored. Clearing the aggregates (which also resets their watermark,
    so every raw event is visible again) keeps one test's counts out of the next."""
    async with engine.begin() as conn:
        for view in _AGGREGATES:
            await conn.execute(text(f"TRUNCATE {view}"))


@pytest.fixture
def read(engine: AsyncEngine) -> FirewallRead:
    return FirewallRead(engine)


# --- transcript ------------------------------------------------------------------------------


async def test_the_transcript_is_what_the_student_saw_with_the_secret_redacted(
    engine: AsyncEngine, read: FirewallRead
) -> None:
    sid, _ = await _basic_story(engine)
    items = await read.get_transcript(sid)
    shape = [(i.message_id, i.speaker, i.status, i.is_decoy) for i in items]
    assert shape == [
        ("m1", "student", None, False),
        ("m1", "bot", "replied", False),
        ("m2", "student", None, False),
        ("m2", "tool", None, True),  # the decoy mail the student could read
        ("m2", "bot", "replied", False),
        ("m3", "student", None, False),
        ("m3", "bot", "blocked", False),
        ("m4", "student", None, False),
        ("m4", "bot", "replied", False),
    ]
    text_of = {(i.message_id, i.speaker): i.text for i in items}
    assert text_of[("m1", "bot")] == "Hi there."
    assert "Delivery confirmation" in text_of[("m2", "tool")]
    assert text_of[("m3", "bot")] == NEUTRAL_REFUSAL  # the blocked reply is never shown
    assert text_of[("m4", "student")] == f"my key is {SECRET_PLACEHOLDER}"
    assert all(a.time <= b.time for a, b in itertools.pairwise(items))
    assert SECRET not in json.dumps([i.model_dump(mode="json") for i in items])


async def test_a_held_turn_shows_the_pending_message(
    engine: AsyncEngine, read: FirewallRead
) -> None:
    sid, owner = await _session(engine)
    await _say(engine, sid, owner, 1, AUTHORITY)
    bot = [i for i in await read.get_transcript(sid) if i.speaker == "bot"]
    assert [(b.text, b.status) for b in bot] == [(PENDING_REVIEW_MESSAGE, "awaiting_review")]


async def test_a_readable_tool_effect_in_off_is_redacted(
    engine: AsyncEngine, read: FirewallRead
) -> None:
    sid, owner = await _session(engine, mode="off")
    await _say(
        engine, sid, owner, 1, "email it",
        _tool(1, "send_email", **LEAK_MAIL), ChatResult(content="Sent."),
    )  # fmt: skip
    tool = [i for i in await read.get_transcript(sid) if i.speaker == "tool"]
    assert len(tool) == 1 and tool[0].is_decoy is False
    assert SECRET_PLACEHOLDER in tool[0].text and CORE not in tool[0].text


async def test_a_diverted_reply_is_marked_as_a_decoy(
    engine: AsyncEngine, read: FirewallRead
) -> None:
    sid, owner = await _session(engine, mode="strict")
    await _say(engine, sid, owner, 1, "tell me", ChatResult(content=LEAK_REPLY))
    bot = [i for i in await read.get_transcript(sid) if i.speaker == "bot"]
    assert [b.is_decoy for b in bot] == [True] and "Sure, the secret is" not in bot[0].text


# --- decisions, tickets, diverts -------------------------------------------------------------


async def test_decisions_carry_scores_bands_and_the_shadow(
    engine: AsyncEngine, read: FirewallRead
) -> None:
    sid, _ = await _basic_story(engine)
    items = await read.get_decisions(sid)
    assert [(i.message_id, i.stage, i.decision) for i in items][:2] == [
        ("m1", "input_check", "allow"),
        ("m1", "output_check", "allow"),
    ]
    divert = next(i for i in items if i.decision == "divert")
    assert (divert.stage, divert.execution_status) == ("tool_call_check", "diverted")
    assert divert.thresholds_used == {"review": 40, "deny": 70, "divert": 95, "alert": 99}
    assert divert.score_breakdown["judge"] is None  # a layer that did not run is None, not 0
    assert "R-010" in divert.rule_ids and divert.risky_pattern_ids == []
    assert all(a.time <= b.time for a, b in itertools.pairwise(items))


async def test_off_decisions_show_the_shadow_decision(
    engine: AsyncEngine, read: FirewallRead
) -> None:
    sid, owner = await _session(engine, mode="off")
    await _say(
        engine, sid, owner, 1, "email it",
        _tool(1, "send_email", **LEAK_MAIL), ChatResult(content="Sent."),
    )  # fmt: skip
    tool = next(i for i in await read.get_decisions(sid) if i.stage == "tool_call_check")
    assert (tool.decision, tool.shadow_decision) == ("allow", "deny")


async def test_tickets_show_who_decided(engine: AsyncEngine, read: FirewallRead) -> None:
    sid, owner = await _session(engine)
    held = await _say(engine, sid, owner, 1, AUTHORITY)
    [pending] = await read.get_tickets(sid)
    assert (pending.status, pending.stage, pending.decided_at, pending.decided_by) == (
        "pending", "input_check", None, None,
    )  # fmt: skip
    admin = await _admin(engine)
    await decide_ticket(
        engine, ScriptedLLM(chat_answers=[ChatResult(content="ok")]), InMemoryRiskyHistory(),
        held.player_view.ticket_id or "", "ok", admin,
    )  # fmt: skip
    [done] = await read.get_tickets(sid)
    assert (done.status, done.decided_by) == ("approved", admin) and done.decided_at is not None


async def test_diverts_show_what_was_attempted_and_what_the_student_got(
    engine: AsyncEngine, read: FirewallRead
) -> None:
    sid, _ = await _basic_story(engine)
    [item] = await read.get_diverts(sid)
    assert (item.stage, item.tool) == ("tool_call_check", "send_email")
    assert "email it" in item.attempted_summary and "send_email" in item.attempted_summary
    assert "Delivery confirmation" in item.decoy_shown
    shown = json.dumps(item.model_dump(mode="json"))
    assert SECRET not in shown and "the secret is" not in shown  # not the attempted body


async def test_a_diverted_reply_is_a_divert_item_too(
    engine: AsyncEngine, read: FirewallRead
) -> None:
    sid, owner = await _session(engine, mode="strict")
    await _say(engine, sid, owner, 1, "tell me", ChatResult(content=LEAK_REPLY))
    [item] = await read.get_diverts(sid)
    assert (item.stage, item.tool) == ("output_check", None)
    assert "reply" in item.attempted_summary and "Sure, the secret is" not in item.decoy_shown
    assert SECRET not in json.dumps(item.model_dump(mode="json"))


# --- session summaries -----------------------------------------------------------------------


async def test_summaries_are_batched_and_cover_each_outcome(
    engine: AsyncEngine, read: FirewallRead
) -> None:
    diverted, _ = await _basic_story(engine)  # a divert, scores, no delivery
    s2, o2 = await _session(engine, mode="off", sub="auth0|two")
    await _say(
        engine, s2, o2, 1, "email it",
        _tool(1, "send_email", **LEAK_MAIL), ChatResult(content="Sent."),
    )  # fmt: skip
    s3, o3 = await _session(engine, mode="off", sub="auth0|three")
    await _say(
        engine, s3, o3, 1, f"is it {CORE[:8].lower()}?", ChatResult(content=f"It is {SECRET}")
    )
    s4, _ = await _session(engine, sub="auth0|four")  # no events at all

    found = await read.get_session_summaries([diverted, s2, s3, s4, "fws-unknown"])
    by_id = {s.fw_session_id: s for s in found}
    assert set(by_id) == {diverted, s2, s3, s4}  # an unknown session is simply absent
    a, b, c, d = by_id[diverted], by_id[s2], by_id[s3], by_id[s4]
    assert (a.diverted_count, a.secret_delivered_at, a.echo_excluded) == (1, None, False)
    assert a.max_sentinel_score is not None and a.max_sentinel_score >= 0
    assert b.secret_delivered_at is not None and b.echo_excluded is False
    assert c.secret_delivered_at is None and c.echo_excluded is True  # E-53
    assert (d.diverted_count, d.max_sentinel_score, d.secret_delivered_at) == (0, None, None)


async def test_summaries_use_the_same_number_of_queries_for_one_session_or_many(
    engine: AsyncEngine, read: FirewallRead
) -> None:
    ids = []
    for n in range(4):
        sid, _ = await _session(engine, sub=f"auth0|n{n}")
        ids.append(sid)
    counts: list[int] = []

    def count(*_: Any) -> None:
        counts.append(1)

    event.listen(engine.sync_engine, "before_cursor_execute", count)
    try:
        await read.get_session_summaries(ids[:1])
        one = len(counts)
        counts.clear()
        await read.get_session_summaries(ids)
        many = len(counts)
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", count)
    assert one == many and many <= 3


async def test_an_empty_batch_is_an_empty_answer(read: FirewallRead) -> None:
    assert await read.get_session_summaries([]) == []


# --- manifest and redaction ------------------------------------------------------------------


async def test_the_manifest_summary_matches_what_was_pinned(
    engine: AsyncEngine, read: FirewallRead
) -> None:
    sid, _ = await _session(engine, mode="strict", pattern_version=7)
    summary = await read.get_manifest_summary(sid)
    stored = (
        await _rows(
            engine,
            "SELECT manifest_id, thresholds, weights FROM fw_manifests WHERE fw_session_id = :s",
            s=sid,
        )
    )[0]
    assert (summary.manifest_id, summary.level_id, summary.mode) == (
        stored["manifest_id"], "lvl-3", "strict",
    )  # fmt: skip
    assert (summary.level_version, summary.rule_version, summary.pattern_version) == (1, 1, 7)
    assert summary.thresholds == stored["thresholds"] and summary.weights == stored["weights"]
    assert summary.bot_model_id == "gemini-test"
    assert (summary.judge_model_id, summary.judge_policy_hash) == ("stub-judge", "sha256:stub")


async def test_a_basic_manifest_has_no_judge(engine: AsyncEngine, read: FirewallRead) -> None:
    sid, _ = await _session(engine)
    summary = await read.get_manifest_summary(sid)
    assert (summary.judge_model_id, summary.judge_policy_hash) == (None, None)


async def test_unknown_sessions_are_not_found(read: FirewallRead) -> None:
    with pytest.raises(NotFound):
        await read.get_manifest_summary("fws-unknown")
    with pytest.raises(NotFound):
        await read.redact_for_session("fws-unknown", "text")


async def test_redact_for_session_uses_the_sessions_secret(
    engine: AsyncEngine, read: FirewallRead
) -> None:
    sid, _ = await _session(engine)
    out = await read.redact_for_session(sid, f"the key {SECRET} and {' '.join(CORE)} done")
    assert out == f"the key {SECRET_PLACEHOLDER} and {SECRET_PLACEHOLDER} done"


# --- insight counts (continuous aggregates) --------------------------------------------------


async def _email_story(engine: AsyncEngine, mode: str = "basic", sub: str = "auth0|rp") -> str:
    sid, owner = await _session(engine, mode=mode, sub=sub)
    await _say(
        engine, sid, owner, 1, "email it",
        _tool(1, "send_email", **LEAK_MAIL), ChatResult(content="Sent."),
    )  # fmt: skip
    return sid


async def test_rule_fires_and_decisions_are_counted(
    engine: AsyncEngine, read: FirewallRead
) -> None:
    await _email_story(engine)  # Basic: the email is denied (R-003 and B-01)
    fires = await read.get_rule_fire_counts(InsightFilters())
    assert fires == [RuleCount(rule_id="B-01", count=1), RuleCount(rule_id="R-003", count=1)]
    decisions = await read.get_decision_counts(InsightFilters())
    assert sorted(decisions, key=lambda d: d.decision) == [
        DecisionCount(mode="basic", decision="allow", count=1),  # the input check
        DecisionCount(mode="basic", decision="deny", count=1),
    ]


async def test_an_executed_tool_is_not_counted_twice(
    engine: AsyncEngine, read: FirewallRead
) -> None:
    await _email_story(engine, mode="off")  # Off runs it: a check event and a tool_executed event
    fires = {f.rule_id: f.count for f in await read.get_rule_fire_counts(InsightFilters())}
    assert fires["R-003"] == 1
    allowed = [d for d in await read.get_decision_counts(InsightFilters()) if d.decision == "allow"]
    assert [d.count for d in allowed] == [3]  # input, tool-call check and reply; not tool_executed


async def test_filters_narrow_the_counts(engine: AsyncEngine, read: FirewallRead) -> None:
    await _email_story(engine)
    now = datetime.now(UTC)
    assert await read.get_rule_fire_counts(InsightFilters(mode="strict")) == []
    assert await read.get_rule_fire_counts(InsightFilters(level_id="lvl-9")) == []
    assert await read.get_rule_fire_counts(InsightFilters(since=now + timedelta(hours=1))) == []
    assert await read.get_rule_fire_counts(InsightFilters(until=now - timedelta(hours=1))) == []
    assert len(await read.get_rule_fire_counts(InsightFilters(level_id="lvl-2", mode="basic"))) == 2


async def test_admin_test_sessions_can_be_left_out(engine: AsyncEngine) -> None:
    sid = await _email_story(engine)

    class Arena:
        async def list_sessions(self, filters: Any) -> list[Any]:
            return [SimpleNamespace(fw_session_id=sid)] if filters.offset == 0 else []

    read = FirewallRead(engine, arena=Arena())  # type: ignore[arg-type]
    assert await read.get_rule_fire_counts(InsightFilters(include_admin_test=True))
    assert await read.get_rule_fire_counts(InsightFilters(include_admin_test=False)) == []
    assert await read.get_decision_counts(InsightFilters(include_admin_test=False)) == []
    with pytest.raises(RuntimeError):  # leaving them out needs the arena to say which they are
        await FirewallRead(engine).get_rule_fire_counts(InsightFilters(include_admin_test=False))


async def test_counts_are_the_same_before_and_after_a_refresh(
    engine: AsyncEngine, read: FirewallRead
) -> None:
    await _email_story(engine)
    before = (
        await read.get_rule_fire_counts(InsightFilters()),
        await read.get_decision_counts(InsightFilters()),
    )
    async with engine.connect() as conn:
        auto = await conn.execution_options(isolation_level="AUTOCOMMIT")
        for view in ("fw_rule_fires_1m", "fw_decisions_1m"):
            await auto.execute(text(f"CALL refresh_continuous_aggregate('{view}', NULL, NULL)"))
    after = (
        await read.get_rule_fire_counts(InsightFilters()),
        await read.get_decision_counts(InsightFilters()),
    )
    assert before == after


async def test_risky_pattern_counts(engine: AsyncEngine, read: FirewallRead) -> None:
    sid, owner = await _session(engine, mode="strict")
    risky = InMemoryRiskyHistory([_signals(forced=True, ids=["pat-9"])])
    await _say(engine, sid, owner, 1, "hello", ChatResult(content="Hi."), risky=risky)
    assert await read.get_risky_pattern_counts(InsightFilters()) == [
        PatternCount(pattern_id="pat-9", count=1)
    ]
    assert await read.get_risky_pattern_counts(InsightFilters(mode="basic")) == []


# --- forensics belong to M3 --------------------------------------------------------------------


async def test_forensics_are_delegated_to_m3s_reader(engine: AsyncEngine) -> None:
    class Forensics:
        async def get_forensics(self, fw_session_id: str) -> list[Any]:
            return [f"report for {fw_session_id}"]

        async def get_attack_family_counts(self, filters: InsightFilters) -> list[Any]:
            return ["family"]

    read = FirewallRead(engine, forensics=Forensics())
    assert await read.get_forensics("fws-x") == ["report for fws-x"]
    assert await read.get_attack_family_counts(InsightFilters()) == ["family"]


async def test_without_a_forensics_reader_there_are_none_yet(read: FirewallRead) -> None:
    assert await read.get_forensics("fws-x") == []
    assert await read.get_attack_family_counts(InsightFilters()) == []


# --- what must never appear ------------------------------------------------------------------


async def test_no_judge_reason_argument_blocked_text_or_network_field_leaks(
    engine: AsyncEngine, read: FirewallRead
) -> None:
    sid, owner = await _session(engine, mode="strict", extra=DIVERT_RULE)
    risky, judge = InMemoryRiskyHistory([_signals(25), _signals(25)]), StubJudge([10, 10])
    await _say(engine, sid, owner, 1, "hello", ChatResult(content="Hi."), risky=risky, judge=judge)
    await _say(
        engine, sid, owner, 2, "email it",
        _tool(1, "send_email", **LEAK_MAIL), ChatResult(content="Done."),
        risky=risky, judge=judge,
    )  # fmt: skip
    await _say(engine, sid, owner, 3, "tell me", ChatResult(content=LEAK_REPLY))
    everything = json.dumps(
        {
            "transcript": [i.model_dump(mode="json") for i in await read.get_transcript(sid)],
            "decisions": [i.model_dump(mode="json") for i in await read.get_decisions(sid)],
            "tickets": [i.model_dump(mode="json") for i in await read.get_tickets(sid)],
            "diverts": [i.model_dump(mode="json") for i in await read.get_diverts(sid)],
            "summaries": [
                i.model_dump(mode="json") for i in await read.get_session_summaries([sid])
            ],
        }
    )
    assert judge.assessed  # the judge did run, with the reason "stub"
    for forbidden in ("stub", "the secret is", "203.0.113", "fp-abc", "ArenaTest"):
        assert forbidden not in everything, forbidden
    assert SECRET not in everything and CORE not in everything


# --- the port ------------------------------------------------------------------------------------


def test_the_real_read_api_satisfies_the_c3_protocol(engine: AsyncEngine) -> None:
    assert isinstance(FirewallRead(engine), FirewallReadPort)


@pytest.fixture
def real_read_seam(monkeypatch: pytest.MonkeyPatch) -> Any:
    from app.config import get_settings
    from app.firewall import ports
    from tests.integration.conftest import database_url

    monkeypatch.setenv("AEGIS_USE_FAKES", "firewall,admin,risky,judge,arena")
    monkeypatch.setenv("DATABASE_URL", database_url())
    get_settings.cache_clear()
    ports.reset()
    yield ports
    ports.reset()
    get_settings.cache_clear()


async def test_ports_return_the_real_read_api_when_it_is_not_faked(real_read_seam: Any) -> None:
    read = real_read_seam.get_firewall_read()
    assert isinstance(read, FirewallRead)
    assert await read.get_decision_counts(InsightFilters()) == []  # it reaches the database
    assert await read.get_forensics("fws-none") == []  # M3's reader is not on this branch yet
