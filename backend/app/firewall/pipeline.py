"""One student turn, end to end (M2 B-08; PRD §7.1, §8.1, §8.2, §15.1; spec AEGIS-DOM-112).

claim -> input check -> bot runner (tool-call check before each tool; each allowed tool runs
with its two events in one transaction) -> output check -> one final transaction (remaining
events, conversation rows, claim result). A bot failure or any error releases the claim and
re-raises, so the arena can retry the same message ID; call IDs are deterministic
(`<message_id>-r<round>-c<n>`), so a retry never runs a tool twice.

Temporary until Phase C: a Review (C-01) or Divert (C-05) decision fails closed (blocked).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.contracts.common import ClientMeta, ExecutionStatus, Stage
from app.contracts.firewall import PlayerStatus, ToolEffect, TurnResult
from app.firewall.bot_runner import BotTurn, ToolStep, run_turn
from app.firewall.checks import Checked, check_input, check_output, check_tool_call
from app.firewall.claims import claim_message, complete_claim, release_claim
from app.firewall.context import TurnContext, load_context
from app.firewall.events import EventRow, SourceTrust, insert_event, row_from_decision
from app.firewall.leak import echo_excluded, scan_cumulative
from app.firewall.limits import check_text
from app.firewall.textnorm import storable
from app.firewall.tool_exec import execute_tool
from app.firewall.views import turn_result
from app.llm.base import ChatMessage, ChatModel, ToolCall

Clock = Callable[[], datetime]

_CONVERSATION = (
    "INSERT INTO fw_conversation (fw_session_id, seq, message_id, role, content, visible,"
    " call_id, tool, model_payload) VALUES (:sid, :seq, :mid, :role, :content, :visible,"
    " :call_id, :tool, CAST(:payload AS jsonb))"
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class _Turn:
    """Accumulates one turn's outcome; local to `_run` and never shared."""

    ctx: TurnContext
    message_id: str
    checks: list[Checked] = field(default_factory=list)
    later_events: list[EventRow] = field(default_factory=list)
    effects: list[ToolEffect] = field(default_factory=list)
    tool_results: list[str] = field(default_factory=list)
    visible_new: list[str] = field(default_factory=list)
    visible_by_call: dict[str, str] = field(default_factory=dict)
    calls_made: int = 0


def _event(
    turn: _Turn,
    checked: Checked,
    execution_status: ExecutionStatus,
    stage: Stage | None = None,
    source_trust: SourceTrust | None = None,
) -> EventRow:
    ctx = turn.ctx
    call = checked.call
    row = row_from_decision(
        checked.gate,
        ctx.thresholds,
        fw_session_id=ctx.fw_session_id,
        user_id=ctx.owner_ref,
        message_id=turn.message_id,
        manifest_id=ctx.manifest_id,
        level_id=ctx.level_id,
        mode=ctx.mode,
        stage=stage or checked.stage,
        source_trust=source_trust or checked.source_trust,
        execution_status=execution_status,
        tool=checked.tool,
        call_id=checked.call_id,
        args_hash=call.args_hash if call else None,
        secret_attempted=checked.leak is not None,
    )
    if stage == "tool_executed":  # the shadow belongs to the check, so forensics flags once
        return replace(row, shadow_decision=None, secret_attempted=False)
    return row


def _tool_hook(engine: AsyncEngine, turn: _Turn, clock: Clock) -> Callable[..., Any]:
    async def on_tool_call(call: ToolCall, round_index: int) -> ToolStep:
        call_id = f"{turn.message_id}-r{round_index}-c{turn.calls_made}"
        turn.calls_made += 1
        seen = (*turn.ctx.visible_output, *turn.visible_new)
        checked = check_tool_call(turn.ctx, call, call_id, turn.tool_results, clock(), seen)
        turn.checks.append(checked)
        tool = storable(call.name)
        if not checked.allowed or checked.call is None:
            turn.effects.append(
                ToolEffect(call_id=call_id, tool=tool, state="blocked", visible_content=None)
            )
            turn.later_events.append(_event(turn, checked, "not_executed"))
            return ToolStep.stop()
        async with engine.begin() as conn:
            executed = await execute_tool(
                conn, turn.ctx.fw_session_id, turn.message_id, checked.call
            )
            if executed.call_id != call_id:  # a retry whose call differs from the recorded one
                checked = replace(checked, call_id=executed.call_id)
                call_id = executed.call_id
            await insert_event(conn, _event(turn, checked, "executed"))
            await insert_event(
                conn, _event(turn, checked, "executed", "tool_executed", "tool_result")
            )
        limited = check_text("tool_result", executed.result, turn.ctx.mode)
        turn.effects.append(
            ToolEffect(
                call_id=call_id,
                tool=tool,
                state="executed",
                visible_content=executed.visible_content,
            )
        )
        if executed.visible_content:
            turn.visible_new.append(executed.visible_content)
            turn.visible_by_call[call.id] = executed.visible_content
        if limited.action == "deny":  # an oversized tool result never reaches the bot
            return ToolStep.stop()
        turn.tool_results.append(limited.text)
        return ToolStep.result(limited.text)

    return on_tool_call


def _delivered(turn: _Turn, message: str) -> bool:
    if not turn.visible_new:
        return False
    ctx = turn.ctx
    leak = scan_cumulative(ctx.visible_output, "\n".join(turn.visible_new), ctx.secret)
    typed = (*ctx.student_inputs, message)
    return leak is not None and not leak.partial and not echo_excluded(typed, ctx.secret)


def _rows(turn: _Turn, message: str, bot: BotTurn | None, replied: bool) -> list[dict[str, Any]]:
    base = {"sid": turn.ctx.fw_session_id, "mid": turn.message_id, "tool": None}
    rows = [
        {
            **base,
            "role": "student",
            "content": message,
            "visible": False,
            "call_id": None,
            "payload": {"in_history": replied},
        }
    ]
    for msg in bot.new_messages if bot else ():
        rows.append({**base, **_row_for(msg, turn, replied)})
    return [  # model text can hold NUL or lone surrogates; Postgres stores neither
        {
            **r,
            "seq": turn.ctx.next_seq + i,
            "content": storable(r["content"]),
            "payload": json.dumps(storable(r["payload"])),
        }
        for i, r in enumerate(rows)
    ]


def _row_for(msg: ChatMessage, turn: _Turn, replied: bool) -> dict[str, Any]:
    if msg.role == "tool":
        visible = turn.visible_by_call.get(msg.tool_call_id or "")
        return {
            "role": "tool_result",
            "content": msg.content or "",
            "visible": bool(visible),
            "call_id": msg.tool_call_id,
            "payload": {"in_history": replied, "visible": visible},
        }
    if msg.tool_calls:
        calls = [c.model_dump(mode="json") for c in msg.tool_calls]
        return {
            "role": "tool_call",
            "content": msg.content or "",
            "visible": False,
            "call_id": None,
            "payload": {"in_history": replied, "tool_calls": calls},
        }
    return {
        "role": "bot",
        "content": msg.content or "",
        "visible": replied,
        "call_id": None,
        "payload": {"in_history": replied},
    }


async def _finish(
    engine: AsyncEngine,
    turn: _Turn,
    message: str,
    bot: BotTurn | None,
    status: PlayerStatus,
    reply: str | None,
) -> TurnResult:
    if status == "replied" and reply:
        turn.visible_new.append(reply)
    delivered = _delivered(turn, message)
    events = list(turn.later_events)
    if events and delivered:
        events[-1] = replace(events[-1], secret_delivered=True)
    result = turn_result(status, reply, turn.effects, turn.checks, delivered)
    async with engine.begin() as conn:
        await _commit(conn, turn, events, _rows(turn, message, bot, status == "replied"), result)
    return result


async def _commit(
    conn: AsyncConnection,
    turn: _Turn,
    events: list[EventRow],
    rows: list[dict[str, Any]],
    result: TurnResult,
) -> None:
    for event in events:
        await insert_event(conn, event)
    for row in rows:
        await conn.execute(text(_CONVERSATION), row)
    await complete_claim(conn, turn.ctx.fw_session_id, turn.message_id, result)


async def _run(
    engine: AsyncEngine, llm: ChatModel, sid: str, message_id: str, message: str, clock: Clock
) -> TurnResult:
    turn = _Turn(ctx=await load_context(engine, sid), message_id=message_id)
    checked_input = check_input(turn.ctx, message, clock())
    turn.checks.append(checked_input)
    turn.later_events.append(
        _event(turn, checked_input, "executed" if checked_input.allowed else "not_executed")
    )
    if not checked_input.allowed:  # deny, or review/divert until Phase C (fail closed)
        return await _finish(engine, turn, message, None, "blocked", None)
    ctx = turn.ctx
    bot = await run_turn(
        llm,
        ctx.bot_model_id,
        ctx.system_prompt,
        ctx.history,
        checked_input.text,
        ctx.tools,
        _tool_hook(engine, turn, clock),
    )
    if bot.stopped or bot.reply is None:
        return await _finish(engine, turn, message, bot, "blocked", None)
    seen = (*ctx.visible_output, *turn.visible_new)
    checked_output = check_output(ctx, bot.reply, seen, clock())
    turn.checks.append(checked_output)
    allowed = checked_output.allowed
    turn.later_events.append(
        _event(turn, checked_output, "executed" if allowed else "not_executed")
    )
    if not allowed:
        return await _finish(engine, turn, message, bot, "blocked", None)
    return await _finish(engine, turn, message, bot, "replied", checked_output.text)


async def run_message(
    engine: AsyncEngine,
    llm: ChatModel,
    owner_ref: str,
    fw_session_id: str,
    message_id: str,
    message: str,
    client: ClientMeta,
    clock: Clock = _utcnow,
) -> TurnResult:
    """C2 `send_message` core. `client` is used only by Divert's trace-back (Phase C)."""
    message = storable(message)  # NUL and lone surrogates cannot be stored (M2-DD-36)
    claim = await claim_message(engine, owner_ref, fw_session_id, message_id, message)
    if claim.stored is not None:
        return claim.stored
    try:
        return await _run(engine, llm, fw_session_id, message_id, message, clock)
    except BaseException:
        await release_claim(engine, fw_session_id, message_id)
        raise
