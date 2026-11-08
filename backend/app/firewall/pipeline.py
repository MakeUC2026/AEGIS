"""One student turn, end to end (M2 B-08; PRD §7.1, §8.1, §8.2, §15.1; spec AEGIS-DOM-112).

claim -> input check -> bot runner (tool-call check before each tool; each allowed tool runs
with its two events in one transaction) -> output check -> one final transaction (remaining
events, conversation rows, claim result). A bot failure or any error releases the claim and
re-raises, so the arena can retry the same message ID; call IDs are deterministic
(`<message_id>-r<round>-c<n>`), so a retry never runs a tool twice.

A Review decision at any stage parks the turn (C-01, `review.py`): a pending ticket with the
continuation, the claim held, and `awaiting_review` returned at once.

Temporary until C-05: a Divert decision fails closed (blocked).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.contracts.common import ClientMeta, ExecutionStatus, Stage
from app.contracts.firewall import FeedItem, PlayerStatus, ToolEffect, TurnResult
from app.contracts.sentinel import RiskyHistoryPort
from app.firewall.bot_runner import BotTurn, ToolStep, run_turn
from app.firewall.canonical import CanonicalCall
from app.firewall.checks import Checked, check_input, check_output, check_tool_call
from app.firewall.claims import claim_message, complete_claim, release_claim
from app.firewall.context import TurnContext, load_context
from app.firewall.decoys import DecoyGenerator, make_decoy, reply_decoy
from app.firewall.divert import divert_call, record_divert
from app.firewall.events import EventRow, SourceTrust, insert_event, row_from_decision
from app.firewall.leak import echo_excluded, scan_cumulative
from app.firewall.limits import check_text
from app.firewall.review import Continuation, HeldKind, new_ticket_id, open_ticket
from app.firewall.textnorm import storable
from app.firewall.tool_exec import execute_tool
from app.firewall.trace_back import NetworkFields, Tracer, insert_trace_back, new_trace_id
from app.firewall.views import turn_result
from app.llm.base import ChatMessage, ChatModel, ToolCall

Clock = Callable[[], datetime]

logger = logging.getLogger(__name__)

_CONVERSATION = (
    "INSERT INTO fw_conversation (fw_session_id, seq, message_id, role, content, visible,"
    " call_id, tool, model_payload) VALUES (:sid, :seq, :mid, :role, :content, :visible,"
    " :call_id, :tool, CAST(:payload AS jsonb))"
)
_DROP_PARKED = "DELETE FROM fw_conversation WHERE fw_session_id = :sid AND message_id = :mid"


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class Turn:
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
    held: Checked | None = None  # a tool call parked for review
    held_call: ToolCall | None = None
    # what a parked turn had produced before its review (C-02 continuation)
    prior_feed: list[FeedItem] = field(default_factory=list)
    prior_rule_ids: list[str] = field(default_factory=list)
    prior_attempted: bool = False
    diverted: bool = False  # a decoy was returned in this turn (C-05)
    # what Divert needs (C-05): who is asking, what they typed, and the C7/decoy ports
    client: ClientMeta = field(default_factory=ClientMeta)
    student_message: str = ""
    risky: RiskyHistoryPort | None = None
    decoys: DecoyGenerator | None = None
    tracer: Tracer = field(default_factory=Tracer.disabled)

    def result(
        self, status: PlayerStatus, reply: str | None, delivered: bool, ticket: str | None = None
    ) -> TurnResult:
        return turn_result(
            status,
            reply,
            self.effects,
            self.checks,
            delivered,
            ticket_id=ticket,
            prior_feed=self.prior_feed,
            prior_rule_ids=self.prior_rule_ids,
            prior_attempted=self.prior_attempted,
            diverted=self.diverted,
        )


def _event(
    turn: Turn,
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


def tool_hook(engine: AsyncEngine, turn: Turn, clock: Clock) -> Callable[..., Any]:
    async def on_tool_call(call: ToolCall, round_index: int) -> ToolStep:
        call_id = f"{turn.message_id}-r{round_index}-c{turn.calls_made}"
        turn.calls_made += 1
        seen = (*turn.ctx.visible_output, *turn.visible_new)
        checked = check_tool_call(turn.ctx, call, call_id, turn.tool_results, clock(), seen)
        turn.checks.append(checked)
        tool = storable(call.name)
        if checked.gate.decision == "review" and checked.call is not None:
            turn.held, turn.held_call = checked, call
            turn.effects.append(
                ToolEffect(
                    call_id=call_id, tool=tool, state="awaiting_review", visible_content=None
                )
            )
            return ToolStep.hold()
        if checked.gate.decision == "divert" and checked.call is not None:
            step = await _divert(engine, turn, checked, call, clock)
            if step is not None:
                return step
            # the divert transaction failed and rolled back: block, never run the real tool
            checked = replace(checked, gate=replace(checked.gate, decision="deny"))
            turn.checks[-1] = checked
        if not checked.allowed or checked.call is None:
            turn.effects.append(
                ToolEffect(call_id=call_id, tool=tool, state="blocked", visible_content=None)
            )
            turn.later_events.append(_event(turn, checked, "not_executed"))
            return ToolStep.stop()
        allowed = checked

        def events(effective_id: str) -> list[EventRow]:
            done = replace(allowed, call_id=effective_id)
            return [
                _event(turn, done, "executed"),
                _event(turn, done, "executed", "tool_executed", "tool_result"),
            ]

        return await execute_allowed(engine, turn, checked.call, call, events)

    return on_tool_call


async def _divert(
    engine: AsyncEngine, turn: Turn, checked: Checked, call: ToolCall, clock: Clock
) -> ToolStep | None:
    """Divert a tool call (C-05): decoy first, then one transaction. None means it failed
    (everything rolled back) and the caller blocks the call."""
    canonical = checked.call
    if canonical is None:
        return None
    try:
        tool_def = next((t for t in turn.ctx.tools if t.name == canonical.tool), None)
        decoy = await make_decoy(turn.decoys, canonical, turn.ctx.secret, tool_def)
        async with engine.begin() as conn:
            done = await divert_call(
                conn,
                event=_event(turn, checked, "diverted"),
                call=canonical,
                decoy=decoy,
                client=turn.client,
                student_message=turn.student_message,
                risky=turn.risky,
                now=clock(),
                tracer=turn.tracer,
            )
    except Exception as exc:  # fail closed: a divert that cannot be recorded is a block
        logger.warning("divert failed closed: %s", type(exc).__name__)
        return None
    turn.effects.append(
        ToolEffect(
            call_id=done.call_id,
            tool=canonical.tool,
            state="executed",  # a diverted call shows as executed (PRD §8.4)
            visible_content=done.visible_content,
        )
    )
    if done.visible_content:
        turn.visible_new.append(done.visible_content)
        turn.visible_by_call[call.id] = done.visible_content
    turn.tool_results.append(done.result)
    turn.diverted = True
    return ToolStep.result(done.result)


async def execute_allowed(
    engine: AsyncEngine,
    turn: Turn,
    canonical: CanonicalCall,
    call: ToolCall,
    events: Callable[[str], list[EventRow]],
) -> ToolStep:
    """Run an allowed (or approved) call with its events in one transaction, record its
    effect, and return what goes back to the bot. `events` gets the ID the call ran under."""
    async with engine.begin() as conn:
        executed = await execute_tool(conn, turn.ctx.fw_session_id, turn.message_id, canonical)
        for event in events(executed.call_id):
            await insert_event(conn, event)
    limited = check_text("tool_result", executed.result, turn.ctx.mode)
    effect = ToolEffect(
        call_id=executed.call_id,
        tool=canonical.tool,
        state="executed",
        visible_content=executed.visible_content,
    )
    held_at = next((i for i, e in enumerate(turn.effects) if e.state == "awaiting_review"), None)
    if held_at is not None and turn.effects[held_at].call_id == canonical.call_id:
        turn.effects[held_at] = effect  # an approved held call: same slot, now executed
    else:
        turn.effects.append(effect)
    if executed.visible_content:
        turn.visible_new.append(executed.visible_content)
        turn.visible_by_call[call.id] = executed.visible_content
    if limited.action == "deny":  # an oversized tool result never reaches the bot
        return ToolStep.stop()
    turn.tool_results.append(limited.text)
    return ToolStep.result(limited.text)


@dataclass(frozen=True)
class ReplyDivert:
    """A diverted reply (C-06): its event, trace-back ID and the real reply, kept withheld."""

    event: EventRow
    trace_id: str
    withheld: str
    net: NetworkFields


def _delivered(turn: Turn, message: str, extra: tuple[str, ...] = ()) -> bool:
    visible = [*turn.visible_new, *extra]
    if not visible:
        return False
    ctx = turn.ctx
    leak = scan_cumulative(ctx.visible_output, "\n".join(visible), ctx.secret)
    typed = (*ctx.student_inputs, message)
    return leak is not None and not leak.partial and not echo_excluded(typed, ctx.secret)


def _rows(
    turn: Turn,
    message: str,
    bot: BotTurn | None,
    replied: bool,
    withheld: str | None = None,
) -> list[dict[str, Any]]:
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
    if withheld is not None and rows[-1]["role"] == "bot":
        rows[-1]["payload"]["withheld"] = withheld  # the real reply, never shown (C-06)
    return [  # model text can hold NUL or lone surrogates; Postgres stores neither
        {
            **r,
            "seq": turn.ctx.next_seq + i,
            "content": storable(r["content"]),
            "payload": json.dumps(storable(r["payload"])),
        }
        for i, r in enumerate(rows)
    ]


def _row_for(msg: ChatMessage, turn: Turn, replied: bool) -> dict[str, Any]:
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


async def finish(
    engine: AsyncEngine,
    turn: Turn,
    message: str,
    bot: BotTurn | None,
    status: PlayerStatus,
    reply: str | None,
    divert: ReplyDivert | None = None,
) -> TurnResult:
    shown = (reply,) if status == "replied" and reply else ()
    delivered = _delivered(turn, message, shown)
    events = list(turn.later_events)
    if events and delivered:
        events[-1] = replace(events[-1], secret_delivered=True)
    result = turn.result(status, reply, delivered)
    withheld = divert.withheld if divert else None
    rows = _rows(turn, message, bot, status == "replied", withheld)
    async with engine.begin() as conn:
        await _commit(conn, turn, events, rows, result, divert)
    return result


async def _park(
    engine: AsyncEngine,
    turn: Turn,
    message: str,
    user_text: str,
    bot: BotTurn | None,
    kind: HeldKind,
    checked: Checked,
) -> TurnResult:
    """Park the turn on a Review decision (C-01): see `review.py`."""
    ticket_id = new_ticket_id()
    events = [*turn.later_events, replace(_event(turn, checked, "held"), ticket_id=ticket_id)]
    delivered = _delivered(turn, message)
    if delivered:
        events[-1] = replace(events[-1], secret_delivered=True)
    result = turn.result("awaiting_review", None, delivered, ticket_id)
    call = checked.call if kind == "tool_call" else None
    cont = Continuation(
        kind=kind,
        student_message=message,
        user_text=user_text,
        messages=list(bot.new_messages) if bot else [],
        round_index=bot.rounds if bot else 0,
        calls_made=turn.calls_made,
        held_call=turn.held_call if call else None,
        held_call_id=checked.call_id if call else None,
        held_args_hash=call.args_hash if call else None,
        remaining_calls=list(bot.remaining_calls) if bot else [],
        held_reply=checked.text if kind == "reply" else None,
        feed=list(result.player_view.defense_feed),
        effects=list(turn.effects),
        rule_ids=list(result.facts.rule_ids),
        secret_attempted=result.facts.secret_attempted,
        secret_delivered=delivered,
        diverted=turn.diverted,
        tool_results=list(turn.tool_results),
        visible_new=list(turn.visible_new),
        visible_by_call=dict(turn.visible_by_call),
    )
    ctx = turn.ctx
    async with engine.begin() as conn:
        await open_ticket(
            conn,
            ticket_id=ticket_id,
            fw_session_id=ctx.fw_session_id,
            message_id=turn.message_id,
            manifest_id=ctx.manifest_id,
            stage=checked.stage,
            gate=checked.gate,
            cont=cont,
            held_args=dict(call.args) if call else None,
        )
        for event in events:
            await insert_event(conn, event)
        await _drop_parked(conn, turn)
        for row in _rows(turn, message, bot, replied=False):  # in_history false until approved
            await conn.execute(text(_CONVERSATION), row)
        await complete_claim(
            conn, ctx.fw_session_id, turn.message_id, result, held=True, ticket_id=ticket_id
        )
    return result


async def _commit(
    conn: AsyncConnection,
    turn: Turn,
    events: list[EventRow],
    rows: list[dict[str, Any]],
    result: TurnResult,
    divert: ReplyDivert | None = None,
) -> None:
    if divert is not None:  # the trace-back row first; the record joins this transaction
        await insert_trace_back(
            conn,
            trace_id=divert.trace_id,
            user_id=divert.event.user_id,
            fw_session_id=divert.event.fw_session_id,
            event_id=divert.event.event_id,
            client=turn.client,
            tool=None,
            net=divert.net,
        )
    for event in events:
        await insert_event(conn, event)
    if divert is not None:
        await record_divert(
            turn.risky,
            conn,
            event=divert.event,
            tool=None,
            args_hash=None,
            student_message=turn.student_message,
            trace_id=divert.trace_id,
            now=datetime.now(UTC),
        )
    await _drop_parked(conn, turn)
    for row in rows:
        await conn.execute(text(_CONVERSATION), row)
    await complete_claim(conn, turn.ctx.fw_session_id, turn.message_id, result)


async def _drop_parked(conn: AsyncConnection, turn: Turn) -> None:
    """A continued turn rewrites its own rows (written once already when it was parked)."""
    await conn.execute(text(_DROP_PARKED), {"sid": turn.ctx.fw_session_id, "mid": turn.message_id})


async def _run(
    engine: AsyncEngine,
    llm: ChatModel,
    sid: str,
    message_id: str,
    message: str,
    clock: Clock,
    client: ClientMeta,
    risky: RiskyHistoryPort | None,
    decoys: DecoyGenerator | None,
    tracer: Tracer | None,
) -> TurnResult:
    turn = Turn(
        ctx=await load_context(engine, sid),
        message_id=message_id,
        client=client,
        student_message=message,
        risky=risky,
        decoys=decoys,
        tracer=tracer or Tracer.disabled(),
    )
    checked_input = check_input(turn.ctx, message, clock())
    turn.checks.append(checked_input)
    if checked_input.gate.decision == "review":
        return await _park(engine, turn, message, checked_input.text, None, "input", checked_input)
    turn.later_events.append(
        _event(turn, checked_input, "executed" if checked_input.allowed else "not_executed")
    )
    if not checked_input.allowed:  # deny, or divert until C-05 (fail closed)
        return await finish(engine, turn, message, None, "blocked", None)
    return await after_input(engine, llm, turn, message, checked_input.text, clock)


async def after_input(
    engine: AsyncEngine,
    llm: ChatModel,
    turn: Turn,
    message: str,
    user_text: str,
    clock: Clock,
) -> TurnResult:
    """An allowed (or approved) input goes to the bot."""
    ctx = turn.ctx
    bot = await run_turn(
        llm,
        ctx.bot_model_id,
        ctx.system_prompt,
        ctx.history,
        user_text,
        ctx.tools,
        tool_hook(engine, turn, clock),
    )
    return await after_bot(engine, turn, message, user_text, bot, clock)


async def _divert_reply(
    engine: AsyncEngine, turn: Turn, message: str, bot: BotTurn, checked: Checked
) -> TurnResult:
    """Divert a reply (C-06, Strict outbound hit): the student gets a decoy reply, the real
    one is withheld. The records join the turn's final transaction; if that fails the reply
    is blocked instead."""
    ctx = turn.ctx
    shown = reply_decoy(ctx.secret, ctx.fw_session_id, leaked=checked.leak is not None)
    trace_id = new_trace_id()
    net = turn.tracer.network(turn.client.ip)
    event = replace(
        _event(turn, checked, "diverted"), trace_back_id=trace_id, client_ip_hash=net.ip_hash
    )
    swapped = replace(
        bot, new_messages=(*bot.new_messages[:-1], ChatMessage(role="assistant", content=shown))
    )
    turn.later_events.append(event)
    turn.diverted = True
    try:
        return await finish(
            engine,
            turn,
            message,
            swapped,
            "replied",
            shown,
            ReplyDivert(event, trace_id, checked.text, net),
        )
    except Exception as exc:  # fail closed: nothing was written, so block the reply instead
        logger.warning("reply divert failed closed: %s", type(exc).__name__)
        turn.later_events.pop()
        turn.diverted = False
        denied = replace(checked, gate=replace(checked.gate, decision="deny"))
        turn.checks[-1] = denied
        turn.later_events.append(_event(turn, denied, "not_executed"))
        return await finish(engine, turn, message, bot, "blocked", None)


async def after_bot(
    engine: AsyncEngine,
    turn: Turn,
    message: str,
    user_text: str,
    bot: BotTurn,
    clock: Clock,
) -> TurnResult:
    """A finished bot turn: park a held call, or check the reply and finish."""
    ctx = turn.ctx
    if bot.held and turn.held is not None:
        return await _park(engine, turn, message, user_text, bot, "tool_call", turn.held)
    if bot.stopped or bot.reply is None:
        return await finish(engine, turn, message, bot, "blocked", None)
    seen = (*ctx.visible_output, *turn.visible_new)
    checked_output = check_output(ctx, bot.reply, seen, clock())
    turn.checks.append(checked_output)
    if checked_output.gate.decision == "review":
        return await _park(engine, turn, message, user_text, bot, "reply", checked_output)
    if checked_output.gate.decision == "divert":
        return await _divert_reply(engine, turn, message, bot, checked_output)
    allowed = checked_output.allowed
    turn.later_events.append(
        _event(turn, checked_output, "executed" if allowed else "not_executed")
    )
    if not allowed:
        return await finish(engine, turn, message, bot, "blocked", None)
    return await finish(engine, turn, message, bot, "replied", checked_output.text)


async def run_message(
    engine: AsyncEngine,
    llm: ChatModel,
    owner_ref: str,
    fw_session_id: str,
    message_id: str,
    message: str,
    client: ClientMeta,
    clock: Clock = _utcnow,
    *,
    risky: RiskyHistoryPort | None = None,
    decoys: DecoyGenerator | None = None,
    tracer: Tracer | None = None,
) -> TurnResult:
    """C2 `send_message` core. `client` is used only by Divert's trace-back (C-05, C-07);
    `risky` receives the Divert record (C7); `decoys` is the decoy generator (C-06);
    `tracer` hashes the client IP and looks up its network (C-07)."""
    message = storable(message)  # NUL and lone surrogates cannot be stored (M2-DD-36)
    claim = await claim_message(engine, owner_ref, fw_session_id, message_id, message)
    if claim.stored is not None:
        return claim.stored
    try:
        return await _run(
            engine, llm, fw_session_id, message_id, message, clock, client, risky, decoys, tracer
        )
    except BaseException:
        await release_claim(engine, fw_session_id, message_id)
        raise
