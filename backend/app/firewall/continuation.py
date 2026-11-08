"""Continuing an approved parked turn, exactly once (M2 C-02; PRD §8.3 step 4; E-46b).

The turn is rebuilt from its `Continuation` (the session read without its own parked rows):

- held input: it goes to the bot, then the turn runs as usual;
- held tool call: the call is re-canonicalized and must hash to what the reviewer saw; it
  runs, its result goes back to the bot, the calls queued after it get normal checks, and
  the bot continues from the next round;
- held reply: released exactly as checked, with no model call.

Anything the continuation produces is checked normally, so it can be denied or parked again.
Any failure ends the turn `blocked` (fail closed): nothing more runs.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine

from app.contracts.firewall import FeedItem, TurnResult
from app.contracts.sentinel import RiskyHistoryPort
from app.firewall.bot_runner import BotTurn, resume_turn
from app.firewall.canonical import CanonicalError, canonicalize
from app.firewall.context import TurnContext, load_context
from app.firewall.decoys import DecoyGenerator
from app.firewall.events import EventRow
from app.firewall.pipeline import (
    Clock,
    Turn,
    after_bot,
    after_input,
    execute_allowed,
    finish,
    tool_hook,
)
from app.firewall.review import Continuation
from app.firewall.sentinel import Sentinel
from app.llm.base import ChatModel

logger = logging.getLogger(__name__)


class HeldCallMismatch(Exception):
    """The stored held call no longer hashes to what the reviewer approved."""


def _executed_event(
    ctx: TurnContext,
    message_id: str,
    call_id: str,
    tool: str,
    args_hash: str,
    held: Mapping[str, Any],
) -> EventRow:
    return EventRow(
        fw_session_id=ctx.fw_session_id,
        user_id=ctx.owner_ref,
        message_id=message_id,
        manifest_id=ctx.manifest_id,
        level_id=ctx.level_id,
        mode=ctx.mode,
        stage="tool_executed",
        source_trust="tool_result",
        decision="allow",
        execution_status="executed",
        sentinel_score=int(held.get("sentinel_score") or 0),
        score_breakdown=dict(held.get("score_breakdown") or {}),
        thresholds_used=dict(ctx.thresholds),
        rule_ids=tuple(held.get("rule_ids") or ()),
        tool=tool,
        call_id=call_id,
        args_hash=args_hash,
        ticket_id=held.get("ticket_id"),
    )


async def _resume_tool(
    engine: AsyncEngine,
    llm: ChatModel,
    turn: Turn,
    cont: Continuation,
    held: Mapping[str, Any],
    clock: Clock,
) -> TurnResult:
    ctx = turn.ctx
    call = cont.held_call
    if call is None or cont.held_call_id is None:
        raise HeldCallMismatch("no held call")
    canonical = canonicalize(call.name, call.arguments, ctx.tools, cont.held_call_id)
    if isinstance(canonical, CanonicalError) or canonical.args_hash != cont.held_args_hash:
        raise HeldCallMismatch("the held call differs from the reviewed one")

    def events(effective_id: str) -> list[EventRow]:
        return [
            _executed_event(
                ctx, turn.message_id, effective_id, canonical.tool, canonical.args_hash, held
            )
        ]

    step = await execute_allowed(engine, turn, canonical, call, events)
    bot = await resume_turn(
        llm,
        ctx.bot_model_id,
        ctx.system_prompt,
        ctx.history,
        cont.user_text,
        ctx.tools,
        tool_hook(engine, turn, clock),
        prior=cont.messages,
        round_index=cont.round_index,
        calls=[call, *cont.remaining_calls],
        held_step=step,
    )
    return await after_bot(engine, turn, cont.student_message, cont.user_text, bot, clock)


async def continue_turn(
    engine: AsyncEngine,
    llm: ChatModel,
    fw_session_id: str,
    message_id: str,
    cont: Continuation,
    resolved: FeedItem,
    held: Mapping[str, Any],
    clock: Clock,
    risky: RiskyHistoryPort | None = None,
    decoys: DecoyGenerator | None = None,
    sentinel: Sentinel | None = None,
) -> TurnResult:
    """`resolved` is the review's feed line; `held` carries the ticket's score, breakdown,
    rule IDs and ticket ID for the held tool's execution event."""
    ctx = await load_context(engine, fw_session_id, exclude_message=message_id)
    turn = Turn(
        ctx=ctx,
        message_id=message_id,
        effects=list(cont.effects),
        tool_results=list(cont.tool_results),
        visible_new=list(cont.visible_new),
        visible_by_call=dict(cont.visible_by_call),
        calls_made=cont.calls_made,
        prior_feed=[*cont.feed, resolved],
        prior_rule_ids=list(cont.rule_ids),
        prior_attempted=cont.secret_attempted,
        diverted=cont.diverted,
        student_message=cont.student_message,  # no client data is kept with a parked turn
        risky=risky,
        decoys=decoys,
        sentinel=sentinel,
    )
    message = cont.student_message
    try:
        if cont.kind == "input":
            return await after_input(engine, llm, turn, message, cont.user_text, clock)
        if cont.kind == "reply":
            bot = BotTurn(cont.held_reply, False, cont.round_index, tuple(cont.messages))
            return await finish(engine, turn, message, bot, "replied", cont.held_reply)
        return await _resume_tool(engine, llm, turn, cont, held, clock)
    except Exception as exc:  # fail closed (PRD §8.3): nothing more runs
        logger.warning("approved turn %s failed closed: %s", message_id, type(exc).__name__)
        turn.effects = [
            e.model_copy(update={"state": "blocked"}) if e.state == "awaiting_review" else e
            for e in turn.effects
        ]
        bot = BotTurn(None, True, cont.round_index, tuple(cont.messages))
        return await finish(engine, turn, message, bot, "blocked", None)
