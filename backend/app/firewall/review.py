"""Review parking (M2 C-01; PRD §8.3 steps 1-2; E-46a; spec AEGIS-DOM-116).

A Review decision parks the turn instead of finishing it. In one transaction:

- the turn's events so far, plus the held item's event (`decision: review`,
  `execution_status: held`, with the ticket ID);
- the conversation rows so far, all with `in_history: false` (an approval flips them; an
  expiry leaves them out of the bot's history, as for a blocked turn), so visible tool effects
  before the hold still count for the cumulative scan;
- a pending ticket bound to session, message, stage, call ID, payload hash and manifest,
  expiring after the manifest's `review_timeout_s`, carrying the `Continuation`;
- the claim, now `held` with the `awaiting_review` result (so the same message replays it,
  and any other message gets `SessionBusy`: one active item per session).

The `Continuation` is everything C-02 needs to continue the turn exactly once: the bot
messages so far (with Gemini's signatures), the held call and the calls after it in the same
model message, the round and call counters, and the feed, effects and facts built so far.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from app.contracts.common import Stage
from app.contracts.firewall import FeedItem, ToolEffect
from app.firewall.gatekeeper import GateDecision
from app.llm.base import ChatMessage, ToolCall

HeldKind = Literal["input", "tool_call", "reply"]

_OPEN_TICKET = (
    "INSERT INTO fw_tickets (ticket_id, fw_session_id, message_id, stage, call_id,"
    " payload_hash, manifest_id, status, expires_at, continuation, sentinel_score,"
    " score_breakdown, rule_ids, priority_alert, student_command, held_tool, held_args,"
    " held_reply)"
    " SELECT :ticket_id, :sid, :mid, :stage, :call_id, :payload_hash, m.manifest_id,"
    " 'pending', now() + make_interval(secs => m.review_timeout_s),"
    " CAST(:continuation AS jsonb), :score, CAST(:breakdown AS jsonb), :rule_ids,"
    " :priority_alert, :student_command, :held_tool, CAST(:held_args AS jsonb), :held_reply"
    " FROM fw_manifests m WHERE m.manifest_id = :manifest_id"
    " RETURNING ticket_id"
)


class Continuation(BaseModel):
    """The parked turn, stored on the ticket (`fw_tickets.continuation`)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: HeldKind
    student_message: str  # what the student typed (stored form)
    user_text: str  # what the bot sees (the checked input)
    messages: list[ChatMessage] = Field(default_factory=list)  # bot messages this turn
    round_index: int = 0
    calls_made: int = 0
    held_call: ToolCall | None = None
    held_call_id: str | None = None
    held_args_hash: str | None = None
    remaining_calls: list[ToolCall] = Field(default_factory=list)
    held_reply: str | None = None
    # the turn so far, for the final result after the decision
    feed: list[FeedItem] = Field(default_factory=list)
    effects: list[ToolEffect] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list)
    secret_attempted: bool = False
    secret_delivered: bool = False
    tool_results: list[str] = Field(default_factory=list)
    visible_new: list[str] = Field(default_factory=list)
    visible_by_call: dict[str, str] = Field(default_factory=dict)


def new_ticket_id() -> str:
    return f"tkt-{secrets.token_hex(12)}"


def payload_hash(cont: Continuation) -> str:
    """What the reviewer approves: the input text, the canonical call, or the exact reply."""
    if cont.kind == "tool_call" and cont.held_args_hash:
        return cont.held_args_hash
    held = cont.held_reply if cont.kind == "reply" else cont.student_message
    return hashlib.sha256((held or "").encode("utf-8")).hexdigest()


async def open_ticket(
    conn: AsyncConnection,
    *,
    ticket_id: str,
    fw_session_id: str,
    message_id: str,
    manifest_id: str,
    stage: Stage,
    gate: GateDecision,
    cont: Continuation,
    held_args: dict[str, Any] | None = None,
) -> None:
    row = await conn.execute(
        text(_OPEN_TICKET),
        {
            "ticket_id": ticket_id,
            "sid": fw_session_id,
            "mid": message_id,
            "stage": stage,
            "call_id": cont.held_call_id,
            "payload_hash": payload_hash(cont),
            "manifest_id": manifest_id,
            "continuation": cont.model_dump_json(),
            "score": gate.score,
            "breakdown": json.dumps(dict(gate.breakdown)),
            "rule_ids": list(gate.rule_ids),
            "priority_alert": gate.priority_alert,
            "student_command": cont.student_message,
            "held_tool": cont.held_call.name if cont.held_call else None,
            "held_args": json.dumps(held_args) if held_args is not None else None,
            "held_reply": cont.held_reply,
        },
    )
    if row.first() is None:
        raise LookupError(f"no manifest {manifest_id}")
