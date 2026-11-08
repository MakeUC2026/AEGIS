"""Review tickets: the admin decision (M2 C-02; PRD §8.3 steps 3-6; C6; spec AEGIS-DOM-117).

`decide_ticket` locks the ticket row, so one decision wins any race. A ticket that is no
longer pending, or at or past its deadline, is a `ConflictError` (expiry wins at the
deadline; the C-03 sweeper marks it expired). An unknown ticket is `NotFound`.

- **ok:** one transaction marks the ticket approved, writes the `review_resolved` allow
  event, and moves the claim back to `in_flight`; then the turn continues exactly once
  (`continuation.py`). Only the transaction's winner ever continues.
- **not ok (Human Deny):** one transaction marks the ticket `human_denied`, writes the
  `review_resolved` human_deny event, calls `record_behavior(action="human_deny")` and, for a
  held tool call, `add_candidate`, and finishes the claim with status `human_denied` and
  "A reviewer denied this request.". Nothing executes, and Human Deny never diverts.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.contracts.common import Decision, ExecutionStatus
from app.contracts.firewall import (
    HUMAN_DENIED_MESSAGE,
    Facts,
    FeedItem,
    NotFound,
    PlayerView,
    TurnResult,
)
from app.contracts.firewall_admin import ConflictError, TicketDecision
from app.contracts.sentinel import PatternCandidate, RiskyBehaviorRecord, RiskyHistoryPort
from app.firewall.claims import complete_claim
from app.firewall.continuation import continue_turn
from app.firewall.events import EventRow, insert_event
from app.firewall.review import Continuation
from app.llm.base import ChatModel

_LOCK = (
    "SELECT t.ticket_id, t.fw_session_id, t.message_id, t.stage, t.call_id, t.status,"
    " t.expires_at > now() AS live, t.continuation, t.sentinel_score, t.score_breakdown,"
    " t.rule_ids, t.held_tool, t.held_args, s.owner_ref, s.mode, m.manifest_id, m.level_id,"
    " m.thresholds"
    " FROM fw_tickets t JOIN fw_sessions s ON s.fw_session_id = t.fw_session_id"
    " JOIN fw_manifests m ON m.manifest_id = t.manifest_id"
    " WHERE t.ticket_id = :t FOR UPDATE OF t"
)
_DECIDE = (
    "UPDATE fw_tickets SET status = :status, decided_at = now(),"
    " decided_by = CAST(:admin AS uuid) WHERE ticket_id = :t"
)
_RESUME_CLAIM = (
    "UPDATE fw_claims SET status = 'in_flight', updated_at = now()"
    " WHERE fw_session_id = :sid AND message_id = :mid AND status = 'held'"
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _json(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


def _resolved_event(
    t: Mapping[str, Any], cont: Continuation, decision: Decision, status: ExecutionStatus
) -> EventRow:
    return EventRow(
        fw_session_id=t["fw_session_id"],
        user_id=str(t["owner_ref"]),
        message_id=t["message_id"],
        manifest_id=t["manifest_id"],
        level_id=t["level_id"],
        mode=t["mode"],
        stage="review_resolved",
        source_trust="player" if cont.kind == "input" else "bot_output",
        decision=decision,
        execution_status=status,
        sentinel_score=int(t["sentinel_score"] or 0),
        score_breakdown=_json(t["score_breakdown"]) or {},
        thresholds_used=_json(t["thresholds"]) or {},
        rule_ids=tuple(t["rule_ids"] or ()),
        tool=t["held_tool"],
        call_id=t["call_id"],
        args_hash=cont.held_args_hash,
        ticket_id=t["ticket_id"],
    )


def _resolved_line(cont: Continuation, decision: str) -> FeedItem:
    band = cont.feed[-1].score_band if cont.feed else "medium"
    return FeedItem(stage="review_resolved", decision=decision, rule_ids=[], score_band=band)  # type: ignore[arg-type]


def _denied_result(cont: Continuation) -> TurnResult:
    effects = [
        e.model_copy(update={"state": "human_denied"}) if e.state == "awaiting_review" else e
        for e in cont.effects
    ]
    return TurnResult(
        player_view=PlayerView(
            status="human_denied",
            reply=HUMAN_DENIED_MESSAGE,
            tool_effects=effects,
            ticket_id=None,
            defense_feed=[*cont.feed, _resolved_line(cont, "human_deny")],
        ),
        facts=Facts(
            decision="human_deny",
            rule_ids=list(cont.rule_ids),
            secret_attempted=cont.secret_attempted,
            secret_delivered=cont.secret_delivered,
            diverted=False,
        ),
    )


async def _human_deny(
    conn: AsyncConnection,
    t: Mapping[str, Any],
    cont: Continuation,
    risky: RiskyHistoryPort,
    now: datetime,
) -> TurnResult:
    event = _resolved_event(t, cont, "human_deny", "not_executed")
    await insert_event(conn, event)
    owner = str(t["owner_ref"])
    record = RiskyBehaviorRecord(
        time=now,
        user_id=owner,
        fw_session_id=t["fw_session_id"],
        event_id=event.event_id,
        stage=t["stage"],
        tool=t["held_tool"],
        args_hash=cont.held_args_hash,
        action="human_deny",
        sentinel_score=int(t["sentinel_score"] or 0),
        rule_ids=list(t["rule_ids"] or ()),
        input_text=cont.student_message,
        trace_id=None,
        shadow=False,
    )
    await risky.record_behavior(record, conn)
    if cont.kind == "tool_call" and t["held_tool"]:
        candidate = PatternCandidate(
            tool=t["held_tool"],
            canonical_args=_json(t["held_args"]) or {},
            source_event_id=event.event_id,
            user_id=owner,
        )
        await risky.add_candidate(candidate, conn)
    result = _denied_result(cont)
    await complete_claim(conn, t["fw_session_id"], t["message_id"], result)
    return result


async def decide_ticket(
    engine: AsyncEngine,
    llm: ChatModel,
    risky: RiskyHistoryPort,
    ticket_id: str,
    decision: TicketDecision,
    admin_id: str,
    clock: Callable[[], datetime] = _utcnow,
) -> TurnResult:
    async with engine.begin() as conn:
        row = (await conn.execute(text(_LOCK), {"t": ticket_id})).mappings().first()
        if row is None:
            raise NotFound("ticket not found")
        if row["status"] != "pending" or not row["live"]:
            raise ConflictError("the ticket is no longer pending")
        t = dict(row)
        cont = Continuation.model_validate(_json(t["continuation"]))
        approved = decision == "ok"
        await conn.execute(
            text(_DECIDE),
            {
                "t": ticket_id,
                "admin": admin_id,
                "status": "approved" if approved else "human_denied",
            },
        )
        if not approved:
            return await _human_deny(conn, t, cont, risky, clock())
        await insert_event(conn, _resolved_event(t, cont, "allow", "executed"))
        await conn.execute(text(_RESUME_CLAIM), {"sid": t["fw_session_id"], "mid": t["message_id"]})
    held = {
        "sentinel_score": t["sentinel_score"],
        "score_breakdown": _json(t["score_breakdown"]),
        "rule_ids": t["rule_ids"],
        "ticket_id": ticket_id,
    }
    return await continue_turn(
        engine,
        llm,
        t["fw_session_id"],
        t["message_id"],
        cont,
        _resolved_line(cont, "allow"),
        held,
        clock,
    )
