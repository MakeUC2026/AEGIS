"""Review tickets: the admin decision (M2 C-02; PRD §8.3 steps 3-6; C6; spec AEGIS-DOM-117).

`decide_ticket` locks the ticket row, so one decision wins any race. A ticket that is no
longer pending, or at or past its deadline, is a `ConflictError` (expiry wins at the
deadline; the C-03 sweeper marks it expired). An unknown ticket is `NotFound`.

- **ok:** one transaction marks the ticket approved, writes the `review_resolved` allow
  event, and moves the claim back to `in_flight`; then the turn continues exactly once
  (`continuation.py`). Only the transaction's winner ever continues.
- **expired** (C-03): counts as Deny. The ticket becomes `expired`, a `review_resolved`
  deny event is written, and the held turn finishes `blocked` with nothing executed. The
  sweep (`expire_due`, every `TICKET_SWEEP_INTERVAL_S`) skips rows a decision holds;
  `decide_ticket` expires a due ticket itself before refusing; close expires every pending
  ticket of the session through the same code. No risky-behaviour row: a timeout is the
  reviewer's silence, not the student's act (M2-DD-41).
- **check** (C-04, `check_ticket`): the owner's poll. Status, deadline, and the stored
  `TurnResult` once the turn has finished (claim `done`). A turn still continuing, or held
  again under a new ticket, shows no result yet, so the arena keeps polling the ticket it
  was given and gets the final result when the turn really ends (M2-DD-42). A due pending
  ticket expires on the spot. Someone else's ticket, or an unknown one, is `NotFound`.
- **not ok (Human Deny):** one transaction marks the ticket `human_denied`, writes the
  `review_resolved` human_deny event, calls `record_behavior(action="human_deny")` and, for a
  held tool call, `add_candidate`, and finishes the claim with status `human_denied` and
  "A reviewer denied this request.". Nothing executes, and Human Deny never diverts.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.contracts.common import Decision, ExecutionStatus
from app.contracts.firewall import (
    HUMAN_DENIED_MESSAGE,
    NEUTRAL_REFUSAL,
    Facts,
    FeedItem,
    NotFound,
    PlayerView,
    TicketResult,
    TurnResult,
)
from app.contracts.firewall_admin import ConflictError, TicketDecision
from app.contracts.sentinel import PatternCandidate, RiskyBehaviorRecord, RiskyHistoryPort
from app.firewall.claims import complete_claim
from app.firewall.continuation import continue_turn
from app.firewall.events import EventRow, insert_event
from app.firewall.review import Continuation
from app.llm.base import ChatModel

TICKET_SWEEP_INTERVAL_S = 5.0
SWEEP_BATCH = 100

logger = logging.getLogger(__name__)

_LOCK = (
    "SELECT t.ticket_id, t.fw_session_id, t.message_id, t.stage, t.call_id, t.status,"
    " t.expires_at > now() AS live, t.continuation, t.sentinel_score, t.score_breakdown,"
    " t.rule_ids, t.held_tool, t.held_args, s.owner_ref, s.mode, m.manifest_id, m.level_id,"
    " m.thresholds"
    " FROM fw_tickets t JOIN fw_sessions s ON s.fw_session_id = t.fw_session_id"
    " JOIN fw_manifests m ON m.manifest_id = t.manifest_id"
    " WHERE t.ticket_id = :t FOR UPDATE OF t"
)
_LOCK_IF_FREE = (  # the sweep never waits on a decision in progress
    "SELECT t.ticket_id, t.fw_session_id, t.message_id, t.stage, t.call_id, t.status,"
    " t.expires_at > now() AS live, t.continuation, t.sentinel_score, t.score_breakdown,"
    " t.rule_ids, t.held_tool, t.held_args, s.owner_ref, s.mode, m.manifest_id, m.level_id,"
    " m.thresholds"
    " FROM fw_tickets t JOIN fw_sessions s ON s.fw_session_id = t.fw_session_id"
    " JOIN fw_manifests m ON m.manifest_id = t.manifest_id"
    " WHERE t.ticket_id = :t FOR UPDATE OF t SKIP LOCKED"
)
_DUE = (
    "SELECT ticket_id FROM fw_tickets WHERE status = 'pending' AND expires_at <= now()"
    " ORDER BY expires_at LIMIT :n"
)
_SESSION_PENDING = (
    "SELECT ticket_id FROM fw_tickets WHERE fw_session_id = :sid AND status = 'pending'"
)
_EXPIRE = "UPDATE fw_tickets SET status = 'expired', decided_at = now() WHERE ticket_id = :t"
_CHECK = (
    "SELECT t.status, t.expires_at, t.expires_at > now() AS live, c.status AS claim_status,"
    " c.result FROM fw_tickets t"
    " JOIN fw_sessions s ON s.fw_session_id = t.fw_session_id"
    " LEFT JOIN fw_claims c"
    " ON c.fw_session_id = t.fw_session_id AND c.message_id = t.message_id"
    " WHERE t.ticket_id = :t AND CAST(s.owner_ref AS text) = :owner"
)
_STATUS = {True: "approved", False: "human_denied"}
_KIND_BY_STAGE = {"input_check": "input", "tool_call_check": "tool_call", "output_check": "reply"}
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


def _continuation(t: Mapping[str, Any]) -> Continuation:
    raw = _json(t["continuation"])
    if raw is not None:
        return Continuation.model_validate(raw)
    kind = _KIND_BY_STAGE.get(t["stage"], "input")  # a ticket written without one
    return Continuation(kind=kind, student_message="", user_text="")  # type: ignore[arg-type]


def _resolved_result(cont: Continuation, *, denied_by_human: bool) -> TurnResult:
    """The end of a held turn that never continues: Human Deny, or an expired review."""
    state = "human_denied" if denied_by_human else "blocked"
    effects = [
        e.model_copy(update={"state": state}) if e.state == "awaiting_review" else e
        for e in cont.effects
    ]
    return TurnResult(
        player_view=PlayerView(
            status="human_denied" if denied_by_human else "blocked",
            reply=HUMAN_DENIED_MESSAGE if denied_by_human else NEUTRAL_REFUSAL,
            tool_effects=effects,
            ticket_id=None,
            defense_feed=[
                *cont.feed,
                _resolved_line(cont, "human_deny" if denied_by_human else "deny"),
            ],
        ),
        facts=Facts(
            decision="human_deny" if denied_by_human else "deny",
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
    result = _resolved_result(cont, denied_by_human=True)
    await complete_claim(conn, t["fw_session_id"], t["message_id"], result)
    return result


async def _expire_locked(conn: AsyncConnection, t: Mapping[str, Any]) -> TurnResult:
    cont = _continuation(t)
    await conn.execute(text(_EXPIRE), {"t": t["ticket_id"]})
    await insert_event(conn, _resolved_event(t, cont, "deny", "not_executed"))
    result = _resolved_result(cont, denied_by_human=False)
    await complete_claim(conn, t["fw_session_id"], t["message_id"], result)
    return result


async def expire_ticket(engine: AsyncEngine, ticket_id: str) -> bool:
    """Expire one ticket if it is still pending and due; False if not (or a decision holds it)."""
    async with engine.begin() as conn:
        row = (await conn.execute(text(_LOCK_IF_FREE), {"t": ticket_id})).mappings().first()
        if row is None or row["status"] != "pending" or row["live"]:
            return False
        await _expire_locked(conn, row)
        return True


async def expire_due(engine: AsyncEngine) -> int:
    """One sweep: expire every pending ticket at or past its deadline."""
    async with engine.connect() as conn:
        due = (await conn.execute(text(_DUE), {"n": SWEEP_BATCH})).scalars().all()
    expired = 0
    for ticket_id in due:
        expired += await expire_ticket(engine, ticket_id)
    return expired


async def expire_session_tickets(conn: AsyncConnection, fw_session_id: str) -> list[str]:
    """Session close: every pending ticket expires now, deadline or not (on the caller's
    transaction). Returns the expired ticket IDs."""
    ids = (await conn.execute(text(_SESSION_PENDING), {"sid": fw_session_id})).scalars().all()
    for ticket_id in ids:
        row = (await conn.execute(text(_LOCK), {"t": ticket_id})).mappings().one()
        await _expire_locked(conn, row)
    return list(ids)


async def sweep(
    engine: AsyncEngine, stop: asyncio.Event, interval_s: float = TICKET_SWEEP_INTERVAL_S
) -> None:
    """Run `expire_due` every `interval_s` until `stop` is set; a failed sweep is logged and
    the next one runs anyway (the lazy check in `decide_ticket` still covers the gap)."""
    while not stop.is_set():
        try:
            await expire_due(engine)
        except Exception as exc:  # keep sweeping: one bad sweep must not stop expiry for good
            logger.warning("ticket sweep failed: %s", type(exc).__name__)
        with contextlib.suppress(TimeoutError):  # the interval passed without a stop
            await asyncio.wait_for(stop.wait(), timeout=interval_s)


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
        if row["status"] != "pending":
            raise ConflictError("the ticket is no longer pending")
        t = dict(row)
        expired = not t["live"]
        if expired:  # expiry wins at the deadline: expire it now, refuse after the commit
            await _expire_locked(conn, t)
        else:
            cont = _continuation(t)
            approved = decision == "ok"
            await conn.execute(
                text(_DECIDE),
                {"t": ticket_id, "admin": admin_id, "status": _STATUS[approved]},
            )
            if not approved:
                return await _human_deny(conn, t, cont, risky, clock())
            await insert_event(conn, _resolved_event(t, cont, "allow", "executed"))
            await conn.execute(
                text(_RESUME_CLAIM), {"sid": t["fw_session_id"], "mid": t["message_id"]}
            )
    if expired:
        raise ConflictError("the review expired")
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


async def _read_check(engine: AsyncEngine, owner_ref: str, ticket_id: str) -> Mapping[str, Any]:
    async with engine.connect() as conn:
        row = (
            (await conn.execute(text(_CHECK), {"t": ticket_id, "owner": owner_ref}))
            .mappings()
            .first()
        )
    if row is None:
        raise NotFound("ticket not found")
    return row


async def check_ticket(engine: AsyncEngine, owner_ref: str, ticket_id: str) -> TicketResult:
    row = await _read_check(engine, owner_ref, ticket_id)
    if row["status"] == "pending" and not row["live"]:
        await expire_ticket(engine, ticket_id)  # lazy expiry; a decision in progress wins
        row = await _read_check(engine, owner_ref, ticket_id)
    finished = row["status"] != "pending" and row["claim_status"] == "done"
    raw = _json(row["result"]) if finished else None
    return TicketResult(
        ticket_id=ticket_id,
        status=row["status"],
        expires_at=row["expires_at"].astimezone(UTC).isoformat(),
        turn_result=TurnResult.model_validate(raw) if raw is not None else None,
    )
