"""Risky-behaviour records and pattern candidates (M2 C-09; PRD §7.5, §8.2; AEGIS-DOM-124).

`record_event` is called on the same transaction as an event is written. It writes the C7
`record_behavior` row when the event is an enforced Deny or Divert, or, in Off, a shadow Deny
or Divert (`shadow: true`), and adds a pattern candidate for an enforced Deny or Divert of a
tool call. Human Deny (C-02) writes its own row; an expiry (C-03) writes none.

The record describes what was enforced: only an event with `execution_status: diverted` is a
`divert`; an item blocked at the Divert band without a decoy (M2-DD-43) is a `deny`.

A Divert record is part of the divert transaction: if it fails, the divert rolls back and the
call is blocked instead (C-05). A Deny record, and a shadow record in Off, are written in a
savepoint on the event's transaction: when they succeed they commit with the event, and when
the history store fails the error is logged and the record dropped. The refusal (or Off's
Allow) is the safe outcome either way, the event is the audit trail, and a failed record can
be rebuilt from it; turning a refusal into an error would only add one (M2-DD-55).

Nothing sent to the history port holds the level secret: the input text and any argument that
holds part of it are replaced by a placeholder (the table is embedded with Gemini, M2-DD-52).
"""

from __future__ import annotations

import logging
from typing import Literal

from sqlalchemy.ext.asyncio import AsyncConnection

from app.contracts.sentinel import PatternCandidate, RiskyBehaviorRecord, RiskyHistoryPort
from app.firewall.canonical import CanonicalCall
from app.firewall.events import EventRow
from app.firewall.sentinel import WITHHELD, clean_args, clean_text

__all__ = ["WITHHELD", "behavior_action", "record_event"]

logger = logging.getLogger(__name__)

Action = Literal["deny", "divert"]


def behavior_action(event: EventRow) -> tuple[Action, bool] | None:
    """(action, shadow) for an event that must be recorded, else None."""
    if event.decision in ("deny", "divert"):
        return ("divert" if event.execution_status == "diverted" else "deny", False)
    if event.mode == "off" and event.shadow_decision in ("deny", "divert"):
        return (event.shadow_decision, True)  # type: ignore[return-value]
    return None


async def record_event(
    conn: AsyncConnection,
    risky: RiskyHistoryPort | None,
    event: EventRow,
    *,
    secret: str,
    student_message: str,
    call: CanonicalCall | None = None,
    trace_id: str | None = None,
) -> None:
    found = behavior_action(event)
    if risky is None or found is None:
        return
    action, shadow = found
    record = RiskyBehaviorRecord(
        time=event.time,
        user_id=event.user_id,
        fw_session_id=event.fw_session_id,
        event_id=event.event_id,
        stage=event.stage,
        tool=event.tool,
        args_hash=event.args_hash,
        action=action,
        sentinel_score=event.sentinel_score,
        rule_ids=list(event.rule_ids),
        input_text=clean_text(student_message, secret),
        trace_id=trace_id,
        shadow=shadow,
    )
    if action == "divert" and not shadow:  # all or nothing with the divert transaction
        await _write(conn, risky, record, event, call, secret)
        return
    try:
        async with conn.begin_nested():
            await _write(conn, risky, record, event, call, secret)
    except Exception as exc:  # a failed record never changes the outcome of a Deny or of Off
        logger.warning("behaviour record dropped: %s", type(exc).__name__)


async def _write(
    conn: AsyncConnection,
    risky: RiskyHistoryPort,
    record: RiskyBehaviorRecord,
    event: EventRow,
    call: CanonicalCall | None,
    secret: str,
) -> None:
    await risky.record_behavior(record, conn)
    if not record.shadow and call is not None and event.stage == "tool_call_check":
        await risky.add_candidate(
            PatternCandidate(
                tool=call.tool,
                canonical_args=clean_args(call.args, secret) or {},
                source_event_id=event.event_id,
                user_id=event.user_id,
            ),
            conn,
        )
