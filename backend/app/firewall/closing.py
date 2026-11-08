"""Session close (M2 B-10; PRD §8.3, §6.3; M2-X40; spec AEGIS-DOM-114).

One transaction: the session is marked closed; any pending ticket expires (an expired review
counts as Deny), with a `review_resolved` deny event, and the held turn is finished with the
blocked result; then a `finalize` event. Nothing held ever executes after a close. An unknown
session, or someone else's, is `NotFound`; closing twice is `SessionClosed` (the arena treats
that as success).
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.contracts.common import Decision, Stage
from app.contracts.firewall import NotFound, SessionClosed
from app.firewall.events import EventRow, insert_event
from app.firewall.tickets import expire_session_tickets
from app.firewall.views import expired_result

_LOCK_SESSION = (
    "SELECT s.owner_ref, s.status, s.mode, m.manifest_id, m.level_id, m.thresholds"
    " FROM fw_sessions s JOIN fw_manifests m ON m.fw_session_id = s.fw_session_id"
    " WHERE s.fw_session_id = :sid FOR UPDATE OF s"
)
_CLOSE = "UPDATE fw_sessions SET status = 'closed', closed_at = now() WHERE fw_session_id = :sid"
_FINISH_HELD = (
    "UPDATE fw_claims SET status = 'done', result = CAST(:result AS jsonb), updated_at = now()"
    " WHERE fw_session_id = :sid AND status = 'held'"
)


def _event(
    session: dict[str, Any],
    sid: str,
    stage: Stage,
    decision: Decision,
    message_id: str,
    ticket_id: str | None = None,
) -> EventRow:
    thresholds = session["thresholds"]
    return EventRow(
        fw_session_id=sid,
        user_id=str(session["owner_ref"]),
        message_id=message_id,
        manifest_id=session["manifest_id"],
        level_id=session["level_id"],
        mode=session["mode"],
        stage=stage,
        source_trust="player",
        decision=decision,
        execution_status="not_executed",
        sentinel_score=0,
        score_breakdown={},
        thresholds_used=json.loads(thresholds) if isinstance(thresholds, str) else thresholds,
        ticket_id=ticket_id,
    )


async def _lock(conn: AsyncConnection, owner_ref: str, sid: str) -> dict[str, Any]:
    row = (await conn.execute(text(_LOCK_SESSION), {"sid": sid})).mappings().first()
    if row is None or str(row["owner_ref"]) != owner_ref:
        raise NotFound("session not found")
    if row["status"] == "closed":
        raise SessionClosed("session is already closed")
    return dict(row)


async def close_session(engine: AsyncEngine, owner_ref: str, fw_session_id: str) -> None:
    async with engine.begin() as conn:
        session = await _lock(conn, owner_ref, fw_session_id)
        await conn.execute(text(_CLOSE), {"sid": fw_session_id})
        await expire_session_tickets(conn, fw_session_id)  # same expiry as the sweep (C-03)
        await conn.execute(  # a held claim with no pending ticket left: never expected
            text(_FINISH_HELD),
            {"sid": fw_session_id, "result": expired_result().model_dump_json()},
        )
        await insert_event(conn, _event(session, fw_session_id, "finalize", "allow", "close"))
