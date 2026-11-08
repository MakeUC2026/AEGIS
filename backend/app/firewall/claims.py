"""Message claims and idempotency (M2 B-07; PRD §15.1 concurrency; spec AEGIS-DOM-111).

One active claim per session, held through review (a partial unique index from B-01):

- same `message_id` and same text: a finished or held turn returns its stored `TurnResult`
  with no new model call (E-01); a turn still in flight is waited for, then its result is
  returned, or `SessionBusy` after the wait (E-02);
- same `message_id`, different text: `MessageConflict` (E-03);
- a different message while one is in flight or held: `SessionBusy` (E-04);
- an unknown session, or someone else's: `NotFound`; a new message on a closed session:
  `SessionClosed` (a finished or held turn still replays after close, E-01);
- an in-flight claim not updated for `STALE_AFTER_S` (its process died) is stale: the same
  message ID takes it over, and a different message reaps it (M2-DD-38).

`complete_claim` stores the result on the caller's transaction (atomic with the turn's
events). `release_claim` frees an in-flight claim after `BotUnavailable`, so the arena can
retry the same message ID; it never removes a finished or held turn.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Row, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.contracts.firewall import (
    MessageConflict,
    NotFound,
    SessionBusy,
    SessionClosed,
    TurnResult,
)

DEFAULT_WAIT_S = 25.0  # below the arena's 30 s turn timeout
POLL_INTERVAL_S = 0.1
STALE_AFTER_S = 120  # well past the arena's 30 s turn timeout

_SESSION = "SELECT owner_ref, status FROM fw_sessions WHERE fw_session_id = :sid"
_EXISTING = (
    "SELECT text_hash, status, result,"
    " updated_at < now() - make_interval(secs => :stale) AS stale FROM fw_claims"
    " WHERE fw_session_id = :sid AND message_id = :mid"
)
_INSERT = (
    "INSERT INTO fw_claims (fw_session_id, message_id, text_hash, status)"
    " VALUES (:sid, :mid, :hash, 'in_flight')"
    " ON CONFLICT (fw_session_id, message_id) DO NOTHING RETURNING message_id"
)
_COMPLETE = (
    "UPDATE fw_claims SET status = :status, result = CAST(:result AS jsonb),"
    " ticket_id = :ticket_id, updated_at = now()"
    " WHERE fw_session_id = :sid AND message_id = :mid"
)
_TAKE_OVER = (
    "UPDATE fw_claims SET updated_at = now()"
    " WHERE fw_session_id = :sid AND message_id = :mid AND status = 'in_flight'"
    " AND updated_at < now() - make_interval(secs => :stale) RETURNING message_id"
)
_REAP = (
    "DELETE FROM fw_claims WHERE fw_session_id = :sid AND status = 'in_flight'"
    " AND updated_at < now() - make_interval(secs => :stale)"
)
_RELEASE = (
    "DELETE FROM fw_claims"
    " WHERE fw_session_id = :sid AND message_id = :mid AND status = 'in_flight'"
)


@dataclass(frozen=True)
class Claim:
    is_new: bool  # True: this request runs the turn
    stored: TurnResult | None  # set when an earlier request already produced the result


def text_hash(message_text: str) -> str:
    return hashlib.sha256(message_text.encode("utf-8")).hexdigest()


async def _session_closed(engine: AsyncEngine, owner_ref: str, fw_session_id: str) -> bool:
    async with engine.connect() as conn:
        row = (await conn.execute(text(_SESSION), {"sid": fw_session_id})).first()
    if row is None or str(row.owner_ref) != owner_ref:
        raise NotFound("session not found")
    return bool(row.status == "closed")


async def _existing(engine: AsyncEngine, fw_session_id: str, message_id: str) -> Row[Any] | None:
    params = {"sid": fw_session_id, "mid": message_id, "stale": STALE_AFTER_S}
    async with engine.connect() as conn:
        return (await conn.execute(text(_EXISTING), params)).first()


async def _take_over(engine: AsyncEngine, fw_session_id: str, message_id: str) -> bool:
    params = {"sid": fw_session_id, "mid": message_id, "stale": STALE_AFTER_S}
    async with engine.begin() as conn:
        return (await conn.execute(text(_TAKE_OVER), params)).first() is not None


def _stored(raw: Any) -> TurnResult:
    data = json.loads(raw) if isinstance(raw, str) else raw
    return TurnResult.model_validate(data)


async def _insert(engine: AsyncEngine, fw_session_id: str, message_id: str, h: str) -> bool:
    async with engine.begin() as conn:
        row = await conn.execute(
            text(_INSERT), {"sid": fw_session_id, "mid": message_id, "hash": h}
        )
        return row.first() is not None


async def _try_insert(engine: AsyncEngine, fw_session_id: str, message_id: str, h: str) -> bool:
    try:
        return await _insert(engine, fw_session_id, message_id, h)
    except IntegrityError:  # the one-active-claim index: another message is active
        pass
    async with engine.begin() as conn:  # reap a stale in-flight claim, then try once more
        reaped = await conn.execute(text(_REAP), {"sid": fw_session_id, "stale": STALE_AFTER_S})
    try:
        if reaped.rowcount:
            return await _insert(engine, fw_session_id, message_id, h)
    except IntegrityError:
        pass
    raise SessionBusy("another message is in flight or awaiting review")


async def claim_message(
    engine: AsyncEngine,
    owner_ref: str,
    fw_session_id: str,
    message_id: str,
    message_text: str,
    wait_s: float = DEFAULT_WAIT_S,
) -> Claim:
    closed = await _session_closed(engine, owner_ref, fw_session_id)
    h = text_hash(message_text)
    deadline = time.monotonic() + wait_s
    while True:
        existing = await _existing(engine, fw_session_id, message_id)
        if existing is None:
            if closed:
                raise SessionClosed("session is closed")
            if await _try_insert(engine, fw_session_id, message_id, h):
                return Claim(True, None)
            continue  # lost a race on this same message ID: read what the winner wrote
        if existing.text_hash != h:
            raise MessageConflict("this message ID was already used with different text")
        result = existing.result
        if existing.status in ("done", "held") and result is not None:
            return Claim(False, _stored(result))
        if closed:
            raise SessionClosed("session is closed")
        if existing.status == "in_flight" and existing.stale:
            if await _take_over(engine, fw_session_id, message_id):
                return Claim(True, None)
            continue
        if time.monotonic() >= deadline:
            raise SessionBusy("this message is still being processed")
        await asyncio.sleep(POLL_INTERVAL_S)


async def complete_claim(
    conn: AsyncConnection,
    fw_session_id: str,
    message_id: str,
    result: TurnResult,
    held: bool = False,
    ticket_id: str | None = None,
) -> None:
    await conn.execute(
        text(_COMPLETE),
        {
            "sid": fw_session_id,
            "mid": message_id,
            "status": "held" if held else "done",
            "result": result.model_dump_json(),
            "ticket_id": ticket_id,
        },
    )


async def release_claim(engine: AsyncEngine, fw_session_id: str, message_id: str) -> None:
    async with engine.begin() as conn:
        await conn.execute(text(_RELEASE), {"sid": fw_session_id, "mid": message_id})
