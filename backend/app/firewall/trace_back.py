"""Trace-back rows for diverted turns (M2 C-05, extended by C-07; PRD §8.5; spec AEGIS-DOM-120).

One `trace_back` row is written inside the divert transaction. This first version keeps what
`ClientMeta` carries without network lookups: user agent, the arena's fingerprint hash, and
the tool names attempted in the session. The salted IP hash, the /24 (/48) subnet and the
offline ASN and country lookup come with C-07; `methods_used` is filled later by M3's worker.
Admin-only data: it never reaches a `PlayerView` or the teacher API (PRD §8.5, I-3).
"""

from __future__ import annotations

import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from app.contracts.common import ClientMeta
from app.firewall.textnorm import storable

TRACE_ID_PREFIX = "trc-"
MAX_FIELD_CHARS = 512

_TOOLS_ATTEMPTED = (
    "SELECT DISTINCT tool FROM fw_events"
    " WHERE fw_session_id = :sid AND tool IS NOT NULL ORDER BY tool"
)
_INSERT = (
    "INSERT INTO trace_back (trace_id, user_id, fw_session_id, event_id, user_agent,"
    " client_fingerprint, tools_called)"
    " VALUES (:trace_id, CAST(:user_id AS uuid), :sid, :event_id, :user_agent, :fingerprint,"
    " :tools)"
)


def new_trace_id() -> str:
    return TRACE_ID_PREFIX + uuid.uuid4().hex


def _clip(value: str | None) -> str | None:
    return None if value is None else str(storable(value))[:MAX_FIELD_CHARS]


async def insert_trace_back(
    conn: AsyncConnection,
    *,
    trace_id: str,
    user_id: str,
    fw_session_id: str,
    event_id: str,
    client: ClientMeta,
    tool: str | None,
) -> None:
    tools = (await conn.execute(text(_TOOLS_ATTEMPTED), {"sid": fw_session_id})).scalars().all()
    await conn.execute(
        text(_INSERT),
        {
            "trace_id": trace_id,
            "user_id": user_id,
            "sid": fw_session_id,
            "event_id": event_id,
            "user_agent": _clip(client.user_agent),
            "fingerprint": _clip(client.fingerprint_hash),
            "tools": sorted({*tools, *([tool] if tool else [])}),
        },
    )
