"""Where the forensic worker gets its events (M3 C-01, plan §3.2, PRD §10.2).

`FwEventSource` is the real source on M2's `0003_firewall_core`: it claims one selected
`fw_events` row with `FOR UPDATE SKIP LOCKED` inside the worker's own transaction (the row lock
is the claim, so a crash returns the event to pending) and writes only `fw_events.forensic_status`
and `trace_back.methods_used` (§0.2 rule 2). The turn's text comes from `fw_conversation`, the
arguments from `fw_tool_calls` and the secret, for redaction only, from `fw_sessions`, all read
only (owner decision, plan §10). `InMemoryEventSource` stays for unit-speed tests.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.contracts.common import Decision, Mode, Stage, UtcDatetime
from app.firewall.risky_patterns import normalize

log = logging.getLogger("aegis.workers.events")

ForensicStatus = Literal["pending", "done", "failed"]
PICKED: frozenset[str] = frozenset({"deny", "human_deny", "divert"})


class ForensicEvent(BaseModel):
    """What the worker needs from one `fw_events` row plus its turn (text, call, secret)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    time: UtcDatetime
    fw_session_id: str
    user_id: str
    level_id: str | None
    mode: Mode
    stage: Stage
    decision: Decision
    shadow_decision: Decision | None
    tool: str | None
    canonical_args: dict[str, Any] | None
    text: str
    context_excerpt: str = ""
    player_text: str | None = None  # the student message of this turn (player-message drafts)
    unredactable: bool = False  # the session's secret could not be read: never sent to a model
    rule_ids: list[str] = Field(default_factory=list)
    secret: str | None = Field(default=None, repr=False)  # redaction only; never logged
    secret_delivered: bool
    trace_id: str | None


def selected(event: ForensicEvent) -> bool:
    """PRD §10.2: Deny, Human Deny or Divert by decision or shadow decision, plus Off allows that
    delivered the secret. A Basic or Strict allow is never picked, secret or not (M3-X26)."""
    if event.decision in PICKED or event.shadow_decision in PICKED:
        return True
    return event.mode == "off" and event.decision == "allow" and event.secret_delivered


class Claim(Protocol):
    event: ForensicEvent
    conn: AsyncConnection  # the worker's own transaction; commits when the claim block exits

    async def finish(self, status: Literal["done", "failed"]) -> None: ...

    async def set_methods_used(self, trace_id: str, methods: list[str]) -> None: ...


class EventSource(Protocol):
    def claim(self) -> AbstractAsyncContextManager[Claim | None]: ...

    async def texts_for(self, event_ids: list[str]) -> dict[str, str]: ...


class _MemoryClaim:
    def __init__(self, event: ForensicEvent, conn: AsyncConnection) -> None:
        self.event, self.conn = event, conn
        self.final: Literal["done", "failed"] | None = None
        self.methods: dict[str, list[str]] = {}

    async def finish(self, status: Literal["done", "failed"]) -> None:
        self.final = status

    async def set_methods_used(self, trace_id: str, methods: list[str]) -> None:
        self.methods = {**self.methods, trace_id: list(methods)}


class InMemoryEventSource:
    """Events in a dict, claims guarded by a lock. M3 writes still go to the real DB."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._lock = asyncio.Lock()
        self._claimed: set[str] = set()
        self.events: dict[str, ForensicEvent] = {}
        self.status: dict[str, ForensicStatus | None] = {}
        self.methods_used: dict[str, list[str]] = {}

    def add(self, event: ForensicEvent) -> None:
        """M2's writer sets `pending` only for selected events (M2 B-03)."""
        self.events[event.event_id] = event
        self.status[event.event_id] = "pending" if selected(event) else None

    async def _take(self) -> str | None:
        async with self._lock:
            pending = sorted(
                (e for e, s in self.status.items() if s == "pending" and e not in self._claimed),
                key=lambda e: self.events[e].time,
            )
            if not pending:
                return None
            self._claimed.add(pending[0])
            return pending[0]

    @asynccontextmanager
    async def _claim(self) -> AsyncIterator[_MemoryClaim | None]:
        event_id = await self._take()
        if event_id is None:
            yield None
            return
        try:
            async with self._engine.begin() as conn:
                claim = _MemoryClaim(self.events[event_id], conn)
                yield claim
            # Committed: only now does the status change (a crash before this leaves it pending).
            if claim.final is not None:
                self.status[event_id] = claim.final
            self.methods_used.update(claim.methods)
        finally:
            self._claimed.discard(event_id)

    def claim(self) -> AbstractAsyncContextManager[Claim | None]:
        return self._claim()

    async def texts_for(self, event_ids: list[str]) -> dict[str, str]:
        return {e: self.events[e].text for e in event_ids if e in self.events}


# --- real source on M2's tables ---------------------------------------------------------------

# Selection mirrors `selected()` (PRD §10.2).
_CLAIM = text(  # nosemgrep: avoid-sqlalchemy-text (constant SQL)
    "SELECT e.event_id, e.time, e.fw_session_id, e.user_id::text AS user_id, e.message_id,"
    " e.level_id, e.mode, e.stage, e.decision, e.shadow_decision, e.tool, e.call_id,"
    " e.rule_ids_fired, e.secret_delivered, e.trace_back_id FROM fw_events e"
    " WHERE e.forensic_status = 'pending'"
    " AND (e.decision IN ('deny', 'human_deny', 'divert')"
    " OR e.shadow_decision IN ('deny', 'human_deny', 'divert')"
    " OR (e.mode = 'off' AND e.decision = 'allow' AND e.secret_delivered))"
    " ORDER BY e.time LIMIT 1 FOR UPDATE SKIP LOCKED"
)
# The turn's student message, the bot's last reply in it, the held call's arguments, the secret.
_TURN = text(  # nosemgrep: avoid-sqlalchemy-text (constant SQL, bound values)
    "SELECT"
    " (SELECT c.content FROM fw_conversation c WHERE c.fw_session_id = :s"
    "  AND c.message_id = :m AND c.role = 'student' ORDER BY c.seq LIMIT 1) AS student,"
    " (SELECT c.content FROM fw_conversation c WHERE c.fw_session_id = :s"
    "  AND c.message_id = :m AND c.role = 'bot' ORDER BY c.seq DESC LIMIT 1) AS reply,"
    " (SELECT t.canonical_args FROM fw_tool_calls t WHERE t.fw_session_id = :s"
    "  AND t.call_id = :c) AS args,"
    " (SELECT f.secret FROM fw_sessions f WHERE f.fw_session_id = :s) AS secret"
)
_FINISH = text(  # nosemgrep: avoid-sqlalchemy-text (constant SQL, bound values)
    "UPDATE fw_events SET forensic_status = :st WHERE event_id = :e AND time = :t"
)
_METHODS = text(  # nosemgrep: avoid-sqlalchemy-text (constant SQL, bound values)
    "UPDATE trace_back SET methods_used = :m WHERE trace_id = :t"
)
_TEXTS = text(  # nosemgrep: avoid-sqlalchemy-text (constant SQL, bound values)
    "SELECT e.event_id, e.stage,"
    " (SELECT c.content FROM fw_conversation c WHERE c.fw_session_id = e.fw_session_id"
    "  AND c.message_id = e.message_id AND c.role = 'student' ORDER BY c.seq LIMIT 1) AS student,"
    " (SELECT c.content FROM fw_conversation c WHERE c.fw_session_id = e.fw_session_id"
    "  AND c.message_id = e.message_id AND c.role = 'bot' ORDER BY c.seq DESC LIMIT 1) AS reply"
    " FROM fw_events e WHERE e.event_id = ANY(:ids)"
)


def _item_text(stage: str, student: str | None, reply: str | None) -> str:
    """The checked item: the bot reply at output_check, otherwise the student's message (a tool
    call's own arguments are in `canonical_args`)."""
    return (reply if stage == "output_check" else student) or ""


class _FwClaim:
    def __init__(self, event: ForensicEvent, conn: AsyncConnection) -> None:
        self.event, self.conn = event, conn

    async def finish(self, status: Literal["done", "failed"]) -> None:
        await self.conn.execute(
            _FINISH, {"st": status, "e": self.event.event_id, "t": self.event.time}
        )

    async def set_methods_used(self, trace_id: str, methods: list[str]) -> None:
        await self.conn.execute(_METHODS, {"m": list(methods), "t": trace_id})


class FwEventSource:
    """Claims M2's `fw_events` rows (PRD §10.2). Selection is in the claim query too, so a row M2
    marked pending by mistake is never analysed (M3-X26)."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    @staticmethod
    async def _event(conn: AsyncConnection, row: Any) -> ForensicEvent:
        params = {"s": row["fw_session_id"], "m": row["message_id"], "c": row["call_id"]}
        turn = (await conn.execute(_TURN, params)).mappings().one()
        student, stage, secret = turn["student"], row["stage"], turn["secret"]
        keys = {
            "event_id": row["event_id"],
            "time": row["time"],
            "fw_session_id": row["fw_session_id"],
            "user_id": row["user_id"],
            "level_id": row["level_id"],
            "mode": row["mode"],
            "stage": stage,
            "decision": row["decision"],
            "shadow_decision": row["shadow_decision"],
            "tool": row["tool"],
            "rule_ids": list(row["rule_ids_fired"] or []),
            "secret_delivered": row["secret_delivered"],
            "trace_id": row["trace_back_id"],
        }
        if secret is None:  # no session row (no FK): cannot redact, so carry no text at all
            return ForensicEvent(**keys, canonical_args=None, text="", unredactable=True)
        return ForensicEvent(
            **keys,
            canonical_args=turn["args"],
            text=_item_text(stage, student, turn["reply"]),
            context_excerpt=(student or "") if stage == "output_check" else "",
            player_text=student,
            secret=secret,
        )

    @asynccontextmanager
    async def _claim(self) -> AsyncIterator[_FwClaim | None]:
        async with self._engine.begin() as conn:  # commit on exit; any error rolls back
            while True:
                row = (await conn.execute(_CLAIM)).mappings().one_or_none()
                if row is None:
                    yield None
                    return
                try:
                    event = await self._event(conn, row)
                except ValidationError as exc:
                    # A row M3 cannot read would stay first in the queue forever (security
                    # review): mark it failed, keep its lock until commit, take the next one.
                    log.error("unreadable fw_events row %s: %s", row["event_id"], exc.title)
                    await conn.execute(
                        _FINISH, {"st": "failed", "e": row["event_id"], "t": row["time"]}
                    )
                    continue
                yield _FwClaim(event, conn)
                return

    def claim(self) -> AbstractAsyncContextManager[Claim | None]:
        return self._claim()

    async def texts_for(self, event_ids: list[str]) -> dict[str, str]:
        """The checked text per event, for the embedding backfill (C-08)."""
        if not event_ids:
            return {}
        async with self._engine.connect() as conn:
            rows = (await conn.execute(_TEXTS, {"ids": list(event_ids)})).mappings()
            # CheckedItem.text is normalized (PRD §9.1) and record_behavior hashes that form.
            return {
                r["event_id"]: normalize(_item_text(r["stage"], r["student"], r["reply"]))
                for r in rows
            }
