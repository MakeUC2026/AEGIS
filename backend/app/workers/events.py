"""Where the forensic worker gets its events (M3 C-01, plan §3.2, PRD §10.2).

M2's `fw_events` (`0003_firewall_core`) has not landed, so the worker reads through the
`EventSource` protocol. `InMemoryEventSource` is the stand-in for tests and for a worker started
before M2 lands. The real source (follow-up when `0003` lands) claims one row with
`SELECT ... FROM fw_events WHERE forensic_status = 'pending' ... FOR UPDATE SKIP LOCKED LIMIT 1`
inside the worker's own transaction, and writes only `fw_events.forensic_status` and
`trace_back.methods_used` (§0.2 rule 2).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.contracts.common import Decision, Mode, Stage, UtcDatetime

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
