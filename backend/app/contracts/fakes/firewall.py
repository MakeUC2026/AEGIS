"""Scriptable in-memory C2 fake. Mirrors the real AFF's claim, conflict, busy and
review rules (PRD §8.3, §15.1) so arena code tested against it behaves the same
against M2's implementation.
"""

from __future__ import annotations

import asyncio
import itertools
import secrets
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal

from app.contracts.common import ClientMeta
from app.contracts.fakes.turns import fake_turn, with_ticket
from app.contracts.firewall import (
    Catalog,
    MessageConflict,
    Mode,
    NotFound,
    RegisterSession,
    RuleSummary,
    SessionBusy,
    SessionClosed,
    SessionHandle,
    TicketResult,
    TurnResult,
)

STARTING_RULES: tuple[RuleSummary, ...] = (
    RuleSummary(
        rule_id="R-001", applies_on="player_message", action="score", note="Override phrases"
    ),
    RuleSummary(
        rule_id="R-002", applies_on="player_message", action="review", note="Authority claim"
    ),
    RuleSummary(
        rule_id="R-003",
        applies_on="bot_tool_call",
        action="deny",
        note="Email domain not allowlisted",
    ),
    RuleSummary(
        rule_id="R-004", applies_on="bot_tool_call", action="deny", note="DB DROP/DELETE/TRUNCATE"
    ),
    RuleSummary(
        rule_id="R-005", applies_on="bot_tool_call", action="deny", note="Path outside workspace"
    ),
    RuleSummary(
        rule_id="R-006",
        applies_on="bot_tool_call",
        action="divert",
        note="Shell network/destructive",
    ),
    RuleSummary(
        rule_id="B-01", applies_on="bot_reply", action="deny_or_divert", note="Secret scan"
    ),
    RuleSummary(rule_id="B-02", applies_on="bot_tool_call", action="deny", note="Forged approval"),
    RuleSummary(
        rule_id="B-03",
        applies_on="bot_tool_call",
        action="builtin",
        note="Workspace path resolution",
    ),
    RuleSummary(rule_id="B-04", applies_on="bot_reply", action="fact", note="Echo exclusion"),
)
FAKE_REVIEW_TIMEOUT_S = 120


@dataclass(frozen=True)
class FakeDelay:
    """A step that sleeps before producing `then` (to exercise the arena's 30 s timeout)."""

    seconds: float
    then: TurnResult | Exception | None = None


Step = TurnResult | Exception | FakeDelay


@dataclass(frozen=True)
class SessionContext:
    fw_session_id: str
    owner_ref: str
    mode: Mode
    level_id: str
    secret: str
    attacker_mailbox: str


Responder = Callable[[SessionContext, str], Step | None]


@dataclass(frozen=True)
class Received:
    owner_ref: str
    fw_session_id: str
    message_id: str
    text: str
    client: ClientMeta


@dataclass
class _Session:
    ctx: SessionContext
    closed: bool = False
    results: dict[str, tuple[str, TurnResult]] = field(default_factory=dict)
    inflight: set[str] = field(default_factory=set)
    held_ticket: str | None = None


@dataclass
class _Ticket:
    owner_ref: str
    fw_session_id: str
    status: Literal["pending", "approved", "human_denied", "expired"]
    expires_at: datetime
    result: TurnResult | None = None


TurnObserver = Callable[[SessionContext, str, str, TurnResult], None]


class FakeFirewall:
    """In-memory FirewallPort. `script()` queues steps; `responder` handles the rest."""

    def __init__(
        self,
        responder: Responder | None = None,
        observer: TurnObserver | None = None,
    ) -> None:
        self._responder = responder
        self._observer = observer
        self._queue: deque[Step] = deque()
        self._sessions: dict[str, _Session] = {}
        self._tickets: dict[str, _Ticket] = {}
        self._ids = itertools.count(1)
        self._lock = asyncio.Lock()
        self.calls = 0
        self.received: list[Received] = []
        self.registered: list[RegisterSession] = []

    def script(self, *steps: Step) -> None:
        self._queue.extend(steps)

    async def read_catalog(self) -> Catalog:
        return Catalog(rules=list(STARTING_RULES), tools=[], rule_version=1)

    async def register_session(self, req: RegisterSession) -> SessionHandle:
        # Random suffix: IDs must stay unique across process restarts (DB UNIQUE constraints).
        n = f"{next(self._ids)}-{secrets.token_hex(4)}"
        sid, manifest = f"fws-fake-{n}", f"man-fake-{n}"
        ctx = SessionContext(
            fw_session_id=sid,
            owner_ref=req.owner_ref,
            mode=req.level.mode,
            level_id=req.level.level_id,
            secret=req.secret,
            attacker_mailbox=req.mock_state_seed.attacker_mailbox,
        )
        self._sessions[sid] = _Session(ctx=ctx)
        self.registered.append(req)
        return SessionHandle(fw_session_id=sid, manifest_id=manifest)

    def _owned(self, owner_ref: str, fw_session_id: str) -> _Session:
        session = self._sessions.get(fw_session_id)
        if session is None or session.ctx.owner_ref != owner_ref:
            raise NotFound(fw_session_id)
        return session

    async def send_message(
        self,
        owner_ref: str,
        fw_session_id: str,
        message_id: str,
        text: str,
        client: ClientMeta,
    ) -> TurnResult:
        async with self._lock:
            session = self._owned(owner_ref, fw_session_id)
            if session.closed:
                raise SessionClosed(fw_session_id)
            stored = session.results.get(message_id)
            if stored is not None:
                if stored[0] != text:
                    raise MessageConflict(message_id)
                return stored[1]
            if session.held_ticket is not None or session.inflight:
                raise SessionBusy(fw_session_id)
            session.inflight.add(message_id)
            self.received.append(Received(owner_ref, fw_session_id, message_id, text, client))
        try:
            result = await self._run_step(self._next_step(session.ctx, text))
        finally:
            session.inflight.discard(message_id)
        return self._store(session, message_id, text, result)

    def _next_step(self, ctx: SessionContext, text: str) -> Step:
        if self._queue:
            return self._queue.popleft()
        scripted = self._responder(ctx, text) if self._responder else None
        return scripted if scripted is not None else fake_turn()

    async def _run_step(self, step: Step) -> TurnResult:
        if isinstance(step, FakeDelay):
            await asyncio.sleep(step.seconds)
            return await self._run_step(step.then if step.then is not None else fake_turn())
        if isinstance(step, Exception):
            raise step  # claim released by the caller's finally; same message_id may retry
        return step

    def _store(
        self, session: _Session, message_id: str, text: str, result: TurnResult
    ) -> TurnResult:
        self.calls += 1
        if result.player_view.status == "awaiting_review":
            ticket_id = f"tkt-fake-{next(self._ids)}-{secrets.token_hex(4)}"
            result = with_ticket(result, ticket_id)
            self._tickets[ticket_id] = _Ticket(
                owner_ref=session.ctx.owner_ref,
                fw_session_id=session.ctx.fw_session_id,
                status="pending",
                expires_at=datetime.now(UTC) + timedelta(seconds=FAKE_REVIEW_TIMEOUT_S),
            )
            session.held_ticket = ticket_id
        session.results[message_id] = (text, result)
        if self._observer is not None:
            self._observer(session.ctx, message_id, text, result)
        return result

    async def check_ticket(self, owner_ref: str, ticket_id: str) -> TicketResult:
        ticket = self._tickets.get(ticket_id)
        if ticket is None or ticket.owner_ref != owner_ref:
            raise NotFound(ticket_id)
        return TicketResult(
            ticket_id=ticket_id,
            status=ticket.status,
            expires_at=ticket.expires_at.isoformat(),
            turn_result=ticket.result,
        )

    async def resolve_ticket(
        self,
        ticket_id: str,
        outcome: Literal["approved", "human_denied", "expired"],
        turn_result: TurnResult | None = None,
    ) -> None:
        """Test/dev hook standing in for M2's decide_ticket and expiry sweeper."""
        ticket = self._tickets.get(ticket_id)
        if ticket is None:
            raise NotFound(ticket_id)
        if ticket.status != "pending":
            return
        default = {
            "approved": fake_turn(status="replied", stage="review_resolved"),
            "human_denied": fake_turn(status="human_denied", stage="review_resolved"),
            "expired": fake_turn(status="blocked", stage="review_resolved"),
        }[outcome]
        ticket.status = outcome
        ticket.result = turn_result or default
        session = self._sessions[ticket.fw_session_id]
        if session.held_ticket == ticket_id:
            session.held_ticket = None

    def pending_ticket_ids(self) -> list[str]:
        return [tid for tid, t in self._tickets.items() if t.status == "pending"]

    async def close_session(self, owner_ref: str, fw_session_id: str) -> None:
        session = self._owned(owner_ref, fw_session_id)
        if session.held_ticket is not None:
            await self.resolve_ticket(session.held_ticket, "expired")
        session.closed = True
