"""Arena session lifecycle (M1 B-05..B-12; PRD §6.1-§6.4, §8.3 step 7, §15.1).

Only `player_view` data is stored in `arena_turns` and returned; `facts` drive the win
rule and are never persisted or sent to the browser (I-3).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.arena.lifecycle import check_turn_transition
from app.arena.seed import build_mock_state
from app.arena.service import ArenaService
from app.config import Settings
from app.contracts.common import ClientMeta
from app.contracts.firewall import (
    AgentDefinition,
    FirewallError,
    FirewallPort,
    LevelConfig,
    MessageConflict,
    NotFound,
    PlayerView,
    RegisterSession,
    SessionBusy,
    SessionClosed,
    ToolDef,
    TurnResult,
)
from app.contracts.firewall_read import FirewallReadPort
from app.contracts.users import CurrentUser
from app.llm.budget import DailyBudget

NOT_SENT_MESSAGE = "Firewall unavailable, message not sent"  # PRD §6.2
STALE_GRACE_S = 5  # a `sent` turn older than the AFF timeout plus this is a crashed owner
_HOURLY_USED = (
    "SELECT count(*) FROM usage WHERE kind = 'message' AND user_id = CAST(:u AS uuid)"
    " AND time > now() - interval '1 hour'"
)
_FINAL = frozenset({"replied", "blocked", "awaiting_review", "human_denied"})


class ArenaError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status, self.detail = status, detail


def _band(score: int, thresholds: dict[str, int]) -> str:
    if score >= thresholds.get("deny", 60):
        return "high"
    return "medium" if score >= thresholds.get("review", 30) else "low"


class ArenaPlay:
    def __init__(
        self,
        engine: AsyncEngine,
        firewall: FirewallPort,
        read: FirewallReadPort,
        settings: Settings,
        budget: DailyBudget,
    ) -> None:
        self._engine, self._fw, self._read = engine, firewall, read
        self._settings, self._budget = settings, budget
        self._svc = ArenaService(engine)

    # --- helpers ------------------------------------------------------------------------

    async def _owned(self, user: CurrentUser, session_id: str) -> dict[str, Any]:
        async with self._engine.connect() as conn:
            row = (
                (
                    await conn.execute(
                        text(
                            "SELECT s.*, l.name AS level_name, l.divert_enabled, l.thresholds"
                            " FROM arena_sessions s JOIN levels l ON l.level_id = s.level_id"
                            " AND l.level_version = s.level_version"
                            " WHERE s.id = CAST(:id AS uuid) AND s.user_id = CAST(:u AS uuid)"
                        ),
                        {"id": session_id, "u": user.id},
                    )
                )
                .mappings()
                .first()
            )
        if row is None:  # unknown or someone else's: same answer (no enumeration)
            raise ArenaError(404, "session not found")
        return dict(row)

    async def remaining(self, user_id: str) -> int:
        async with self._engine.connect() as conn:
            used = (
                await conn.execute(
                    text(_HOURLY_USED),
                    {"u": user_id},
                )
            ).scalar_one()
        return max(0, self._settings.hourly_message_cap - int(used))

    async def _consume_slot(self, user_id: str, session_id: str, message_id: str) -> int:
        """One slot per (user, session, message_id); only a retry of the same message in the
        same session is free (M1-X10). Keyed by session so reusing an id elsewhere costs a slot."""
        cap = self._settings.hourly_message_cap
        async with self._engine.begin() as conn:
            await conn.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:u, 7))"), {"u": user_id}
            )
            counted = (
                await conn.execute(
                    text(
                        "SELECT 1 FROM usage WHERE kind = 'message' AND user_id = CAST(:u AS uuid)"
                        " AND session_id = CAST(:sid AS uuid) AND message_id = :m"
                    ),
                    {"u": user_id, "sid": session_id, "m": message_id},
                )
            ).first()
            used = (
                await conn.execute(
                    text(_HOURLY_USED),
                    {"u": user_id},
                )
            ).scalar_one()
            if counted:
                return max(0, cap - int(used))
            if used >= cap:
                raise ArenaError(429, "hourly message limit reached")
            await conn.execute(
                text(
                    "INSERT INTO usage (kind, user_id, session_id, message_id)"
                    " VALUES ('message', CAST(:u AS uuid), CAST(:sid AS uuid), :m)"
                ),
                {"u": user_id, "sid": session_id, "m": message_id},
            )
            return cap - int(used) - 1

    @staticmethod
    async def _set_turn(
        conn: AsyncConnection,
        session_id: str,
        message_id: str,
        status: str,
        view: PlayerView | None,
        expected: str,
    ) -> bool:
        """Compare-and-set: only moves the turn if it is still in `expected` (finding 5)."""
        result = await conn.execute(
            text(
                "UPDATE arena_turns SET status = :st, player_view = CAST(:pv AS jsonb),"
                " ticket_id = :t, updated_at = now()"
                " WHERE session_id = CAST(:s AS uuid) AND message_id = :m AND status = :exp"
            ),
            {
                "st": status,
                "pv": view.model_dump_json() if view else None,
                "t": view.ticket_id if view else None,
                "s": session_id,
                "m": message_id,
                "exp": expected,
            },
        )
        return result.rowcount == 1

    async def _won(self, session_id: str) -> bool:
        async with self._engine.connect() as conn:
            return bool(
                (
                    await conn.execute(
                        text(
                            "SELECT secret_obtained_at IS NOT NULL FROM arena_sessions"
                            " WHERE id = CAST(:s AS uuid)"
                        ),
                        {"s": session_id},
                    )
                ).scalar_one()
            )

    async def _apply_result(
        self, session: dict, message_id: str, result: TurnResult, expected: str
    ) -> None:
        """Final status, pending ticket and win in ONE transaction (finding 3)."""
        view = result.player_view
        check_turn_transition(expected, view.status)
        async with self._engine.begin() as conn:
            if not await self._set_turn(
                conn, str(session["id"]), message_id, view.status, view, expected
            ):
                return  # another request already settled this turn
            await conn.execute(
                text("UPDATE arena_sessions SET pending_ticket_id = :t WHERE id = :s"),
                {
                    "t": view.ticket_id if view.status == "awaiting_review" else None,
                    "s": session["id"],
                },
            )
            if result.facts.secret_delivered:  # win rule: facts only (echo exclusion by AFF)
                await self._svc.record_win(str(session["id"]), message_id, conn=conn)

    async def _turn_out(self, session_id: str, message_id: str, remaining: int | None) -> dict:
        async with self._engine.connect() as conn:
            row = (
                (
                    await conn.execute(
                        text(
                            "SELECT message_id, text, status, player_view FROM arena_turns"
                            " WHERE session_id = CAST(:s AS uuid) AND message_id = :m"
                        ),
                        {"s": session_id, "m": message_id},
                    )
                )
                .mappings()
                .one()
            )
        return {
            **turn_payload(dict(row)),
            "won": await self._won(session_id),
            "remaining_messages": remaining,
        }

    # --- B-12 start screen ---------------------------------------------------------------

    async def levels_view(self, user: CurrentUser) -> dict:
        levels = await self._svc.list_levels()
        secrets = {s.level_id: s.compromised for s in await self._svc.get_secret_status()}
        async with self._engine.connect() as conn:
            won = {
                r[0]
                for r in await conn.execute(
                    text("SELECT DISTINCT level_id FROM results WHERE user_id = CAST(:u AS uuid)"),
                    {"u": user.id},
                )
            }
        catalog = await self._fw.read_catalog()
        return {
            "levels": [
                {
                    "level_id": lv.level_id,
                    "number": lv.number,
                    "name": lv.name,
                    "mode": lv.mode,
                    "secret_tier": lv.secret_tier,
                    "divert_enabled": lv.divert_enabled,
                    "obtained": lv.level_id in won,
                    "compromised": secrets.get(lv.level_id, False),
                }
                for lv in levels
            ],
            "rules": [r.model_dump() for r in catalog.rules],
            "remaining_messages": await self.remaining(user.id),
        }

    # --- B-05 start -----------------------------------------------------------------------

    async def start(self, user: CurrentUser, level_id: str) -> dict:
        if await self.remaining(user.id) <= 0:
            raise ArenaError(429, "hourly message limit reached")
        async with self._engine.connect() as conn:
            level = (
                (
                    await conn.execute(
                        text(
                            "SELECT * FROM levels WHERE level_id = :l"
                            " ORDER BY level_version DESC LIMIT 1"
                        ),
                        {"l": level_id},
                    )
                )
                .mappings()
                .first()
            )
            secret = (
                (
                    await conn.execute(
                        text(
                            "SELECT secret_version, value FROM secrets WHERE level_id = :l"
                            " ORDER BY secret_version DESC LIMIT 1"
                        ),
                        {"l": level_id},
                    )
                )
                .mappings()
                .first()
            )
            bot = (
                await conn.execute(text("SELECT bot_definition FROM scenario LIMIT 1"))
            ).scalar_one_or_none()
        if level is None or secret is None or bot is None:
            raise ArenaError(404 if level is None else 503, "level not available")
        req = RegisterSession(
            owner_ref=user.id,
            agent=AgentDefinition(
                system_prompt=bot["system_prompt"],
                tools=[
                    ToolDef(name=t["name"], json_schema=t["json_schema"], high_risk=t["high_risk"])
                    for t in bot["tools"]
                ],
                model_id=self._settings.bot_model_id or "unpinned",
            ),
            level=LevelConfig(
                level_id=level["level_id"],
                level_version=level["level_version"],
                mode=level["mode"],
                rule_version=level["rule_version"],
                weights=level["weights"],
                thresholds=level["thresholds"],
                review_timeout_s=level["review_timeout_s"],
                divert_enabled=level["divert_enabled"],
            ),
            secret=secret["value"],
            mock_state_seed=build_mock_state(level_id, secret["value"]),
        )
        try:
            async with asyncio.timeout(self._settings.aff_timeout_s):
                handle = await self._fw.register_session(req)
        except (TimeoutError, FirewallError, OSError) as exc:
            raise ArenaError(503, "firewall unavailable, session not started") from exc
        async with self._engine.begin() as conn:
            row = (
                await conn.execute(
                    text(
                        "INSERT INTO arena_sessions (user_id, level_id, level_version, mode,"
                        " fw_session_id, manifest_id, secret_version, admin_test)"
                        " VALUES (CAST(:u AS uuid), :l, :lv, :mode, :fws, :man, :sv, :admin)"
                        " RETURNING id"
                    ),
                    {
                        "u": user.id,
                        "l": level_id,
                        "lv": level["level_version"],
                        "mode": level["mode"],
                        "fws": handle.fw_session_id,
                        "man": handle.manifest_id,
                        "sv": secret["secret_version"],
                        "admin": user.has("firewall_admin"),
                    },
                )
            ).scalar_one()
        return session_payload(await self._owned(user, str(row)))

    # --- B-06..B-08 send ------------------------------------------------------------------

    async def send(
        self, user: CurrentUser, session_id: str, message_id: str, body: str, client: ClientMeta
    ) -> dict:
        session = await self._owned(user, session_id)
        if session["status"] != "active":
            raise ArenaError(409, "session is closed")
        async with self._engine.connect() as conn:
            prior = (
                (
                    await conn.execute(
                        text(
                            "SELECT text, status FROM arena_turns"
                            " WHERE session_id = CAST(:s AS uuid)"
                            " AND message_id = :m"
                        ),
                        {"s": session_id, "m": message_id},
                    )
                )
                .mappings()
                .first()
            )
        if prior is not None and prior["text"] != body:
            raise ArenaError(409, "message_id already used with different text")
        if prior is not None and prior["status"] in _FINAL:
            return await self._turn_out(session_id, message_id, await self.remaining(user.id))
        if prior is None and session["pending_ticket_id"]:
            raise ArenaError(409, "a request is pending human review")
        if await self._budget.remaining() <= 0:
            raise ArenaError(503, "the daily model budget is used up; try again tomorrow")
        remaining = await self._consume_slot(user.id, session_id, message_id)
        async with self._engine.begin() as conn:
            owned = await self._claim_turn(conn, session_id, message_id, body, prior)
        if not owned:
            raise ArenaError(409, "this message is still being processed")
        meta = (
            client
            if session["divert_enabled"]
            else client.model_copy(update={"fingerprint_hash": None})
        )
        try:
            async with asyncio.timeout(self._settings.aff_timeout_s):
                result = await self._fw.send_message(
                    user.id, session["fw_session_id"], message_id, body, meta
                )
        except (SessionBusy, MessageConflict, SessionClosed) as exc:
            await self._release(session_id, message_id)
            raise ArenaError(409, type(exc).__name__) from exc
        except NotFound as exc:
            await self._release(session_id, message_id)
            raise ArenaError(404, "session not found") from exc
        except asyncio.CancelledError:  # client went away: never leave the turn stuck in sent
            await asyncio.shield(self._release(session_id, message_id))
            raise
        except Exception:  # timeout, bot down, transport, anything unexpected: Not sent (§6.3)
            await self._release(session_id, message_id)
            return await self._turn_out(session_id, message_id, remaining)
        try:
            await self._apply_result(session, message_id, result, expected="sent")
        except Exception as exc:  # the AFF stored the result; a retry gets it back (E-01)
            await self._release(session_id, message_id)
            raise ArenaError(503, "could not record the result; retry the same message") from exc
        return await self._turn_out(session_id, message_id, remaining)

    async def _claim_turn(
        self, conn: AsyncConnection, session_id: str, message_id: str, body: str, prior: Any
    ) -> bool:
        """Only the owner of a turn calls the AFF (review findings 2 and 3)."""
        if prior is None:
            row = await conn.execute(
                text(
                    "INSERT INTO arena_turns (session_id, message_id, text, status)"
                    " VALUES (CAST(:s AS uuid), :m, :t, 'sent')"
                    " ON CONFLICT (session_id, message_id) DO NOTHING RETURNING message_id"
                ),
                {"s": session_id, "m": message_id, "t": body},
            )
            return row.first() is not None
        if prior["status"] == "not_sent":
            check_turn_transition("not_sent", "sent")
            return await self._set_turn(conn, session_id, message_id, "sent", None, "not_sent")
        stale = await conn.execute(  # a crashed owner left it in `sent`: take it over
            text(
                "UPDATE arena_turns SET updated_at = now() WHERE session_id = CAST(:s AS uuid)"
                " AND message_id = :m AND status = 'sent'"
                " AND updated_at < now() - make_interval(secs => :stale) RETURNING message_id"
            ),
            {
                "s": session_id,
                "m": message_id,
                "stale": self._settings.aff_timeout_s + STALE_GRACE_S,
            },
        )
        return stale.first() is not None

    async def _release(self, session_id: str, message_id: str) -> None:
        async with self._engine.begin() as conn:
            await self._set_turn(conn, session_id, message_id, "not_sent", None, "sent")

    # --- B-09 ticket polling --------------------------------------------------------------

    async def check_ticket(self, user: CurrentUser, session_id: str, ticket_id: str) -> dict:
        session = await self._owned(user, session_id)
        async with self._engine.connect() as conn:
            turn = (
                (
                    await conn.execute(
                        text(
                            "SELECT message_id, status FROM arena_turns"
                            " WHERE session_id = CAST(:s AS uuid)"
                            " AND ticket_id = :t"
                        ),
                        {"s": session_id, "t": ticket_id},
                    )
                )
                .mappings()
                .first()
            )
        if turn is None:
            raise ArenaError(404, "ticket not found")
        if turn["status"] == "awaiting_review":
            await self._sync_ticket(user, session, turn["message_id"], ticket_id)
        return await self._turn_out(session_id, turn["message_id"], await self.remaining(user.id))

    async def _sync_ticket(
        self, user: CurrentUser, session: dict, message_id: str, ticket_id: str
    ) -> None:
        try:
            ticket = await self._fw.check_ticket(user.id, ticket_id)
        except FirewallError as exc:
            raise ArenaError(503, "firewall unavailable") from exc
        if ticket.status == "pending" or ticket.turn_result is None:
            return
        result = ticket.turn_result
        view = result.player_view.model_copy(update={"ticket_id": ticket_id})
        await self._apply_result(
            session,
            message_id,
            result.model_copy(update={"player_view": view}),
            expected="awaiting_review",
        )

    # --- B-10 close, B-11 recap ----------------------------------------------------------

    async def close(self, user: CurrentUser, session_id: str) -> dict:
        session = await self._owned(user, session_id)
        if session["status"] == "active":
            try:
                await self._fw.close_session(user.id, session["fw_session_id"])
            except SessionClosed:
                pass  # already closed on the AFF side (finding 4): finish closing locally
            except FirewallError as exc:
                raise ArenaError(503, "firewall unavailable, session not closed") from exc
            if session["pending_ticket_id"]:  # the AFF expired it; reflect it if we can
                async with self._engine.connect() as conn:
                    mid = (
                        await conn.execute(
                            text("SELECT message_id FROM arena_turns WHERE ticket_id = :t"),
                            {"t": session["pending_ticket_id"]},
                        )
                    ).scalar_one_or_none()
                if mid:
                    with contextlib.suppress(ArenaError):  # non-fatal; polling still works later
                        await self._sync_ticket(user, session, mid, session["pending_ticket_id"])
            async with self._engine.begin() as conn:
                await conn.execute(
                    text(
                        "UPDATE arena_sessions SET status = 'closed', closed_at = now(),"
                        " pending_ticket_id = NULL, recap_unlocked_at = COALESCE(recap_unlocked_at,"
                        " now()) WHERE id = :s AND status = 'active'"
                    ),
                    {"s": session["id"]},
                )
        return session_payload(await self._owned(user, session_id))

    async def recap(self, user: CurrentUser, session_id: str) -> dict:
        session = await self._owned(user, session_id)
        if session["status"] != "closed" and session["recap_unlocked_at"] is None:
            raise ArenaError(403, "the recap opens after you close the session or start a quiz")
        thresholds = session["thresholds"]
        decisions = await self._read.get_decisions(session["fw_session_id"])
        diverts = await self._read.get_diverts(session["fw_session_id"])
        return {
            "items": [
                {
                    "message_id": d.message_id,
                    "stage": d.stage,
                    "decision": d.decision,
                    "rule_ids": d.rule_ids,
                    "score_band": _band(d.sentinel_score, thresholds),
                }
                for d in decisions
            ],
            "diverts": [
                {
                    "stage": d.stage,
                    "tool": d.tool,
                    "attempted": d.attempted_summary,
                    "decoy_shown": d.decoy_shown,
                }
                for d in diverts
            ],
        }

    # --- C-10 my sessions, session detail --------------------------------------------------

    async def my_sessions(self, user: CurrentUser) -> list[dict]:
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    text(
                        "SELECT s.*, l.name AS level_name, l.divert_enabled, l.thresholds"
                        " FROM arena_sessions s JOIN levels l ON l.level_id = s.level_id"
                        " AND l.level_version = s.level_version"
                        " WHERE s.user_id = CAST(:u AS uuid) ORDER BY s.started_at DESC LIMIT 200"
                    ),
                    {"u": user.id},
                )
            ).mappings()
            return [session_payload(dict(r)) for r in rows]

    async def detail(self, user: CurrentUser, session_id: str) -> dict:
        session = await self._owned(user, session_id)
        async with self._engine.connect() as conn:
            turns = (
                await conn.execute(
                    text(
                        "SELECT message_id, text, status, player_view FROM arena_turns"
                        " WHERE session_id = CAST(:s AS uuid) ORDER BY created_at"
                    ),
                    {"s": session_id},
                )
            ).mappings()
            turn_list = [turn_payload(dict(t)) for t in turns]
        return {
            **session_payload(session),
            "turns": turn_list,
            "remaining_messages": await self.remaining(user.id),
        }


def session_payload(row: dict) -> dict:
    return {
        "id": str(row["id"]),
        "user_id": str(row["user_id"]),
        "level_id": row["level_id"],
        "level_name": row.get("level_name"),
        "level_version": row["level_version"],
        "mode": row["mode"],
        "secret_version": row["secret_version"],
        "status": row["status"],
        "admin_test": row["admin_test"],
        "divert_enabled": row.get("divert_enabled"),
        "won": row["secret_obtained_at"] is not None,
        "pending_ticket_id": row["pending_ticket_id"],
        "started_at": row["started_at"].isoformat(),
        "closed_at": row["closed_at"].isoformat() if row["closed_at"] else None,
    }


def turn_payload(row: dict) -> dict:
    """A turn as the browser may see it: player_view fields only (I-3)."""
    view = row.get("player_view") or {}
    if isinstance(view, str):
        view = json.loads(view)
    status = row["status"]
    reply = NOT_SENT_MESSAGE if status == "not_sent" else view.get("reply")
    return {
        "message_id": row["message_id"],
        "text": row["text"],
        "status": status,
        "reply": reply,
        "tool_effects": view.get("tool_effects", []),
        "ticket_id": view.get("ticket_id"),
        "defense_feed": view.get("defense_feed", []),
    }
