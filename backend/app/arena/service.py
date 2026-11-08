"""C4 (arena read) and C8 (arena admin and teacher operations), plus the read helpers the
arena play flow needs (M1 C-11, C-12; PRD §5.2, §5.3, §12.4, §14.5).

All SQL is parameterized (CONST-SEC-005). Every C8 write is audited in the same transaction.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.arena.seed import new_secret
from app.contracts.arena import (
    ArenaSession,
    LevelConfigUpdate,
    LevelSummary,
    SecretStatus,
    SessionFilters,
)
from app.contracts.firewall import NotFound
from app.db.audit import record_audit

_SESSION_COLS = (
    "id, user_id, level_id, level_version, mode, fw_session_id, manifest_id, secret_version,"
    " status, secret_obtained_at, started_at, closed_at, admin_test, recap_unlocked_at"
)
_GET_SESSION = f"SELECT {_SESSION_COLS} FROM arena_sessions WHERE id = CAST(:id AS uuid)"  # noqa: S608
_LATEST_LEVELS = "SELECT DISTINCT ON (level_id) * FROM levels ORDER BY level_id, level_version DESC"
_LATEST_SECRETS = (
    "SELECT DISTINCT ON (level_id) * FROM secrets ORDER BY level_id, secret_version DESC"
)


def _session(row: Any) -> ArenaSession:
    data = dict(row)
    return ArenaSession(**{**data, "id": str(data["id"]), "user_id": str(data["user_id"])})


def _level(row: Any) -> LevelSummary:
    keys = LevelSummary.model_fields
    return LevelSummary(**{k: v for k, v in dict(row).items() if k in keys})


def _secret_status(row: Any) -> SecretStatus:
    d = dict(row)
    return SecretStatus(
        level_id=d["level_id"],
        secret_version=d["secret_version"],
        compromised=d["compromised_at"] is not None,
        compromised_by_user=str(d["compromised_by_user"]) if d["compromised_by_user"] else None,
        compromised_by_session=str(d["compromised_by_session"])
        if d["compromised_by_session"]
        else None,
        compromised_at=d["compromised_at"],
        created_at=d["created_at"],
    )


class ArenaService:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    # --- C4 -------------------------------------------------------------------------------

    async def list_sessions(self, filters: SessionFilters) -> list[ArenaSession]:
        clauses, params = [], {"limit": filters.limit, "offset": filters.offset}
        for col in ("user_id", "level_id", "mode", "status", "admin_test"):
            value = getattr(filters, col)
            if value is not None:
                clauses.append(f"{col} = :{col}")
                params[col] = value
        if filters.outcome == "obtained":
            clauses.append("secret_obtained_at IS NOT NULL")
        elif filters.outcome == "not_obtained":
            clauses.append("secret_obtained_at IS NULL")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            f"SELECT {_SESSION_COLS} FROM arena_sessions {where}"  # noqa: S608 - fixed column names
            " ORDER BY started_at DESC LIMIT :limit OFFSET :offset"
        )
        async with self._engine.connect() as conn:
            return [_session(r) for r in (await conn.execute(text(sql), params)).mappings()]

    async def get_session(self, session_id: str) -> ArenaSession | None:
        async with self._engine.connect() as conn:
            row = (
                (
                    await conn.execute(
                        text(_GET_SESSION),
                        {"id": session_id},
                    )
                )
                .mappings()
                .first()
            )
        return _session(row) if row else None

    async def list_levels(self) -> list[LevelSummary]:
        async with self._engine.connect() as conn:
            rows = (await conn.execute(text(_LATEST_LEVELS))).mappings()
            return sorted((_level(r) for r in rows), key=lambda lv: lv.number)

    # --- C8 -------------------------------------------------------------------------------

    async def save_level_version(self, update: LevelConfigUpdate, actor: str) -> LevelSummary:
        changes = update.model_dump(exclude={"level_id"}, exclude_none=True)
        async with self._engine.begin() as conn:
            current = (
                (
                    await conn.execute(
                        text(
                            "SELECT * FROM levels WHERE level_id = :l"
                            " ORDER BY level_version DESC LIMIT 1 FOR UPDATE"
                        ),
                        {"l": update.level_id},
                    )
                )
                .mappings()
                .first()
            )
            if current is None:
                raise NotFound(update.level_id)
            new = {**dict(current), **changes, "level_version": current["level_version"] + 1}
            row = (
                (
                    await conn.execute(
                        text(
                            "INSERT INTO levels (level_id, level_version, number, name, mode,"
                            " secret_tier, rule_version, weights, thresholds, review_timeout_s,"
                            " divert_enabled, created_by) VALUES (:level_id, :level_version,"
                            " :number, :name, :mode, :secret_tier, :rule_version,"
                            " CAST(:weights AS jsonb), CAST(:thresholds AS jsonb),"
                            " :review_timeout_s, :divert_enabled,"
                            " CAST(:actor AS uuid)) RETURNING *"
                        ),
                        {
                            **{
                                k: new[k]
                                for k in (
                                    "level_id",
                                    "level_version",
                                    "number",
                                    "name",
                                    "mode",
                                    "secret_tier",
                                    "rule_version",
                                    "review_timeout_s",
                                    "divert_enabled",
                                )
                            },
                            "weights": json.dumps(new["weights"]),
                            "thresholds": json.dumps(new["thresholds"]),
                            "actor": actor,
                        },
                    )
                )
                .mappings()
                .one()
            )
            await record_audit(
                conn,
                actor_id=actor,
                entity="level",
                entity_id=update.level_id,
                action="save_version",
                before={
                    "level_version": current["level_version"],
                    **{k: current[k] for k in changes},
                },
                after={"level_version": new["level_version"], **changes},
            )
        return _level(row)

    async def rotate_secret(self, level_id: str, actor: str) -> SecretStatus:
        async with self._engine.begin() as conn:
            prior = (
                await conn.execute(
                    text(
                        "SELECT secret_version FROM secrets WHERE level_id = :l"
                        " ORDER BY secret_version DESC LIMIT 1 FOR UPDATE"
                    ),
                    {"l": level_id},
                )
            ).scalar_one_or_none()
            if prior is None:
                raise NotFound(level_id)
            row = (
                (
                    await conn.execute(
                        text(
                            "INSERT INTO secrets (level_id, secret_version, value, created_by)"
                            " VALUES (:l, :v, :value, CAST(:actor AS uuid)) RETURNING *"
                        ),
                        {
                            "l": level_id,
                            "v": prior + 1,
                            "value": new_secret(level_id),
                            "actor": actor,
                        },
                    )
                )
                .mappings()
                .one()
            )
            await record_audit(
                conn,
                actor_id=actor,
                entity="secret",
                entity_id=level_id,
                action="rotate",
                before={"secret_version": prior},
                after={"secret_version": prior + 1},
            )
        return _secret_status(row)

    async def get_secret_status(self) -> list[SecretStatus]:
        async with self._engine.connect() as conn:
            rows = (await conn.execute(text(_LATEST_SECRETS))).mappings()
            return [_secret_status(r) for r in rows]

    async def unlock_recap(self, session_id: str) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                text(
                    "UPDATE arena_sessions SET recap_unlocked_at = COALESCE(recap_unlocked_at,"
                    " now()) WHERE id = CAST(:id AS uuid)"
                ),
                {"id": session_id},
            )

    # --- Play helpers (M1 only, not part of the contract) ---------------------------------

    async def record_win(
        self, session_id: str, message_id: str, conn: AsyncConnection | None = None
    ) -> bool:
        """Record a delivered secret; joins `conn`'s transaction when given (atomic with the
        turn's final status)."""
        if conn is not None:
            return await self._record_win(conn, session_id, message_id)
        async with self._engine.begin() as own:
            return await self._record_win(own, session_id, message_id)

    async def _record_win(self, conn: AsyncConnection, session_id: str, message_id: str) -> bool:
        """Record a delivered secret (PRD §5.3, §6.4). True only the first time this session
        wins; the level's secret version is marked compromised by the first winner only."""
        session = (
            (
                await conn.execute(
                    text(
                        "SELECT id, user_id, level_id, secret_version FROM arena_sessions"
                        " WHERE id = CAST(:id AS uuid) FOR UPDATE"
                    ),
                    {"id": session_id},
                )
            )
            .mappings()
            .one()
        )
        inserted = (
            await conn.execute(
                text(
                    "INSERT INTO results (session_id, user_id, level_id, secret_version,"
                    " message_id) VALUES (:s, :u, :l, :v, :m)"
                    " ON CONFLICT (session_id) DO NOTHING RETURNING session_id"
                ),
                {
                    "s": session["id"],
                    "u": session["user_id"],
                    "l": session["level_id"],
                    "v": session["secret_version"],
                    "m": message_id,
                },
            )
        ).first()
        if inserted is None:
            return False
        await conn.execute(
            text(
                "UPDATE arena_sessions SET secret_obtained_at = now() WHERE id = :s"
                " AND secret_obtained_at IS NULL"
            ),
            {"s": session["id"]},
        )
        await conn.execute(
            text(
                "UPDATE secrets SET compromised_at = now(), compromised_by_user = :u,"
                " compromised_by_session = :s WHERE level_id = :l AND secret_version = :v"
                " AND compromised_at IS NULL"
            ),
            {
                "u": session["user_id"],
                "s": session["id"],
                "l": session["level_id"],
                "v": session["secret_version"],
            },
        )
        return True


def create() -> ArenaService:
    """`ports.py` factory for the real C4/C8 implementation."""
    from app.db.engine import get_engine

    return ArenaService(get_engine())
