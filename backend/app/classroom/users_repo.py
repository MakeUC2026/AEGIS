"""One batched, read-only lookup of user names (the only direct SQL M4 runs on `users`)."""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

_SQL = text("SELECT id, name FROM users WHERE id = ANY(:ids)")


def _valid_ids(ids: Iterable[str]) -> list[uuid.UUID]:
    found: dict[uuid.UUID, None] = {}
    for raw in ids:
        try:
            found[uuid.UUID(raw)] = None
        except (ValueError, AttributeError, TypeError):
            continue
    return list(found)


async def names_for(db: AsyncEngine | AsyncConnection, ids: Iterable[str]) -> dict[str, str | None]:
    """`{user_id: name}` for the ids that exist, in a single SELECT. Bad ids are skipped."""
    wanted = _valid_ids(ids)
    if not wanted:
        return {}
    if isinstance(db, AsyncEngine):
        async with db.connect() as conn:
            rows = (await conn.execute(_SQL, {"ids": wanted})).all()
    else:
        rows = (await db.execute(_SQL, {"ids": wanted})).all()
    return {str(r[0]): r[1] for r in rows}


_BY_NAME = text("SELECT id, name FROM users WHERE name = ANY(:names) ORDER BY created_at")


async def ids_by_name(db: AsyncEngine, names: Iterable[str]) -> dict[str, str]:
    """`{name: id}` for the given display names in one SELECT (dev seed only). The earliest
    user wins when two share a name."""
    wanted = sorted(set(names))
    if not wanted:
        return {}
    async with db.connect() as conn:
        rows = (await conn.execute(_BY_NAME, {"names": wanted})).all()
    found: dict[str, str] = {}
    for user_id, name in rows:
        found.setdefault(name, str(user_id))
    return found
