"""M4 B-02: one batched read of users (id, name); no N+1."""

from __future__ import annotations

import uuid

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.classroom.users_repo import names_for


async def _add(engine: AsyncEngine, sub: str, name: str | None) -> str:
    async with engine.begin() as conn:
        row = await conn.execute(
            text("INSERT INTO users (auth0_sub, name) VALUES (:s, :n) RETURNING id"),
            {"s": sub, "n": name},
        )
        return str(row.scalar_one())


async def test_returns_names_by_id_in_one_statement(engine: AsyncEngine) -> None:
    ada = await _add(engine, "auth0|ada", "Ada")
    ben = await _add(engine, "auth0|ben", None)
    statements: list[str] = []

    def count(conn, cursor, statement, *a):  # type: ignore[no-untyped-def]
        statements.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", count)
    try:
        got = await names_for(engine, [ada, ben, ada])
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", count)
    assert got == {ada: "Ada", ben: None}
    assert len(statements) == 1


async def test_unknown_and_malformed_ids_are_skipped(engine: AsyncEngine) -> None:
    ada = await _add(engine, "auth0|ada", "Ada")
    got = await names_for(engine, [ada, str(uuid.uuid4()), "not-a-uuid", ""])
    assert got == {ada: "Ada"}


async def test_empty_input_does_not_query(engine: AsyncEngine) -> None:
    assert await names_for(engine, []) == {}
