"""`record_audit` joins the caller's transaction (PRD §11 Audit log, §15.1 Atomicity)."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.db.audit import record_audit


async def test_record_audit_writes_before_and_after(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        audit_id = await record_audit(
            conn,
            actor_id=None,
            entity="secret",
            entity_id="lvl-1",
            action="rotate",
            before={"secret_version": 1},
            after={"secret_version": 2},
        )
    async with engine.connect() as conn:
        row = (
            await conn.execute(
                text("SELECT entity, action, before, after, time FROM audit_log WHERE id = :i"),
                {"i": audit_id},
            )
        ).one()
    assert row.entity == "secret" and row.action == "rotate"
    assert row.before == {"secret_version": 1} and row.after == {"secret_version": 2}
    assert row.time.tzinfo is not None


async def test_record_audit_rolls_back_with_caller(engine: AsyncEngine) -> None:
    class Boom(Exception):
        pass

    with pytest.raises(Boom):
        async with engine.begin() as conn:
            await record_audit(
                conn,
                actor_id=None,
                entity="level",
                entity_id="lvl-2",
                action="save_version",
                before=None,
                after={"level_version": 2},
            )
            raise Boom
    async with engine.connect() as conn:
        count = (await conn.execute(text("SELECT count(*) FROM audit_log"))).scalar_one()
    assert count == 0


async def test_record_audit_never_stores_secret_values(engine: AsyncEngine) -> None:
    with pytest.raises(ValueError, match="secret value"):
        async with engine.begin() as conn:
            await record_audit(
                conn,
                actor_id=None,
                entity="secret",
                entity_id="lvl-1",
                action="rotate",
                before=None,
                after={"value": "DEMO_TOKEN_42"},
            )
