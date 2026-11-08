"""C4/C8 arena service (M1 C-11, C-12; PRD §5.2, §5.3, §12.4; M1-X13, X14, X15, X28)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.arena.seed import seed
from app.arena.service import ArenaService
from app.contracts.arena import LevelConfigUpdate, SessionFilters


async def _user(engine: AsyncEngine, sub: str) -> str:
    async with engine.begin() as conn:
        return str(
            (
                await conn.execute(
                    text("INSERT INTO users (auth0_sub) VALUES (:s) RETURNING id"), {"s": sub}
                )
            ).scalar_one()
        )


async def _session(engine: AsyncEngine, user_id: str, level: str, n: int, **extra: object) -> str:
    async with engine.begin() as conn:
        row = await conn.execute(
            text(
                "INSERT INTO arena_sessions (user_id, level_id, level_version, mode, fw_session_id,"
                " manifest_id, secret_version, admin_test) VALUES (:u, :l, 1, 'off', :f, 'man', 1,"
                " :admin) RETURNING id"
            ),
            {"u": user_id, "l": level, "f": f"fws-{n}", "admin": bool(extra.get("admin_test"))},
        )
        return str(row.scalar_one())


@pytest.fixture
async def svc(engine: AsyncEngine) -> ArenaService:
    await seed(engine)
    return ArenaService(engine)


async def test_list_levels_returns_latest_versions(svc: ArenaService) -> None:
    levels = await svc.list_levels()
    assert [(lv.level_id, lv.mode, lv.level_version) for lv in levels] == [
        ("lvl-1", "off", 1),
        ("lvl-2", "basic", 1),
        ("lvl-3", "strict", 1),
    ]


async def test_save_level_version_creates_new_version_and_audits(
    svc: ArenaService, engine: AsyncEngine
) -> None:
    admin = await _user(engine, "auth0|admin")
    saved = await svc.save_level_version(
        LevelConfigUpdate(level_id="lvl-2", review_timeout_s=90), actor=admin
    )
    assert saved.level_version == 2 and saved.review_timeout_s == 90
    assert saved.thresholds == {"review": 40, "deny": 70, "divert": 95, "alert": 99}  # kept
    assert [lv.level_version for lv in await svc.list_levels() if lv.level_id == "lvl-2"] == [2]
    async with engine.connect() as conn:
        audit = (
            (await conn.execute(text("SELECT entity, entity_id, action, after FROM audit_log")))
            .mappings()
            .one()
        )
    assert (audit["entity"], audit["entity_id"], audit["action"]) == (
        "level",
        "lvl-2",
        "save_version",
    )
    assert audit["after"]["level_version"] == 2


async def test_bad_thresholds_are_rejected() -> None:
    with pytest.raises(ValidationError):
        LevelConfigUpdate(
            level_id="lvl-2", thresholds={"review": 80, "deny": 70, "divert": 95, "alert": 99}
        )


async def test_rotate_secret_new_version_audited_without_value(
    svc: ArenaService, engine: AsyncEngine
) -> None:  # M1-X14 (service part)
    teacher = await _user(engine, "auth0|teacher")
    async with engine.connect() as conn:
        old = (
            await conn.execute(text("SELECT value FROM secrets WHERE level_id = 'lvl-1'"))
        ).scalar_one()
    status = await svc.rotate_secret("lvl-1", actor=teacher)
    assert status.secret_version == 2 and status.compromised is False
    async with engine.connect() as conn:
        values = [
            r[0]
            for r in await conn.execute(
                text("SELECT value FROM secrets WHERE level_id = 'lvl-1' ORDER BY secret_version")
            )
        ]
        audit_json = (
            await conn.execute(text("SELECT before::text || after::text FROM audit_log"))
        ).scalar_one()
    assert values[0] == old and values[1] != old
    assert old not in audit_json and values[1] not in audit_json
    latest = {s.level_id: s.secret_version for s in await svc.get_secret_status()}
    assert latest == {"lvl-1": 2, "lvl-2": 1, "lvl-3": 1}


async def test_compromise_records_first_delivery_only(
    svc: ArenaService, engine: AsyncEngine
) -> None:  # M1-X15
    a, b = await _user(engine, "auth0|a"), await _user(engine, "auth0|b")
    sa, sb = await _session(engine, a, "lvl-1", 1), await _session(engine, b, "lvl-1", 2)
    assert await svc.record_win(sa, "m1") is True
    assert await svc.record_win(sb, "m1") is True  # b also wins...
    assert await svc.record_win(sa, "m2") is False  # ...but a session wins only once
    status = next(s for s in await svc.get_secret_status() if s.level_id == "lvl-1")
    assert status.compromised and status.compromised_by_user == a  # first one kept
    assert status.compromised_by_session == sa


async def test_unlock_recap_sets_once(svc: ArenaService, engine: AsyncEngine) -> None:
    sid = await _session(engine, await _user(engine, "auth0|u"), "lvl-2", 3)
    await svc.unlock_recap(sid)
    first = (await svc.get_session(sid)).recap_unlocked_at  # type: ignore[union-attr]
    await svc.unlock_recap(sid)
    assert first is not None and (await svc.get_session(sid)).recap_unlocked_at == first  # type: ignore[union-attr]


async def test_list_sessions_filters(svc: ArenaService, engine: AsyncEngine) -> None:  # M1-X28
    a, b = await _user(engine, "auth0|a2"), await _user(engine, "auth0|b2")
    sa = await _session(engine, a, "lvl-1", 4)
    await _session(engine, b, "lvl-2", 5, admin_test=True)
    await svc.record_win(sa, "m1")
    assert {s.user_id for s in await svc.list_sessions(SessionFilters())} == {a, b}
    assert [s.id for s in await svc.list_sessions(SessionFilters(user_id=a))] == [sa]
    assert [s.id for s in await svc.list_sessions(SessionFilters(outcome="obtained"))] == [sa]
    assert [s.admin_test for s in await svc.list_sessions(SessionFilters(admin_test=True))] == [
        True
    ]
    assert await svc.get_session("00000000-0000-0000-0000-000000000000") is None
