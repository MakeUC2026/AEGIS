"""Demo seed and reset (M1 D-02): scenario, levels, secrets, demo accounts, other parts' seeds.
Idempotent without reset; reset wipes every app table and reseeds."""

from __future__ import annotations

import sys
import types

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app import demo
from app.demo import DEMO_USERS, seed_demo


async def _scalar(engine: AsyncEngine, sql: str) -> object:
    async with engine.connect() as conn:
        return (await conn.execute(text(sql))).scalar()


async def _secrets(engine: AsyncEngine) -> dict[str, str]:
    async with engine.connect() as conn:
        rows = await conn.execute(text("SELECT level_id, value FROM secrets"))
        return {r.level_id: r.value for r in rows}


async def test_seeds_accounts_levels_and_secrets(engine: AsyncEngine) -> None:
    report = await seed_demo(engine)
    async with engine.connect() as conn:
        rows = await conn.execute(text("SELECT auth0_sub, role FROM users"))
        users = {r.auth0_sub: r.role for r in rows}
    assert users == {
        "dev|student-ada": "student",
        "dev|student-ben": "student",
        "dev|teacher-cho": "teacher",
        "dev|admin-dee": "firewall_admin",
        "dev|both-eli": "firewall_admin",  # primary_role, exactly as on sign-in
    }
    assert await _scalar(engine, "SELECT count(*) FROM levels") == 3
    assert set(await _secrets(engine)) == {"lvl-1", "lvl-2", "lvl-3"}
    assert report.accounts == len(DEMO_USERS)
    assert report.reset is False


async def test_rerun_without_reset_changes_nothing(engine: AsyncEngine) -> None:
    await seed_demo(engine)
    before = await _secrets(engine)
    await seed_demo(engine)
    assert await _secrets(engine) == before
    assert await _scalar(engine, "SELECT count(*) FROM users") == len(DEMO_USERS)
    assert await _scalar(engine, "SELECT count(*) FROM levels") == 3


async def test_reset_wipes_play_data_and_reseeds(engine: AsyncEngine) -> None:
    await seed_demo(engine)
    before = await _secrets(engine)
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO users (auth0_sub, role) VALUES ('auth0|x', 'student')")
        )
        await conn.execute(
            text(
                "INSERT INTO arena_sessions (user_id, level_id, level_version, mode,"
                " fw_session_id, manifest_id, secret_version) SELECT id, 'lvl-1', 1, 'off',"
                " 'fws-x', 'man-x', 1 FROM users WHERE auth0_sub = 'auth0|x'"
            )
        )
    report = await seed_demo(engine, reset=True)
    assert report.reset is True
    assert await _scalar(engine, "SELECT count(*) FROM arena_sessions") == 0
    assert await _scalar(engine, "SELECT count(*) FROM users WHERE auth0_sub = 'auth0|x'") == 0
    assert await _scalar(engine, "SELECT count(*) FROM users") == len(DEMO_USERS)
    after = await _secrets(engine)
    assert set(after) == set(before)
    assert all(after[k] != before[k] for k in before)  # fresh secrets after a reset
    assert await _scalar(engine, "SELECT count(*) FROM alembic_version") >= 1


async def test_other_parts_seeders_run_when_present(
    engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[AsyncEngine] = []

    async def fake_seed(e: AsyncEngine) -> None:
        calls.append(e)

    mod = types.ModuleType("aegis_test_part_seed")
    mod.seed = fake_seed  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aegis_test_part_seed", mod)
    monkeypatch.setattr(
        demo, "PART_SEEDERS", ("aegis_test_part_seed:seed", "app.not_on_this_branch.seed:seed")
    )
    report = await seed_demo(engine)
    assert calls == [engine]
    assert report.parts_seeded == ["aegis_test_part_seed"]
    assert report.parts_skipped == ["app.not_on_this_branch.seed"]
