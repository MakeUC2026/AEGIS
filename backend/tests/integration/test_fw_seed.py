"""M2 B-02 starting-rules seed and the DM1-2 seed hook (PRD §9.2; M1 D-02)."""

from __future__ import annotations

import json

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.contracts.firewall_admin import RuleForm
from app.demo import seed_demo
from app.firewall.seed import BUILTIN_RULE_IDS, seed
from app.firewall.starting_rules import RULE_SET_VERSION, STARTING_RULES


async def _rules(engine: AsyncEngine) -> list[dict]:
    async with engine.connect() as conn:
        rows = await conn.execute(
            text(
                "SELECT rule_id, version, set_version, builtin, enabled, deprecated, form"
                " FROM rules ORDER BY rule_id"
            )
        )
        return [dict(r._mapping) for r in rows]


async def test_seed_writes_rule_set_one_with_every_starting_rule(engine: AsyncEngine) -> None:
    await seed(engine)
    rows = await _rules(engine)
    assert [r["rule_id"] for r in rows] == [
        "B-01", "B-02", "B-03", "B-04", "R-001", "R-002", "R-003", "R-004", "R-005", "R-006",
    ]  # fmt: skip
    assert BUILTIN_RULE_IDS == ("B-01", "B-02", "B-03", "B-04")
    assert all(r["version"] == 1 and r["set_version"] == RULE_SET_VERSION for r in rows)
    assert all(r["enabled"] and not r["deprecated"] for r in rows)
    assert all((r["form"] is None) == r["builtin"] for r in rows)


async def test_seeded_forms_round_trip_exactly(engine: AsyncEngine) -> None:
    await seed(engine)
    stored = {r["rule_id"]: r["form"] for r in await _rules(engine) if not r["builtin"]}
    for rule_id, form in STARTING_RULES:
        raw = stored[rule_id]
        loaded = RuleForm(**(json.loads(raw) if isinstance(raw, str) else raw))
        assert loaded == form


async def test_seed_is_idempotent(engine: AsyncEngine) -> None:
    await seed(engine)
    await seed(engine)  # no error from the append-only trigger, no duplicates
    async with engine.connect() as conn:
        rules = (await conn.execute(text("SELECT count(*) FROM rules"))).scalar_one()
        sets = (await conn.execute(text("SELECT count(*) FROM rule_sets"))).scalar_one()
    assert (rules, sets) == (10, 1)


async def test_demo_seed_picks_up_the_firewall_seed(engine: AsyncEngine) -> None:
    report = await seed_demo(engine)
    assert "app.firewall.seed" in report.parts_seeded
    assert "app.firewall.seed" not in report.parts_skipped
    assert len(await _rules(engine)) == 10
