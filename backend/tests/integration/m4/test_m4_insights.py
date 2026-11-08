"""M4 B-04 class insights: teacher only (M4-X03), panels from C3/C4 and the quiz views, X09."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import text

from app.classroom.dev_seed import add_level, add_session, now
from app.contracts.firewall_read import (
    DecisionCount,
    FamilyCount,
    PatternCount,
    RuleCount,
)
from tests.m4_support import World

URL = "/api/classroom/insights"


async def _seed(w: World):  # type: ignore[no-untyped-def]
    cho = await w.persona("Cho", "teacher")
    ada = await w.persona("Ada", "student")
    ben = await w.persona("Ben", "student")
    add_level(w.arena, "L1", 1, "Warm-up", "off")
    add_level(w.arena, "L2", 2, "Guarded", "basic")
    old = now() - timedelta(days=3)
    s1 = add_session(
        w.arena, w.read, user_id=ada.id, level_id="L1", mode="off", obtained=True, started_at=old
    )
    s2 = add_session(w.arena, w.read, user_id=ada.id, level_id="L2", mode="basic")
    s3 = add_session(w.arena, w.read, user_id=ben.id, level_id="L2", mode="basic", started_at=old)
    add_session(w.arena, w.read, user_id=cho.id, level_id="L2", mode="basic", admin_test=True)
    w.read.rule_counts = [RuleCount(rule_id=f"R{i}", count=20 - i) for i in range(12)]
    w.read.pattern_counts = [
        PatternCount(pattern_id="P1", count=3),
        PatternCount(pattern_id="P2", count=9),
    ]
    w.read.decision_counts = [
        DecisionCount(mode="basic", decision="deny", count=7),
        DecisionCount(mode="basic", decision="allow", count=30),
        DecisionCount(mode="strict", decision="divert", count=4),
    ]
    w.read.family_counts = [
        FamilyCount(attack_family="direct_injection", count=5),
        FamilyCount(attack_family="roleplay", count=2),
    ]
    return cho, ada, ben, s1, s2, s3


async def _insights(w: World, who, **params):  # type: ignore[no-untyped-def]
    return await w.client.get(URL, params=params, headers=who.headers)


async def test_x03_student_is_refused_staff_allowed(world: World) -> None:
    cho, ada, *_ = await _seed(world)
    dee = await world.persona("Dee", "firewall_admin")
    assert (await _insights(world, ada)).status_code == 403
    assert (await _insights(world, dee)).status_code == 200  # admin reads everything
    assert (await _insights(world, cho)).status_code == 200
    assert (await world.client.get(URL)).status_code == 401


async def test_overview_counts_students_and_sessions_without_admin_tests(world: World) -> None:
    cho, *_ = await _seed(world)
    ov = (await _insights(world, cho)).json()["overview"]
    assert ov["students"] == 2
    assert ov["sessions"] == 3
    assert ov["sessions_per_student"] == 1.5
    assert ov["active_today"] == 1  # only Ada's L2 session is recent


async def test_admin_tests_can_be_included_on_request(world: World) -> None:
    cho, *_ = await _seed(world)
    ov = (await _insights(world, cho, include_admin_test="true")).json()["overview"]
    assert ov["sessions"] == 4 and ov["students"] == 3


async def test_outcomes_per_level_in_level_order(world: World) -> None:
    cho, *_ = await _seed(world)
    rows = (await _insights(world, cho)).json()["outcomes"]
    assert [r["level_id"] for r in rows] == ["L1", "L2"]
    assert rows[0] == {**rows[0], "sessions": 1, "obtained": 1, "not_obtained": 0, "rate": 1.0}
    assert rows[1]["sessions"] == 2 and rows[1]["obtained"] == 0 and rows[1]["rate"] == 0.0
    assert rows[1]["level_name"] == "Guarded"


async def test_defense_activity_from_c3(world: World) -> None:
    cho, *_ = await _seed(world)
    d = (await _insights(world, cho)).json()["defense"]
    assert len(d["top_rules"]) == 10 and d["top_rules"][0] == {"rule_id": "R0", "count": 20}
    assert {"mode": "basic", "decision": "deny", "count": 7} in d["decisions"]
    assert d["divert_count"] == 4


async def test_attack_families_and_risky_patterns_sorted_by_count(world: World) -> None:
    cho, *_ = await _seed(world)
    body = (await _insights(world, cho)).json()
    assert [f["attack_family"] for f in body["attack_families"]] == ["direct_injection", "roleplay"]
    assert [p["pattern_id"] for p in body["risky_patterns"]] == ["P2", "P1"]


async def test_filters_are_validated(world: World) -> None:
    cho, *_ = await _seed(world)
    assert (await _insights(world, cho, mode="godmode")).status_code == 422
    assert (await _insights(world, cho, level="L2", mode="basic")).status_code == 200


async def _quiz(w, sid, uid, status, attempt, percent=None, items=None):  # type: ignore[no-untyped-def]
    import json

    async with w.engine.begin() as conn:
        qid = (
            await conn.execute(
                text(
                    "INSERT INTO quiz (session_id, user_id, attempt_number, status, rubric_version)"
                    " VALUES (:s, :u, :a, :st, 'r1') RETURNING id"
                ),
                {"s": sid, "u": uid, "a": attempt, "st": status},
            )
        ).scalar_one()
        if percent is not None:
            await conn.execute(
                text(
                    "INSERT INTO quiz_result (quiz_id, rubric_version, mcq_points, item_scores,"
                    " total_points, percent, feedback)"
                    " VALUES (:q, 'r1', 1, CAST(:i AS jsonb), 1, :p, 'f')"
                ),
                {"q": qid, "i": json.dumps(items or {}), "p": percent},
            )


async def test_quiz_panel_counts_averages_and_weakest_items(world: World) -> None:
    cho, ada, ben, s1, s2, s3 = await _seed(world)
    full = {"attack": 3, "why": 2, "defense_layer": 0, "prevention": 1}
    await _quiz(world, s1.id, ada.id, "done", 1, 80, full)
    await _quiz(
        world,
        s3.id,
        ben.id,
        "done",
        1,
        40,
        {"attack": 1, "why": 2, "defense_layer": 0, "prevention": 1},
    )
    await _quiz(world, s2.id, ada.id, "assigned", 1)
    q = (await _insights(world, cho)).json()["quiz"]
    assert q["taken"] == 2 and q["open"] == 1 and q["average_percent"] == 60
    weakest = q["lowest_items"]
    assert weakest[0] == {"item": "defense_layer", "title": "Defense layer", "average": 0.0, "n": 2}
    assert [w["item"] for w in weakest][-1] == "why"


async def test_quiz_panel_is_empty_but_valid_with_no_quizzes(world: World) -> None:
    cho, *_ = await _seed(world)
    q = (await _insights(world, cho)).json()["quiz"]
    assert q == {"taken": 0, "open": 0, "average_percent": None, "lowest_items": []}


async def test_empty_class(world: World) -> None:
    cho = await world.persona("Cho", "teacher")
    body = (await _insights(world, cho)).json()
    assert body["overview"] == {
        "students": 0,
        "sessions": 0,
        "sessions_per_student": 0.0,
        "active_today": 0,
    }
    assert body["outcomes"] == [] and body["attack_families"] == []


async def test_x09_a_new_session_shows_up_on_the_next_read(world: World) -> None:
    """The panels read live from C3/C4, so freshness is bounded by M2's 1-minute aggregates."""
    cho, ada, *_ = await _seed(world)
    before = (await _insights(world, cho)).json()["overview"]["sessions"]
    add_session(world.arena, world.read, user_id=ada.id, level_id="L1", mode="off")
    assert (await _insights(world, cho)).json()["overview"]["sessions"] == before + 1
