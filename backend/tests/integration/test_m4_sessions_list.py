"""M4 B-02 sessions list: M4-X01, X04, X07/X08 (parse), X10 and the quiz columns."""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import text

from app.classroom.dev_seed import add_level, add_session, now
from tests.m4_support import World, world  # noqa: F401

URL = "/api/classroom/sessions"


async def _seed(w: World) -> dict[str, str]:
    cho = await w.persona("Cho", "teacher")
    ada = await w.persona("Ada", "student")
    ben = await w.persona("Ben", "student")
    add_level(w.arena, "L1", 1, "Warm-up", "off")
    add_level(w.arena, "L2", 2, "Guarded", "basic")
    add_level(w.arena, "L3", 3, "Fortress", "strict")
    a1 = add_session(
        w.arena,
        w.read,
        user_id=ada.id,
        level_id="L1",
        mode="off",
        obtained=True,
        started_at=now() - timedelta(hours=3),
    )
    a2 = add_session(
        w.arena,
        w.read,
        user_id=ada.id,
        level_id="L3",
        mode="strict",
        scores=[("allow", 10), ("divert", 85)],
        diverts=[("read the vault", "fake vault")],
        started_at=now() - timedelta(hours=2),
    )
    b1 = add_session(
        w.arena,
        w.read,
        user_id=ben.id,
        level_id="L2",
        mode="basic",
        scores=[("deny", 65)],
        started_at=now() - timedelta(hours=1),
    )
    t1 = add_session(
        w.arena,
        w.read,
        user_id=cho.id,
        level_id="L2",
        mode="basic",
        admin_test=True,
        started_at=now() - timedelta(minutes=5),
    )
    return {
        "cho": cho.id,
        "ada": ada.id,
        "ben": ben.id,
        "a1": a1.id,
        "a2": a2.id,
        "b1": b1.id,
        "t1": t1.id,
    }


async def _get(w: World, who: str, **params: object):  # type: ignore[no-untyped-def]
    headers = (
        await w.persona(who, {"Cho": "teacher", "Dee": "firewall_admin"}.get(who, "student"))
    ).headers
    return await w.client.get(URL, params=params, headers=headers)


def _ids(resp) -> list[str]:  # type: ignore[no-untyped-def]
    return [row["id"] for row in resp.json()["items"]]


async def test_requires_auth(world: World) -> None:  # noqa: F811
    assert (await world.client.get(URL)).status_code == 401


async def test_teacher_sees_everything_newest_first_with_columns(world: World) -> None:  # noqa: F811
    ids = await _seed(world)
    resp = await _get(world, "Cho")
    assert resp.status_code == 200
    assert _ids(resp) == [ids["t1"], ids["b1"], ids["a2"], ids["a1"]]
    rows = {r["id"]: r for r in resp.json()["items"]}
    a2 = rows[ids["a2"]]
    assert a2["student_name"] == "Ada" and a2["level_name"] == "Fortress" and a2["mode"] == "strict"
    assert a2["diverted_count"] == 1 and a2["max_sentinel_score"] == 85
    assert a2["secret_obtained"] is False and rows[ids["a1"]]["secret_obtained"] is True
    assert a2["quiz_status"] == "not_taken" and a2["quiz_score"] is None
    assert resp.json()["total"] == 4


async def test_x01_student_only_sees_own_even_with_student_param(world: World) -> None:  # noqa: F811
    ids = await _seed(world)
    own = await _get(world, "Ada")
    assert set(_ids(own)) == {ids["a1"], ids["a2"]}
    spoof = await _get(world, "Ada", student=ids["ben"])
    assert set(_ids(spoof)) == {ids["a1"], ids["a2"]}


async def test_teacher_can_filter_by_student(world: World) -> None:  # noqa: F811
    ids = await _seed(world)
    assert _ids(await _get(world, "Cho", student=ids["ben"])) == [ids["b1"]]


async def test_x04_firewall_admin_can_read_the_list(world: World) -> None:  # noqa: F811
    await _seed(world)
    resp = await _get(world, "Dee")
    assert resp.status_code == 200 and resp.json()["total"] == 4


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"level": "L2"}, {"b1", "t1"}),
        ({"mode": "strict"}, {"a2"}),
        ({"outcome": "obtained"}, {"a1"}),
        ({"outcome": "not_obtained"}, {"a2", "b1", "t1"}),
        ({"diverted": "yes"}, {"a2"}),
        ({"diverted": "no"}, {"a1", "b1", "t1"}),
        ({"admin_test": "true"}, {"t1"}),
        ({"admin_test": "false"}, {"a1", "a2", "b1"}),
        ({"quiz_status": "not_taken"}, {"a1", "a2", "b1", "t1"}),
        ({"quiz_status": "done"}, set()),
        ({"level": "L2", "mode": "basic", "admin_test": "false"}, {"b1"}),
    ],
)
async def test_filters(world: World, params: dict[str, str], expected: set[str]) -> None:  # noqa: F811
    ids = await _seed(world)
    got = set(_ids(await _get(world, "Cho", **params)))
    assert got == {ids[k] for k in expected}


@pytest.mark.parametrize(
    "params",
    [
        {"mode": "godmode"},
        {"outcome": "maybe"},
        {"diverted": "sometimes"},
        {"quiz_status": "x"},
        {"admin_test": "perhaps"},
        {"limit": "0"},
        {"limit": "100000"},
        {"offset": "-1"},
    ],
)
async def test_x08_unknown_filter_values_are_422_not_500(
    world: World, params: dict[str, str]
) -> None:  # noqa: F811
    await _seed(world)
    assert (await _get(world, "Cho", **params)).status_code == 422


async def test_unknown_params_are_ignored(world: World) -> None:  # noqa: F811
    await _seed(world)
    assert (await _get(world, "Cho", colour="red")).status_code == 200


async def test_x10_admin_test_flag_is_present_on_rows(world: World) -> None:  # noqa: F811
    ids = await _seed(world)
    rows = {r["id"]: r for r in (await _get(world, "Cho")).json()["items"]}
    assert rows[ids["t1"]]["admin_test"] is True and rows[ids["a1"]]["admin_test"] is False


async def test_paging(world: World) -> None:  # noqa: F811
    ids = await _seed(world)
    page = await _get(world, "Cho", limit=2, offset=1)
    assert _ids(page) == [ids["b1"], ids["a2"]]
    assert page.json()["total"] == 4


async def _quiz(
    w: World, session_id: str, user_id: str, status: str, attempt: int, percent: int | None
) -> None:
    async with w.engine.begin() as conn:
        qid = (
            await conn.execute(
                text(
                    "INSERT INTO quiz (session_id, user_id, attempt_number, status, rubric_version)"
                    " VALUES (:s, :u, :a, :st, 'r1') RETURNING id"
                ),
                {"s": session_id, "u": user_id, "a": attempt, "st": status},
            )
        ).scalar_one()
        if percent is not None:
            await conn.execute(
                text(
                    "INSERT INTO quiz_result (quiz_id, rubric_version, mcq_points, item_scores,"
                    " total_points, percent, feedback) VALUES (:q, 'r1', 1, '{}', 1, :p, 'f')"
                ),
                {"q": qid, "p": percent},
            )


async def test_quiz_columns_show_status_latest_and_best(world: World) -> None:  # noqa: F811
    ids = await _seed(world)
    await _quiz(world, ids["a1"], ids["ada"], "done", 1, 88)
    await _quiz(world, ids["a1"], ids["ada"], "done", 2, 41)
    await _quiz(world, ids["a2"], ids["ada"], "assigned", 1, None)
    await _quiz(world, ids["b1"], ids["ben"], "grading_failed", 1, None)
    rows = {r["id"]: r for r in (await _get(world, "Cho")).json()["items"]}
    assert (
        rows[ids["a1"]]["quiz_status"],
        rows[ids["a1"]]["quiz_score"],
        rows[ids["a1"]]["quiz_best"],
    ) == ("done", 41, 88)
    assert rows[ids["a1"]]["quiz_attempts"] == 2
    assert rows[ids["a2"]]["quiz_status"] == "assigned" and rows[ids["a2"]]["quiz_score"] is None
    assert rows[ids["b1"]]["quiz_status"] == "in_progress"  # grading_failed is still open
    done = await _get(world, "Cho", quiz_status="done")
    assert _ids(done) == [ids["a1"]]
    assigned = await _get(world, "Cho", quiz_status="assigned")
    assert _ids(assigned) == [ids["a2"]]


async def test_empty_class_returns_empty_list(world: World) -> None:  # noqa: F811
    resp = await _get(world, "Cho")
    assert resp.status_code == 200 and resp.json() == {"items": [], "total": 0}


async def test_session_owner_missing_from_users_shows_no_name(world: World) -> None:  # noqa: F811
    await world.persona("Cho", "teacher")
    add_level(world.arena, "L1", 1, "Warm-up", "off")
    add_session(world.arena, world.read, user_id=str(uuid.uuid4()), level_id="L1", mode="off")
    row = (await _get(world, "Cho")).json()["items"][0]
    assert row["student_name"] is None
