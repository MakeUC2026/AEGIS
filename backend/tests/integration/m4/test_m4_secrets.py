"""M4 B-05 secrets screen API: M4-X03 (students refused), X05 (admin may rotate, audited)."""

from __future__ import annotations

from datetime import UTC, datetime

from app.classroom.dev_seed import add_level
from app.contracts.arena import SecretStatus
from tests.m4_support import World

URL = "/api/classroom/secrets"


def _status(level: str, version: int = 1, by: str | None = None, session: str | None = None):  # type: ignore[no-untyped-def]
    when = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
    return SecretStatus(
        level_id=level,
        secret_version=version,
        compromised=by is not None,
        compromised_by_user=by,
        compromised_by_session=session,
        compromised_at=when if by else None,
        created_at=when,
    )


async def _seed(w: World):  # type: ignore[no-untyped-def]
    cho = await w.persona("Cho", "teacher")
    dee = await w.persona("Dee", "firewall_admin")
    ada = await w.persona("Ada", "student")
    add_level(w.arena, "L1", 1, "Warm-up", "off")
    add_level(w.arena, "L2", 2, "Guarded", "basic")
    w.arena.secrets = {
        "L2": _status("L2"),
        "L1": _status("L1", 3, by=ada.id, session="00000000-0000-4000-8000-000000000042"),
    }
    return cho, dee, ada


async def test_x03_student_refused_on_both_routes(world: World) -> None:
    _, _, ada = await _seed(world)
    assert (await world.client.get(URL, headers=ada.headers)).status_code == 403
    resp = await world.client.post(f"{URL}/L1/rotate", headers=ada.headers)
    assert resp.status_code == 403
    assert world.arena.audit == []


async def test_requires_auth(world: World) -> None:
    assert (await world.client.get(URL)).status_code == 401
    assert (await world.client.post(f"{URL}/L1/rotate")).status_code == 401


async def test_teacher_and_admin_can_list_in_level_order_with_names(world: World) -> None:
    cho, dee, _ = await _seed(world)
    for who in (cho, dee):
        resp = await world.client.get(URL, headers=who.headers)
        assert resp.status_code == 200
        rows = resp.json()["items"]
        assert [r["level_id"] for r in rows] == ["L1", "L2"]
        assert rows[0]["level_name"] == "Warm-up" and rows[0]["secret_version"] == 3
        assert rows[0]["compromised"] is True and rows[0]["compromised_by_name"] == "Ada"
        assert rows[0]["compromised_by_session"].endswith("42")
        assert rows[1]["compromised"] is False and rows[1]["compromised_by_name"] is None


async def test_list_never_carries_a_secret_value(world: World) -> None:
    cho, *_ = await _seed(world)
    body = (await world.client.get(URL, headers=cho.headers)).json()
    assert set(body["items"][0]) == {
        "level_id",
        "level_name",
        "secret_version",
        "compromised",
        "compromised_by_id",
        "compromised_by_name",
        "compromised_by_session",
        "compromised_at",
        "created_at",
    }


async def test_x05_admin_rotates_and_the_actor_is_the_caller(world: World) -> None:
    _, dee, _ = await _seed(world)
    resp = await world.client.post(f"{URL}/L1/rotate", headers=dee.headers)
    assert resp.status_code == 200
    row = resp.json()
    assert row["level_id"] == "L1" and row["secret_version"] == 4 and row["compromised"] is False
    assert world.arena.audit == [("secret", "L1", dee.id)]


async def test_teacher_rotate_is_audited_too(world: World) -> None:
    cho, *_ = await _seed(world)
    assert (await world.client.post(f"{URL}/L2/rotate", headers=cho.headers)).status_code == 200
    assert world.arena.audit == [("secret", "L2", cho.id)]


async def test_rotate_unknown_level_is_404_and_odd_ids_422(world: World) -> None:
    cho, *_ = await _seed(world)
    assert (await world.client.post(f"{URL}/nope/rotate", headers=cho.headers)).status_code == 404
    assert (await world.client.post(f"{URL}/a%20b/rotate", headers=cho.headers)).status_code == 422
    assert world.arena.audit == []


async def test_rotate_requires_post(world: World) -> None:
    cho, *_ = await _seed(world)
    assert (await world.client.get(f"{URL}/L1/rotate", headers=cho.headers)).status_code == 405
