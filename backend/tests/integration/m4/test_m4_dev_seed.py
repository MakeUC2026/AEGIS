"""M4 B-07 dev seed: satisfies the C3/C4 contracts, gated to dev + fakes, idempotent."""

from __future__ import annotations

from app.classroom import dev_seed
from app.contracts.arena import SessionFilters
from app.contracts.fakes import FakeArenaService, FakeFirewallRead
from app.contracts.firewall_read import InsightFilters
from tests.m4_support import World

PEOPLE = {
    "Ada": "00000000-0000-4000-8000-0000000000a1",
    "Ben": "00000000-0000-4000-8000-0000000000b2",
    "Cho": "00000000-0000-4000-8000-0000000000c3",
}


async def test_seed_satisfies_the_contracts_and_covers_every_case() -> None:
    arena, read = FakeArenaService(), FakeFirewallRead()
    dev_seed.seed_dev_data(arena, read, PEOPLE)
    sessions = await arena.list_sessions(SessionFilters())
    assert len(sessions) >= 6
    assert any(s.secret_obtained_at for s in sessions)  # obtained
    assert any(s.status == "active" for s in sessions) and any(
        s.status == "closed" for s in sessions
    )
    assert sum(s.admin_test for s in sessions) == 1
    summaries = {
        x.fw_session_id: x
        for x in await read.get_session_summaries([s.fw_session_id for s in sessions])
    }
    assert any(x.diverted_count for x in summaries.values())  # diverted
    decisions = [d for s in sessions for d in await read.get_decisions(s.fw_session_id)]
    assert any(d.decision == "deny" for d in decisions) and any(
        d.decision == "divert" for d in decisions
    )
    benign = [
        s
        for s in sessions
        if not await read.get_diverts(s.fw_session_id)
        and all(d.decision == "allow" for d in await read.get_decisions(s.fw_session_id))
        and await read.get_transcript(s.fw_session_id)
    ]
    assert benign  # benign-only session
    for s in sessions:
        assert await read.get_manifest_summary(s.fw_session_id)
    assert len(await arena.list_levels()) == 3
    assert {x.level_id for x in await arena.get_secret_status()} == {"lvl-1", "lvl-2", "lvl-3"}
    f = InsightFilters()
    assert await read.get_rule_fire_counts(f) and await read.get_attack_family_counts(f)
    assert await read.get_decision_counts(f) and await read.get_risky_pattern_counts(f)


async def test_seed_uses_the_given_user_ids_only() -> None:
    arena, read = FakeArenaService(), FakeFirewallRead()
    dev_seed.seed_dev_data(arena, read, {"Ada": PEOPLE["Ada"]})
    owners = {s.user_id for s in await arena.list_sessions(SessionFilters())}
    assert owners == {PEOPLE["Ada"]}


async def test_seed_is_idempotent_and_replaces_its_own_sessions() -> None:
    arena, read = FakeArenaService(), FakeFirewallRead()
    dev_seed.seed_dev_data(arena, read, PEOPLE)
    first = len(arena.sessions)
    dev_seed.seed_dev_data(arena, read, PEOPLE)
    assert len(arena.sessions) == first
    dev_seed.seed_dev_data(arena, read, {"Ada": PEOPLE["Ada"]})
    assert len(arena.sessions) < first


async def test_seed_keeps_sessions_it_did_not_create() -> None:
    arena, read = FakeArenaService(), FakeFirewallRead()
    dev_seed.add_level(arena, "LX", 9, "Other", "off")
    mine = dev_seed.add_session(arena, read, user_id=PEOPLE["Ben"], level_id="LX", mode="off")
    dev_seed.seed_dev_data(arena, read, PEOPLE)
    assert mine.id in arena.sessions


async def test_seed_text_has_no_secret_like_strings() -> None:
    arena, read = FakeArenaService(), FakeFirewallRead()
    dev_seed.seed_dev_data(arena, read, PEOPLE)
    blob = " ".join(t.text for items in read.transcripts.values() for t in items)
    assert blob
    for banned in ("sk-", "AKIA", "BEGIN PRIVATE", "Bearer "):
        assert banned not in blob


# --- the lazy dev hook: only with dev + faked seams ---------------------------------------


async def _staff_get(w: World, path: str):  # type: ignore[no-untyped-def]
    cho = await w.persona("Cho", "teacher")
    return await w.client.get(path, headers=cho.headers)


async def test_hook_seeds_on_first_classroom_request_in_development(
    world: World, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    world.client._transport.app.state.settings = (
        world.client._transport.app.state.settings.model_copy(  # type: ignore[attr-defined]
            update={"app_env": "development"}
        )
    )
    await world.persona("Ada", "student")
    await world.persona("Ben", "student")
    resp = await _staff_get(world, "/api/classroom/sessions")
    body = resp.json()
    assert body["total"] >= 4
    assert any(r["student_name"] == "Ada" for r in body["items"])


async def test_hook_does_nothing_in_test_env(world: World) -> None:
    await world.persona("Ada", "student")
    assert (await _staff_get(world, "/api/classroom/sessions")).json()["total"] == 0


async def test_hook_does_nothing_when_a_seam_is_not_a_fake(world: World) -> None:
    from app.firewall import ports

    class NotFake(FakeArenaService):
        pass

    # A subclass is still a fake; a bare object that is not one must block seeding.
    class Real:
        async def list_sessions(self, filters):  # type: ignore[no-untyped-def]
            return []

        async def list_levels(self):  # type: ignore[no-untyped-def]
            return []

    ports.override("arena", Real())
    world.client._transport.app.state.settings = (
        world.client._transport.app.state.settings.model_copy(  # type: ignore[attr-defined]
            update={"app_env": "development"}
        )
    )
    resp = await _staff_get(world, "/api/classroom/sessions")
    assert resp.status_code == 200 and resp.json()["total"] == 0
