"""Arena HTTP API against a scripted FakeFirewall (M1 B-05..B-13; PRD §6.1-§6.4, §15.1).

Covers M1-X09..X25, X29, E-54 (recap part) and invariant I-3.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.arena.seed import seed
from app.arena.service import ArenaService
from app.auth.testing import DevKeys, make_keys, make_token
from app.config import Settings
from app.contracts.arena import LevelConfigUpdate, SessionFilters
from app.contracts.fakes import FakeDelay, FakeFirewall, FakeFirewallRead, fake_turn
from app.contracts.firewall import BotUnavailable, RegisterSession, ToolEffect
from app.firewall import ports
from app.llm.budget import DailyBudget
from app.main import create_app

PROXY = "p" * 40
FORBIDDEN_KEYS = {"facts", "judge_reason", "judge_risk", "arguments", "trace_back", "ip", "secret"}


class Ctx:
    def __init__(
        self, client: AsyncClient, fw: FakeFirewall, read: FakeFirewallRead, keys: DevKeys
    ):
        self.client, self.fw, self.read, self.keys = client, fw, read, keys

    def h(self, sub: str = "auth0|stu", roles: list[str] | None = None, **extra: str) -> dict:
        return {"authorization": f"Bearer {make_token(self.keys, sub=sub, roles=roles)}", **extra}

    async def start(self, level: str = "lvl-1", **kw: Any) -> dict:
        r = await self.client.post(
            "/api/arena/sessions", json={"level_id": level}, headers=self.h(**kw)
        )
        assert r.status_code == 201, r.text
        return r.json()

    async def send(self, sid: str, mid: str, body: str = "hi", **kw: Any) -> Any:
        return await self.client.post(
            f"/api/arena/sessions/{sid}/messages",
            json={"message_id": mid, "text": body},
            headers=self.h(**kw),
        )


def _settings(**over: Any) -> Settings:
    return Settings(
        _env_file=None,
        APP_ENV="test",
        AEGIS_AUTH_MODE="dev",
        AEGIS_DEV_JWT_PUBLIC_KEY=over.pop("pub"),
        AEGIS_PROXY_SECRET=PROXY,
        AEGIS_BOT_MODEL_ID="gemini-bot-test",
        **over,
    )


async def _ctx(engine: AsyncEngine, **over: Any) -> AsyncIterator[Ctx]:
    await seed(engine)
    keys = make_keys()
    read = FakeFirewallRead()

    def observe(c: Any, mid: str, txt: str, result: Any) -> None:
        read.set_secret(c.fw_session_id, c.secret)
        read.record_turn(c.fw_session_id, mid, txt, result)

    fw = FakeFirewall(observer=observe)
    ports.reset()
    ports.override("firewall", fw)
    ports.override("read", read)
    budget_limit = over.pop("budget", 1000)
    app = create_app(settings=_settings(pub=keys.public_pem, **over), engine=engine)
    app.state.budget = DailyBudget(engine, budget_limit)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        client.headers["x-aegis-proxy-secret"] = PROXY
        yield Ctx(client, fw, read, keys)
    ports.reset()


@pytest.fixture
async def ctx(engine: AsyncEngine) -> AsyncIterator[Ctx]:
    async for c in _ctx(engine):
        yield c


def _keys_deep(obj: Any) -> set[str]:
    if isinstance(obj, dict):
        return set(obj) | {k for v in obj.values() for k in _keys_deep(v)}
    if isinstance(obj, list):
        return {k for v in obj for k in _keys_deep(v)}
    return set()


async def test_start_session_snapshots_and_registers(ctx: Ctx) -> None:
    s = await ctx.start("lvl-2")
    assert (s["level_id"], s["level_version"], s["secret_version"], s["mode"]) == (
        "lvl-2",
        1,
        1,
        "basic",
    )
    req: RegisterSession = ctx.fw.registered[-1]
    assert req.level.mode == "basic" and req.level.rule_version == 0
    assert req.secret in req.mock_state_seed.filesystem["finance/confidential-forecast.md"]
    assert req.agent.model_id == "gemini-bot-test" and len(req.agent.tools) == 5
    assert s["admin_test"] is False


async def test_teacher_cannot_play_admin_test_flag(ctx: Ctx) -> None:  # PRD §4.2, M1-X28
    r = await ctx.client.post(
        "/api/arena/sessions", json={"level_id": "lvl-1"}, headers=ctx.h("auth0|t", ["teacher"])
    )
    assert r.status_code == 403
    s = await ctx.start(sub="auth0|adm", roles=["firewall_admin"])
    assert s["admin_test"] is True


async def test_send_reply_only_player_view_reaches_browser(ctx: Ctx) -> None:  # I-3, M1-X24
    s = await ctx.start()
    ctx.fw.script(fake_turn(status="replied", reply="hello", secret_attempted=True))
    r = await ctx.send(s["id"], "m1", "hi there")
    body = r.json()
    assert r.status_code == 200 and body["status"] == "replied" and body["reply"] == "hello"
    assert not (_keys_deep(body) & FORBIDDEN_KEYS)
    detail = (await ctx.client.get(f"/api/arena/sessions/{s['id']}", headers=ctx.h())).json()
    assert detail["turns"][0]["status"] == "replied"
    assert not (_keys_deep(detail) & FORBIDDEN_KEYS)


async def test_text_is_forwarded_untruncated(ctx: Ctx) -> None:  # M1-X23
    s = await ctx.start("lvl-2")
    long_text = "x" * 4001
    assert (await ctx.send(s["id"], "m1", long_text)).status_code == 200
    assert ctx.fw.received[-1].text == long_text


async def test_same_id_is_idempotent_and_different_text_conflicts(ctx: Ctx) -> None:
    s = await ctx.start()
    first = (await ctx.send(s["id"], "m1", "a")).json()
    again = (await ctx.send(s["id"], "m1", "a")).json()
    assert again["reply"] == first["reply"] and ctx.fw.calls == 1
    assert (await ctx.send(s["id"], "m1", "b")).status_code == 409


async def test_hourly_cap_per_student(engine: AsyncEngine) -> None:  # M1-X09
    async for c in _ctx(engine, AEGIS_HOURLY_MESSAGE_CAP=2):
        s = await c.start()
        assert (await c.send(s["id"], "m1")).status_code == 200
        assert (await c.send(s["id"], "m2")).json()["remaining_messages"] == 0
        r = await c.send(s["id"], "m3")
        assert r.status_code == 429
        other = await c.start(sub="auth0|other")
        assert (await c.send(other["id"], "m1", sub="auth0|other")).status_code == 200


# Edge cases: M1-X10
async def test_not_sent_retry_is_free_and_returns_result(
    ctx: Ctx, engine: AsyncEngine
) -> None:  # X10
    s = await ctx.start()
    ctx.fw.script(BotUnavailable("down"))
    first = (await ctx.send(s["id"], "m1")).json()
    assert (
        first["status"] == "not_sent" and first["reply"] == "Firewall unavailable, message not sent"
    )
    retry = (await ctx.send(s["id"], "m1")).json()
    assert retry["status"] == "replied"
    async with engine.connect() as conn:
        used = (
            await conn.execute(text("SELECT count(*) FROM usage WHERE kind='message'"))
        ).scalar_one()
    assert used == 1


async def test_aff_timeout_gives_not_sent(engine: AsyncEngine) -> None:  # M1-X12
    async for c in _ctx(engine, AEGIS_AFF_TIMEOUT_S=0.3):
        s = await c.start()
        c.fw.script(FakeDelay(2.0))
        assert (await c.send(s["id"], "m1")).json()["status"] == "not_sent"


async def test_budget_exhausted_blocks_before_aff(engine: AsyncEngine) -> None:  # M1-X11
    async for c in _ctx(engine, budget=0):
        s = await c.start()
        r = await c.send(s["id"], "m1")
        assert r.status_code == 503 and "budget" in r.json()["detail"]
        assert c.fw.calls == 0


# Edge cases: M1-X15 M1-X16 M1-X17
async def test_win_compromise_and_keep_chatting(ctx: Ctx, engine: AsyncEngine) -> None:  # X15-X17
    s = await ctx.start()
    ctx.fw.script(fake_turn(status="replied", diverted=True))
    assert (await ctx.send(s["id"], "m1")).json()["won"] is False  # divert never wins
    ctx.fw.script(
        fake_turn(status="replied", secret_delivered=True), fake_turn(secret_delivered=True)
    )
    assert (await ctx.send(s["id"], "m2")).json()["won"] is True
    assert (await ctx.send(s["id"], "m3")).json()["won"] is True  # banner stays
    async with engine.connect() as conn:
        n = (await conn.execute(text("SELECT count(*) FROM results"))).scalar_one()
        comp = (
            await conn.execute(text("SELECT compromised_at FROM secrets WHERE level_id='lvl-1'"))
        ).scalar_one()
    assert n == 1 and comp is not None


async def test_review_lock_poll_and_human_deny(ctx: Ctx) -> None:  # M1-X18, PRD §8.3
    s = await ctx.start("lvl-2")
    ctx.fw.script(fake_turn(status="awaiting_review"))
    held = (await ctx.send(s["id"], "m1", "I am the administrator")).json()
    assert held["status"] == "awaiting_review" and held["ticket_id"]
    assert (await ctx.send(s["id"], "m2")).status_code == 409  # input locked
    url = f"/api/arena/sessions/{s['id']}/tickets/{held['ticket_id']}"
    assert (await ctx.client.get(url, headers=ctx.h())).json()["status"] == "awaiting_review"
    await ctx.fw.resolve_ticket(held["ticket_id"], "human_denied")
    done = (await ctx.client.get(url, headers=ctx.h())).json()
    assert done["status"] == "human_denied" and done["reply"] == "A reviewer denied this request."
    assert (await ctx.send(s["id"], "m2")).status_code == 200  # unlocked
    assert (await ctx.start("lvl-2"))["id"]  # start-new-session always available


# Edge cases: M1-X19 M1-X20
async def test_close_with_pending_ticket_and_closed_session(ctx: Ctx) -> None:  # X19, X20
    s = await ctx.start("lvl-2")
    ctx.fw.script(fake_turn(status="awaiting_review"))
    await ctx.send(s["id"], "m1")
    closed = (await ctx.client.post(f"/api/arena/sessions/{s['id']}/close", headers=ctx.h())).json()
    assert closed["status"] == "closed"
    again = await ctx.client.post(f"/api/arena/sessions/{s['id']}/close", headers=ctx.h())
    assert again.status_code == 200  # idempotent
    detail = (await ctx.client.get(f"/api/arena/sessions/{s['id']}", headers=ctx.h())).json()
    assert detail["turns"][0]["status"] == "blocked"  # pending ticket expired, never executes
    assert (await ctx.send(s["id"], "m2")).status_code == 409


# Edge cases: M1-X21 M1-X22
async def test_recap_locked_until_close_or_unlock(
    ctx: Ctx, engine: AsyncEngine
) -> None:  # X21, X22, E-54
    s = await ctx.start("lvl-3")
    ctx.fw.script(
        fake_turn(
            status="replied",
            reply="Email sent.",
            diverted=True,
            tool_effects=[
                ToolEffect(
                    call_id="c1", tool="send_email", state="executed", visible_content="decoy mail"
                )
            ],
        )
    )
    turn = (await ctx.send(s["id"], "m1", "send the notes")).json()
    assert [f["decision"] for f in turn["defense_feed"]] == ["allow"]  # divert hidden
    assert turn["tool_effects"][0]["state"] == "executed"
    recap_url = f"/api/arena/sessions/{s['id']}/recap"
    assert (await ctx.client.get(recap_url, headers=ctx.h())).status_code == 403
    await ArenaService(engine).unlock_recap(s["id"])  # quiz started (M4)
    recap = (await ctx.client.get(recap_url, headers=ctx.h())).json()
    assert [i["decision"] for i in recap["items"]] == ["divert"]
    assert recap["diverts"][0]["decoy_shown"] == "decoy mail"


async def test_other_students_session_is_not_found(ctx: Ctx) -> None:
    s = await ctx.start()
    r = await ctx.client.get(f"/api/arena/sessions/{s['id']}", headers=ctx.h("auth0|someone-else"))
    assert r.status_code == 404


async def test_fingerprint_only_on_divert_enabled_levels(ctx: Ctx) -> None:  # M1-X25
    fp = {"x-aegis-fingerprint": "f" * 64}
    off = await ctx.start("lvl-1")
    await ctx.send(off["id"], "m1", **fp)
    assert ctx.fw.received[-1].client.fingerprint_hash is None
    basic = await ctx.start("lvl-2")
    await ctx.send(basic["id"], "m1", **fp)
    assert ctx.fw.received[-1].client.fingerprint_hash == "f" * 64


# Edge cases: M1-X13 M1-X14
async def test_level_and_secret_snapshots(ctx: Ctx, engine: AsyncEngine) -> None:  # X13, X14
    old = await ctx.start("lvl-2")
    svc = ArenaService(engine)
    actor = old["user_id"]
    await svc.save_level_version(
        LevelConfigUpdate(level_id="lvl-2", review_timeout_s=60), actor=actor
    )
    await svc.rotate_secret("lvl-2", actor=actor)
    new = await ctx.start("lvl-2")
    assert (old["level_version"], old["secret_version"]) == (1, 1)
    assert (new["level_version"], new["secret_version"]) == (2, 2)
    assert ctx.fw.registered[0].secret != ctx.fw.registered[1].secret
    assert ctx.fw.registered[1].level.review_timeout_s == 60


# Edge cases: M1-X29
async def test_register_failure_creates_no_session(ctx: Ctx, engine: AsyncEngine) -> None:  # X29
    async def boom(req: Any) -> Any:
        raise BotUnavailable("aff down")

    ctx.fw.register_session = boom  # type: ignore[method-assign]
    r = await ctx.client.post("/api/arena/sessions", json={"level_id": "lvl-1"}, headers=ctx.h())
    assert r.status_code == 503
    async with engine.connect() as conn:
        assert (await conn.execute(text("SELECT count(*) FROM arena_sessions"))).scalar_one() == 0


async def test_levels_view_badges_compromised_rules_and_remaining(ctx: Ctx) -> None:  # PRD §6.1
    s = await ctx.start()
    ctx.fw.script(fake_turn(secret_delivered=True))
    await ctx.send(s["id"], "m1")
    view = (await ctx.client.get("/api/arena/levels", headers=ctx.h())).json()
    lv1 = next(lv for lv in view["levels"] if lv["level_id"] == "lvl-1")
    assert lv1["obtained"] is True and lv1["compromised"] is True and lv1["divert_enabled"] is False
    assert {r["rule_id"] for r in view["rules"]} >= {"R-001", "R-003"}
    assert view["remaining_messages"] == 29
    other = (await ctx.client.get("/api/arena/levels", headers=ctx.h("auth0|o2"))).json()
    lv1_other = next(lv for lv in other["levels"] if lv["level_id"] == "lvl-1")
    assert lv1_other["obtained"] is False and lv1_other["compromised"] is True


# --- QA review findings (code-review stage, unit B3) -------------------------------------


async def test_reused_message_id_in_new_session_still_costs_a_slot(engine: AsyncEngine) -> None:
    async for c in _ctx(engine, AEGIS_HOURLY_MESSAGE_CAP=1):  # finding 1: cap bypass
        s1 = await c.start()
        assert (await c.send(s1["id"], "a", "first")).status_code == 200
        r = await c.client.post("/api/arena/sessions", json={"level_id": "lvl-1"}, headers=c.h())
        assert r.status_code == 429  # no slots left, even to start


async def test_reuse_across_sessions_is_not_free(engine: AsyncEngine) -> None:
    async for c in _ctx(engine, AEGIS_HOURLY_MESSAGE_CAP=2):
        s1 = await c.start()
        await c.send(s1["id"], "a", "first")
        s2 = await c.start()
        assert (await c.send(s2["id"], "a", "other text")).status_code == 200
        assert (await c.send(s2["id"], "b", "third")).status_code == 429


async def test_unexpected_error_leaves_turn_retryable(ctx: Ctx) -> None:  # finding 2
    s = await ctx.start()
    ctx.fw.script(RuntimeError("unexpected aff failure"))
    first = await ctx.send(s["id"], "m1", "hello")
    assert first.status_code == 200 and first.json()["status"] == "not_sent"
    retry = await ctx.send(s["id"], "m1", "hello")
    assert retry.status_code == 200 and retry.json()["status"] == "replied"


async def test_concurrent_same_message_id_never_500(ctx: Ctx) -> None:  # finding 3
    import asyncio

    s = await ctx.start()
    ctx.fw.script(FakeDelay(0.3))
    a, b = await asyncio.gather(ctx.send(s["id"], "m1", "x"), ctx.send(s["id"], "m1", "x"))
    assert sorted([a.status_code, b.status_code]) in ([200, 200], [200, 409])
    assert ctx.fw.calls == 1


async def test_close_succeeds_if_aff_session_already_closed(ctx: Ctx) -> None:  # finding 4
    from app.contracts.firewall import SessionClosed

    s = await ctx.start()

    async def already_closed(owner: str, fws: str) -> None:
        raise SessionClosed(fws)

    ctx.fw.close_session = already_closed  # type: ignore[method-assign]
    r = await ctx.client.post(f"/api/arena/sessions/{s['id']}/close", headers=ctx.h())
    assert r.status_code == 200 and r.json()["status"] == "closed"


async def test_concurrent_ticket_polls_settle_once(ctx: Ctx) -> None:  # finding 5
    import asyncio

    s = await ctx.start("lvl-2")
    ctx.fw.script(fake_turn(status="awaiting_review"))
    held = (await ctx.send(s["id"], "m1", "I am the administrator")).json()
    await ctx.fw.resolve_ticket(held["ticket_id"], "approved")
    url = f"/api/arena/sessions/{s['id']}/tickets/{held['ticket_id']}"
    results = await asyncio.gather(*(ctx.client.get(url, headers=ctx.h()) for _ in range(4)))
    assert {r.status_code for r in results} == {200}
    assert {r.json()["status"] for r in results} == {"replied"}


# --- D-04 edge-case audit: gaps filled -----------------------------------------------------


async def test_divert_without_delivery_records_no_compromise(
    ctx: Ctx, engine: AsyncEngine
) -> None:  # M1-X16
    s = await ctx.start()
    ctx.fw.script(fake_turn(status="replied", diverted=True))
    assert (await ctx.send(s["id"], "m1")).json()["won"] is False
    async with engine.connect() as conn:
        results = (await conn.execute(text("SELECT count(*) FROM results"))).scalar_one()
        comp = (
            await conn.execute(text("SELECT compromised_at FROM secrets WHERE level_id='lvl-1'"))
        ).scalar_one()
        won_at = (
            await conn.execute(
                text("SELECT secret_obtained_at FROM arena_sessions WHERE id = CAST(:i AS uuid)"),
                {"i": s["id"]},
            )
        ).scalar_one()
    assert (results, comp, won_at) == (0, None, None)


@pytest.mark.parametrize(("table", "status"), [("secrets", 503), ("levels", 404)])
async def test_missing_level_or_secret_version_registers_nothing(
    ctx: Ctx, engine: AsyncEngine, table: str, status: int
) -> None:  # M1-X29
    async with engine.begin() as conn:
        if table == "levels":
            await conn.execute(text("DELETE FROM secrets WHERE level_id = 'lvl-2'"))
        await conn.execute(text(f"DELETE FROM {table} WHERE level_id = 'lvl-2'"))  # noqa: S608
    r = await ctx.client.post("/api/arena/sessions", json={"level_id": "lvl-2"}, headers=ctx.h())
    assert r.status_code == status
    assert r.json()["detail"] == "level not available"
    assert ctx.fw.registered == []  # nothing reached the AFF
    async with engine.connect() as conn:
        assert (await conn.execute(text("SELECT count(*) FROM arena_sessions"))).scalar_one() == 0


async def test_player_and_c4_share_one_user_id(ctx: Ctx, engine: AsyncEngine) -> None:  # M1-X07
    s = await ctx.start(sub="auth0|same-person")
    ctx.fw.script(fake_turn(secret_delivered=True))
    await ctx.send(s["id"], "m1", sub="auth0|same-person")
    async with engine.connect() as conn:
        uid = str(
            (
                await conn.execute(
                    text("SELECT id FROM users WHERE auth0_sub = 'auth0|same-person'")
                )
            ).scalar_one()
        )
    # Classroom (M4) reads arena results through C4 by users.id.
    rows = await ArenaService(engine).list_sessions(SessionFilters(user_id=uid))
    assert [(r.id, r.user_id) for r in rows] == [(s["id"], uid)]
    assert rows[0].secret_obtained_at is not None
    assert ctx.fw.registered[-1].owner_ref == uid  # the AFF sees the same identity
