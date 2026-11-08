"""Auth and the proxy trust boundary: PRD §4.1, §4.3 acceptance, §8.5, §15.1.

Covers M1-X01 to M1-X08 and the require_role half of E-55.
"""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import AsyncIterator
from typing import Annotated

import pytest
from fastapi import APIRouter, Depends, Request
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.auth.deps import client_meta, require_role
from app.auth.testing import DevKeys, make_keys, make_token
from app.config import Settings
from app.contracts.common import ClientMeta
from app.contracts.users import CurrentUser
from app.main import create_app

PROXY_SECRET = "p" * 40

probe = APIRouter(prefix="/api/probe")


@probe.get("/teacher")
async def teacher_only(user: Annotated[CurrentUser, Depends(require_role("teacher"))]) -> dict:
    return {"id": user.id}


@probe.get("/admin")
async def admin_only(
    user: Annotated[CurrentUser, Depends(require_role("firewall_admin"))],
) -> dict:
    return {"id": user.id}


@probe.get("/meta")
async def meta(request: Request) -> dict:
    found: ClientMeta = client_meta(request)
    return found.model_dump()


@pytest.fixture(scope="module")
def keys() -> DevKeys:
    return make_keys()


@pytest.fixture
async def client(engine: AsyncEngine, keys: DevKeys) -> AsyncIterator[AsyncClient]:
    settings = Settings(
        _env_file=None,
        APP_ENV="test",
        AEGIS_AUTH_MODE="dev",
        AEGIS_DEV_JWT_PUBLIC_KEY=keys.public_pem,
        AEGIS_PROXY_SECRET=PROXY_SECRET,
        DATABASE_URL="unused",
    )
    app = create_app(settings=settings, engine=engine, extra_routers=[probe])
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        c.headers["x-aegis-proxy-secret"] = PROXY_SECRET
        yield c


def _bearer(keys: DevKeys, **claims: object) -> dict[str, str]:
    return {"authorization": f"Bearer {make_token(keys, **claims)}"}  # type: ignore[arg-type]


async def test_healthz_needs_no_auth(client: AsyncClient) -> None:
    del client.headers["x-aegis-proxy-secret"]
    assert (await client.get("/healthz")).status_code == 200


# --- M1-X01: 401 cases ---------------------------------------------------------------


async def test_missing_token_is_401(client: AsyncClient) -> None:
    assert (await client.get("/api/me")).status_code == 401


@pytest.mark.parametrize(
    "overrides",
    [
        {"expires_in": -60},
        {"audience": "someone-else"},
        {"issuer": "https://evil.example/"},
    ],
    ids=["expired", "wrong-audience", "wrong-issuer"],
)
async def test_bad_token_is_401(client: AsyncClient, keys: DevKeys, overrides: dict) -> None:
    resp = await client.get("/api/me", headers=_bearer(keys, sub="auth0|x", **overrides))
    assert resp.status_code == 401


async def test_token_signed_by_another_key_is_401(client: AsyncClient) -> None:
    other = make_keys()
    resp = await client.get("/api/me", headers=_bearer(other, sub="auth0|x"))
    assert resp.status_code == 401


@pytest.mark.parametrize("header", ["Token abc", "Bearer", "Bearer not.a.jwt", "bearer  "])
async def test_malformed_authorization_is_401(client: AsyncClient, header: str) -> None:
    assert (await client.get("/api/me", headers={"authorization": header})).status_code == 401


async def test_alg_none_token_is_401(client: AsyncClient) -> None:
    def b64(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    # Built at runtime so secret scanners don't flag a literal (it carries no signature).
    unsigned = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'sub': 'auth0|x'})}."
    resp = await client.get("/api/me", headers={"authorization": f"Bearer {unsigned}"})
    assert resp.status_code == 401


# --- M1-X03, X04, X05, X06, X07 --------------------------------------------------------


async def test_new_user_without_role_is_student_and_upserted_once(
    client: AsyncClient, keys: DevKeys, engine: AsyncEngine
) -> None:
    headers = _bearer(keys, sub="auth0|new", name="Ada", email="ada@school.example")
    first = (await client.get("/api/me", headers=headers)).json()
    second = (await client.get("/api/me", headers=headers)).json()
    assert first["roles"] == ["student"]
    assert first["id"] == second["id"]
    async with engine.connect() as conn:
        rows = (await conn.execute(text("SELECT name, email, role FROM users"))).all()
    assert [tuple(r) for r in rows] == [("Ada", "ada@school.example", "student")]


async def test_concurrent_first_calls_create_one_user(
    client: AsyncClient, keys: DevKeys, engine: AsyncEngine
) -> None:
    headers = _bearer(keys, sub="auth0|race")
    responses = await asyncio.gather(*(client.get("/api/me", headers=headers) for _ in range(8)))
    ids = {r.json()["id"] for r in responses}
    assert len(ids) == 1
    async with engine.connect() as conn:
        count = (await conn.execute(text("SELECT count(*) FROM users"))).scalar_one()
    assert count == 1


async def test_student_on_teacher_and_admin_routes_is_403(
    client: AsyncClient, keys: DevKeys
) -> None:
    headers = _bearer(keys, sub="auth0|stu")
    assert (await client.get("/api/probe/teacher", headers=headers)).status_code == 403
    assert (await client.get("/api/probe/admin", headers=headers)).status_code == 403


async def test_teacher_on_admin_route_is_403(client: AsyncClient, keys: DevKeys) -> None:  # E-55
    headers = _bearer(keys, sub="auth0|tch", roles=["teacher"])
    assert (await client.get("/api/probe/teacher", headers=headers)).status_code == 200
    assert (await client.get("/api/probe/admin", headers=headers)).status_code == 403


async def test_dual_role_user_gets_both(client: AsyncClient, keys: DevKeys) -> None:
    headers = _bearer(keys, sub="auth0|both", roles=["teacher", "firewall_admin"])
    me = (await client.get("/api/me", headers=headers)).json()
    assert set(me["roles"]) == {"teacher", "firewall_admin"}
    assert (await client.get("/api/probe/teacher", headers=headers)).status_code == 200
    assert (await client.get("/api/probe/admin", headers=headers)).status_code == 200


async def test_role_comes_from_token_not_db_cache(
    client: AsyncClient, keys: DevKeys, engine: AsyncEngine
) -> None:
    headers = _bearer(keys, sub="auth0|cache")
    await client.get("/api/me", headers=headers)
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE users SET role = 'teacher' WHERE auth0_sub = 'auth0|cache'")
        )
    assert (await client.get("/api/probe/teacher", headers=headers)).status_code == 403


async def test_unknown_role_strings_are_ignored(client: AsyncClient, keys: DevKeys) -> None:
    headers = _bearer(keys, sub="auth0|odd", roles=["superuser", "teacher "])
    me = (await client.get("/api/me", headers=headers)).json()
    assert me["roles"] == ["student"]


# --- M1-X08: proxy trust boundary -------------------------------------------------------


async def test_missing_or_wrong_proxy_secret_is_401(client: AsyncClient, keys: DevKeys) -> None:
    headers = _bearer(keys, sub="auth0|p")
    del client.headers["x-aegis-proxy-secret"]
    assert (await client.get("/api/me", headers=headers)).status_code == 401
    wrong = {**headers, "x-aegis-proxy-secret": "q" * 40}
    assert (await client.get("/api/me", headers=wrong)).status_code == 401


async def test_client_meta_built_from_trusted_proxy_headers(client: AsyncClient) -> None:
    fingerprint = "a" * 64
    resp = await client.get(
        "/api/probe/meta",
        headers={
            "x-forwarded-for": "203.0.113.7, 10.0.0.1",
            "x-aegis-client-ua": "Mozilla/5.0 test",
            "x-aegis-fingerprint": fingerprint,
        },
    )
    assert resp.json() == {
        "ip": "203.0.113.7",
        "user_agent": "Mozilla/5.0 test",
        "fingerprint_hash": fingerprint,
    }


async def test_garbage_forwarded_for_and_fingerprint_are_dropped(client: AsyncClient) -> None:
    resp = await client.get(
        "/api/probe/meta",
        headers={"x-forwarded-for": "not-an-ip", "x-aegis-fingerprint": "zz"},
    )
    assert resp.json()["ip"] is None
    assert resp.json()["fingerprint_hash"] is None
