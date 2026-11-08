"""Shared M4 test world: the real app on the test DB, with C3/C4 faked.

Import the `world` fixture into a test module (`from tests.m4_support import World, world`).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine

from app.auth.testing import DevKeys, make_keys, make_token
from app.config import Settings
from app.contracts.fakes import FakeArenaService, FakeFirewallRead
from app.firewall import ports
from app.main import create_app

PROXY_SECRET = "p" * 40
KEYS: DevKeys = make_keys()


@dataclass(frozen=True)
class Persona:
    name: str
    id: str
    headers: dict[str, str]


@dataclass
class World:
    client: AsyncClient
    engine: AsyncEngine
    arena: FakeArenaService
    read: FakeFirewallRead

    async def persona(self, name: str, role: str) -> Persona:
        token = make_token(KEYS, sub=f"auth0|{name.lower()}", roles=[role], name=name)
        headers = {"authorization": f"Bearer {token}"}
        me = (await self.client.get("/api/me", headers=headers)).json()
        return Persona(name=name, id=me["id"], headers=headers)


@pytest.fixture
async def world(engine: AsyncEngine) -> AsyncIterator[World]:
    arena, read = FakeArenaService(), FakeFirewallRead()
    ports.override("arena", arena)
    ports.override("read", read)
    settings = Settings(
        _env_file=None,
        APP_ENV="test",
        AEGIS_AUTH_MODE="dev",
        AEGIS_DEV_JWT_PUBLIC_KEY=KEYS.public_pem,
        AEGIS_PROXY_SECRET=PROXY_SECRET,
        DATABASE_URL="unused",
    )
    app = create_app(settings=settings, engine=engine)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        client.headers["x-aegis-proxy-secret"] = PROXY_SECRET
        yield World(client=client, engine=engine, arena=arena, read=read)
    ports.reset()
