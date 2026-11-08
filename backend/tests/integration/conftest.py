"""Integration fixtures: a fresh TimescaleDB+pgvector database per test run (I-6).

DB URL: $TEST_DATABASE_URL, else built from the repo-root .env (docker compose `db`).
DB name: $AEGIS_TEST_DB (default `aegis_test`), so two machines' suites on one host (for
example M1 and M2) never drop each other's database. It must start with `aegis_test`.
Migrations run through the real `alembic upgrade heads` CLI, exactly as CI does.
"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
from collections.abc import AsyncIterator

import asyncpg
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

BACKEND = pathlib.Path(__file__).resolve().parents[2]
ROOT_ENV = BACKEND.parent / ".env"
_TEST_DB_NAME = re.compile(r"aegis_test[a-z0-9_]{0,40}")


def test_db_name() -> str:
    """The database this run drops and recreates. Never anything but an aegis_test* name."""
    name = os.environ.get("AEGIS_TEST_DB", "aegis_test")
    if not _TEST_DB_NAME.fullmatch(name):
        raise ValueError(f"AEGIS_TEST_DB must match {_TEST_DB_NAME.pattern}, got {name!r}")
    return name


TEST_DB = test_db_name()
M1_TABLES = (
    "usage",
    "results",
    "arena_turns",
    "arena_sessions",
    "secrets",
    "levels",
    "scenario",
    "audit_log",
    "users",
)


def _dotenv() -> dict[str, str]:
    if not ROOT_ENV.exists():
        return {}
    pairs = (line.split("=", 1) for line in ROOT_ENV.read_text().splitlines() if "=" in line)
    return {k.strip(): v.strip() for k, v in pairs if not k.strip().startswith("#")}


def _base_dsn() -> str:
    if url := os.environ.get("TEST_DATABASE_URL"):
        return url.replace("postgresql+asyncpg://", "postgresql://").rsplit("/", 1)[0]
    env = _dotenv()
    user, password = env.get("POSTGRES_USER", "aegis"), env.get("POSTGRES_PASSWORD", "aegis")
    return f"postgresql://{user}:{password}@127.0.0.1:55432"


def database_url() -> str:
    return f"{_base_dsn().replace('postgresql://', 'postgresql+asyncpg://')}/{TEST_DB}"


async def _recreate_database() -> None:
    conn = await asyncpg.connect(f"{_base_dsn()}/postgres")
    try:
        await conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB}" WITH (FORCE)')
        await conn.execute(f'CREATE DATABASE "{TEST_DB}"')
    finally:
        await conn.close()


def run_alembic(*args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "DATABASE_URL": database_url()}
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["uv", "run", "alembic", *args],  # noqa: S607
        cwd=BACKEND,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture(scope="session")
async def migrated_db() -> str:
    await _recreate_database()
    result = run_alembic("upgrade", "heads")
    assert result.returncode == 0, result.stderr
    return database_url()


@pytest.fixture(scope="session")
async def engine(migrated_db: str) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(migrated_db, pool_size=10)
    yield eng
    await eng.dispose()


@pytest.fixture(autouse=True)
async def clean_db(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE {', '.join(M1_TABLES)} RESTART IDENTITY CASCADE"))
