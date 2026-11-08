"""Async SQLAlchemy engine (Core, parameterized `text()` queries only, CONST-SEC-005)."""

from __future__ import annotations

import os
from functools import lru_cache

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from app.config import get_settings

POOL_SIZE = 10
POOL_RECYCLE_S = 1800


def make_engine(url: str) -> AsyncEngine:
    if not url:
        raise RuntimeError("DATABASE_URL is not set")
    return create_async_engine(
        url, pool_size=POOL_SIZE, pool_recycle=POOL_RECYCLE_S, pool_pre_ping=True
    )


def migration_url() -> str:
    """URL for Alembic: an explicit $DATABASE_URL wins (CI, tests, deploys); otherwise the app
    settings, which read `.env` / `../.env`, so `uv run alembic upgrade heads` works locally."""
    url = os.environ.get("DATABASE_URL") or get_settings().database_url
    if not url:
        raise RuntimeError("DATABASE_URL must be set (environment or .env) to run migrations")
    return url


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    return make_engine(get_settings().database_url)
