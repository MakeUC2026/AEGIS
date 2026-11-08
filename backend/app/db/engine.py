"""Async SQLAlchemy engine (Core, parameterized `text()` queries only, CONST-SEC-005)."""

from __future__ import annotations

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


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    return make_engine(get_settings().database_url)
