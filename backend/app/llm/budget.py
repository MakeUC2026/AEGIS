"""Global daily model budget (PRD §15.1 Cost). Since the D-15 revision every model call
is Gemini (bot, judge, forensics, decoys, quiz).

Each call inserts one `usage` row (kind `llm_call`). A transaction-scoped advisory lock
serializes the count-then-insert so concurrent calls cannot overshoot the limit.
The day is the UTC calendar day.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.llm.base import BudgetExhausted

BUDGET_LOCK_KEY = 4_242_001  # arbitrary fixed advisory-lock id for the budget counter

_LOCK = text("SELECT pg_advisory_xact_lock(:key)")
_COUNT_TODAY = text(
    "SELECT count(*) FROM usage WHERE kind = 'llm_call'"
    " AND time >= date_trunc('day', now() AT TIME ZONE 'utc') AT TIME ZONE 'utc'"
)
_INSERT = text("INSERT INTO usage (kind, provider) VALUES ('llm_call', :provider)")


class DailyBudget:
    def __init__(self, engine: AsyncEngine, limit: int) -> None:
        if limit < 0:
            raise ValueError("budget limit must be >= 0")
        self._engine = engine
        self._limit = limit

    async def spend(self, provider: str) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(_LOCK, {"key": BUDGET_LOCK_KEY})
            used = (await conn.execute(_COUNT_TODAY)).scalar_one()
            if used >= self._limit:
                raise BudgetExhausted("global daily model budget used up")
            await conn.execute(_INSERT, {"provider": provider})

    async def remaining(self) -> int:
        async with self._engine.connect() as conn:
            used = (await conn.execute(_COUNT_TODAY)).scalar_one()
        return max(0, self._limit - int(used))
