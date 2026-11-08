"""Global daily model budget in `usage` (PRD §15.1 Cost, M1-X11)."""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from app.llm.base import BudgetExhausted
from app.llm.budget import DailyBudget


async def test_budget_counts_and_stops_at_limit(engine: AsyncEngine) -> None:
    budget = DailyBudget(engine, limit=3)
    for _ in range(3):
        await budget.spend("gemini")
    assert await budget.remaining() == 0
    with pytest.raises(BudgetExhausted):
        await budget.spend("gemini")


async def test_budget_is_safe_under_concurrency(engine: AsyncEngine) -> None:
    budget = DailyBudget(engine, limit=5)
    results = await asyncio.gather(
        *(budget.spend("gemini") for _ in range(12)), return_exceptions=True
    )
    assert sum(1 for r in results if r is None) == 5
    assert sum(1 for r in results if isinstance(r, BudgetExhausted)) == 7
