"""C3 forensics read for Classroom and the recap (M3 C-09, PRD §10.2, §14.4, contract
`contracts/firewall_read.py`). M2's `read_api.py` delegates `get_forensics` and
`get_attack_family_counts` here.

Only `done` reports are returned. Summaries were redacted before they were stored (M3-X24), and
the contract shapes carry no trace-back fields (M3-X39).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.contracts.arena import ArenaServicePort, SessionFilters
from app.contracts.firewall_read import FamilyCount, ForensicItem, InsightFilters

ADMIN_TEST_SESSION_PAGE = 1000

_FORENSICS = text(
    "SELECT event_id, attack_family, atlas_techniques, summary, missed_signals,"
    " would_have_blocked_in FROM forensic_reports"
    " WHERE fw_session_id = :s AND status = 'done' ORDER BY event_time, created_at"
)
# Every filter is a bound parameter; NULL means "no filter".
_FAMILIES = text(
    "SELECT attack_family, count(*) AS n FROM forensic_reports WHERE status = 'done'"
    " AND (CAST(:mode AS text) IS NULL OR mode = CAST(:mode AS text))"
    " AND (CAST(:level AS text) IS NULL OR level_id = CAST(:level AS text))"
    " AND (CAST(:since AS timestamptz) IS NULL OR event_time >= CAST(:since AS timestamptz))"
    " AND (CAST(:until AS timestamptz) IS NULL OR event_time < CAST(:until AS timestamptz))"
    " AND NOT (coalesce(fw_session_id, '') = ANY(CAST(:excluded AS text[])))"
    " GROUP BY attack_family ORDER BY n DESC, attack_family"
)


class ForensicsRead:
    def __init__(self, engine: AsyncEngine, arena: ArenaServicePort | None = None) -> None:
        self._engine = engine
        self._arena = arena

    async def get_forensics(self, fw_session_id: str) -> list[ForensicItem]:
        async with self._engine.connect() as conn:
            rows = (await conn.execute(_FORENSICS, {"s": fw_session_id})).mappings()
            return [ForensicItem.model_validate(dict(r)) for r in rows]

    async def _admin_test_sessions(self) -> list[str]:
        """Every admin test session, page by page through C4 (Codex round 1: no silent cap)."""
        if self._arena is None:
            raise RuntimeError("excluding admin test sessions needs the arena service (C4)")
        found: list[str] = []
        while True:
            page = await self._arena.list_sessions(
                SessionFilters(admin_test=True, limit=ADMIN_TEST_SESSION_PAGE, offset=len(found))
            )
            found += [s.fw_session_id for s in page]
            if len(page) < ADMIN_TEST_SESSION_PAGE:
                return found

    async def get_attack_family_counts(self, filters: InsightFilters) -> list[FamilyCount]:
        excluded = [] if filters.include_admin_test else await self._admin_test_sessions()
        params: dict[str, Any] = {
            "mode": filters.mode,
            "level": filters.level_id,
            "since": filters.since,
            "until": filters.until,
            "excluded": excluded,
        }
        async with self._engine.connect() as conn:
            rows = (await conn.execute(_FAMILIES, params)).all()
        return [FamilyCount(attack_family=r.attack_family, count=r.n) for r in rows]


def create() -> ForensicsRead:
    """For M2's `read_api.create()`: the real engine and the C4 arena service."""
    from app.db.engine import get_engine
    from app.firewall.ports import get_arena_service

    return ForensicsRead(get_engine(), get_arena_service())
