"""Quiz status per arena session, read from M4's own view `quiz_session_status`."""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.classroom.schemas import QuizStatus

_SQL = text(
    "SELECT session_id, user_id, latest_status, latest_percent, best_percent, attempts"
    " FROM quiz_session_status WHERE session_id = ANY(:ids)"
)


@dataclass(frozen=True)
class QuizSummary:
    status: QuizStatus
    score: int | None
    best: int | None
    attempts: int


NOT_TAKEN = QuizSummary("not_taken", None, None, 0)


def public_status(db_status: str) -> QuizStatus:
    """`grading_failed` is still an open attempt from the list's point of view."""
    if db_status in ("assigned", "done"):
        return db_status  # type: ignore[return-value]
    return "in_progress"


async def summaries_for(
    engine: AsyncEngine, session_ids: Iterable[str]
) -> dict[tuple[str, str], QuizSummary]:
    """`{(session_id, user_id): summary}` in one query."""
    wanted: list[uuid.UUID] = []
    for raw in session_ids:
        try:
            wanted.append(uuid.UUID(raw))
        except (ValueError, TypeError):
            continue
    if not wanted:
        return {}
    async with engine.connect() as conn:
        rows = (await conn.execute(_SQL, {"ids": wanted})).all()
    return {
        (str(r[0]), str(r[1])): QuizSummary(public_status(r[2]), r[3], r[4], r[5]) for r in rows
    }
