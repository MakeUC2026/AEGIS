"""Sessions list (PRD 12.1): C4 sessions + one C3 summaries call + quiz columns from M4 tables."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine

from app.classroom.access import session_scope_user_id
from app.classroom.quiz_status import NOT_TAKEN, QuizSummary, summaries_for
from app.classroom.schemas import MAX_PAGE, SessionList, SessionQuery, SessionRow
from app.classroom.users_repo import names_for
from app.contracts.arena import ArenaServicePort, ArenaSession, SessionFilters
from app.contracts.firewall_read import FirewallReadPort, SessionSummary
from app.contracts.users import CurrentUser


def _keep(
    q: SessionQuery, s: ArenaSession, summary: SessionSummary | None, quiz: QuizSummary
) -> bool:
    obtained = s.secret_obtained_at is not None
    diverted = (summary.diverted_count if summary else 0) > 0
    return (
        (q.outcome is None or obtained == (q.outcome == "obtained"))
        and (q.diverted is None or diverted == (q.diverted == "yes"))
        and (q.quiz_status is None or quiz.status == q.quiz_status)
    )


def build_row(
    s: ArenaSession,
    *,
    names: dict[str, str | None],
    levels: dict[str, str],
    summary: SessionSummary | None,
    quiz: QuizSummary,
) -> SessionRow:
    obtained_at = s.secret_obtained_at
    return SessionRow(
        id=s.id,
        student_id=s.user_id,
        student_name=names.get(s.user_id),
        level_id=s.level_id,
        level_name=levels.get(s.level_id),
        mode=s.mode,
        status=s.status,
        admin_test=s.admin_test,
        secret_obtained=obtained_at is not None,
        secret_obtained_at=obtained_at.isoformat() if obtained_at else None,
        diverted_count=summary.diverted_count if summary else 0,
        max_sentinel_score=summary.max_sentinel_score if summary else None,
        started_at=s.started_at.isoformat(),
        quiz_status=quiz.status,
        quiz_score=quiz.score,
        quiz_best=quiz.best,
        quiz_attempts=quiz.attempts,
    )


async def list_sessions_view(
    user: CurrentUser,
    q: SessionQuery,
    *,
    engine: AsyncEngine,
    arena: ArenaServicePort,
    read: FirewallReadPort,
) -> SessionList:
    filters = SessionFilters(
        user_id=session_scope_user_id(user, q.student),
        level_id=q.level,
        mode=q.mode,
        admin_test=q.admin_test,
        limit=MAX_PAGE,
    )
    sessions = await arena.list_sessions(filters)
    if not sessions:
        return SessionList(items=[], total=0)
    summaries = {
        s.fw_session_id: s
        for s in await read.get_session_summaries([s.fw_session_id for s in sessions])
    }
    quizzes = await summaries_for(engine, [s.id for s in sessions])
    kept = [
        s
        for s in sessions
        if _keep(q, s, summaries.get(s.fw_session_id), quizzes.get((s.id, s.user_id), NOT_TAKEN))
    ]
    kept.sort(key=lambda s: s.started_at, reverse=True)
    page = kept[q.offset : q.offset + q.limit]
    names = await names_for(engine, {s.user_id for s in page})
    levels = {lv.level_id: lv.name for lv in await arena.list_levels()}
    rows = [
        build_row(
            s,
            names=names,
            levels=levels,
            summary=summaries.get(s.fw_session_id),
            quiz=quizzes.get((s.id, s.user_id), NOT_TAKEN),
        )
        for s in page
    ]
    return SessionList(items=rows, total=len(kept))
