"""Quiz orchestration: start, assign, resume, retakes (PRD §13.1).

One open attempt per student and session (DB unique index). Starting resumes it; a retake is only
possible once the last attempt is `done`. Generation happens before any row is written, so a
failed or invalid quiz never leaves a partial one behind (M4-X17).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.contracts.arena import ArenaServicePort, ArenaSession
from app.contracts.firewall_read import FirewallReadPort
from app.contracts.users import CurrentUser
from app.quiz import repo
from app.quiz.context import build_context
from app.quiz.errors import BadInput, Conflict, NotAllowed, QuizMissing, SessionMissing
from app.quiz.generator import generate_quiz
from app.quiz.grading import InvalidAnswer, grade_answer
from app.quiz.llm import QuizRuntime
from app.quiz.models import PublicQuiz
from app.quiz.repo import QuizRow
from app.quiz.schemas import (
    AnswerOut,
    AssignOut,
    AttemptList,
    AttemptRow,
    MineList,
    MineRow,
    QuizView,
)


@dataclass(frozen=True)
class QuizDeps:
    engine: AsyncEngine
    arena: ArenaServicePort
    read: FirewallReadPort
    runtime: QuizRuntime


def can_see_quiz(user: CurrentUser, row: QuizRow) -> bool:
    return user.id == row.user_id or user.has("teacher")


async def _session(deps: QuizDeps, session_id: str) -> tuple[ArenaSession, uuid.UUID]:
    session = await deps.arena.get_session(session_id)
    sid = repo.parse_uuid(session_id)
    if session is None or sid is None:
        raise SessionMissing("session not found")
    return session, sid


async def quiz_view(conn: AsyncConnection, row: QuizRow) -> QuizView:
    """Public view: questions without answers, plus what the student already answered."""
    qid = uuid.UUID(row.id)
    questions = await repo.public_questions(conn, qid)
    base = PublicQuiz(
        quiz_id=row.id,
        session_id=row.session_id,
        rubric_version=row.rubric_version,
        questions=questions,
    )
    return QuizView(
        **base.model_dump(),
        status=row.status,  # type: ignore[arg-type]
        attempt_number=row.attempt_number,
        answered=await repo.answered(conn, qid),
        turns=await repo.turns(conn, qid),
    )


async def load_quiz(
    deps: QuizDeps, user: CurrentUser, quiz_id: str, *, conn: AsyncConnection
) -> QuizRow:
    qid = repo.parse_uuid(quiz_id)
    row = await repo.get_quiz(conn, qid) if qid else None
    if row is None:
        raise QuizMissing("quiz not found")
    if not can_see_quiz(user, row):
        raise NotAllowed("forbidden")
    return row


async def get_quiz_view(deps: QuizDeps, user: CurrentUser, quiz_id: str) -> QuizView:
    async with deps.engine.connect() as conn:
        row = await load_quiz(deps, user, quiz_id, conn=conn)
        return await quiz_view(conn, row)


async def start_quiz(deps: QuizDeps, user: CurrentUser, session_id: str) -> QuizView:
    session, sid = await _session(deps, session_id)
    if session.user_id != user.id:
        raise NotAllowed("you can only start a quiz on your own session")
    uid = uuid.UUID(user.id)
    async with deps.engine.connect() as conn:
        open_row = await repo.open_attempt(conn, sid, uid)
    if open_row is not None and open_row.status != "assigned":
        return await _resume(deps, session, open_row.id)

    context = await build_context(session, arena=deps.arena, read=deps.read)

    async def redact(text: str) -> str:
        return await deps.read.redact_for_session(session.fw_session_id, text)

    spec = await generate_quiz(
        deps.runtime.llm, model=deps.runtime.pro_model, context=context, redact=redact
    )
    key = context.answer_key
    try:
        async with deps.engine.begin() as conn:
            if open_row is not None:  # an assigned quiz becomes the student's attempt
                if not await repo.activate_assigned(conn, uuid.UUID(open_row.id), key):
                    quiz_id = None
                else:
                    quiz_id = uuid.UUID(open_row.id)
            else:
                attempt = await repo.next_attempt_number(conn, sid, uid)
                quiz_id = await repo.insert_quiz(
                    conn,
                    session_id=sid,
                    user_id=uid,
                    attempt=attempt,
                    status="in_progress",
                    assigned_by=None,
                    key=key,
                )
            if quiz_id is not None:
                await repo.insert_questions(conn, quiz_id, spec)
    except IntegrityError:
        quiz_id = None  # lost a race with another start: use the winner's quiz
    return await _resume(deps, session, str(quiz_id) if quiz_id else None, sid=sid, uid=uid)


async def _resume(
    deps: QuizDeps,
    session: ArenaSession,
    quiz_id: str | None,
    *,
    sid: uuid.UUID | None = None,
    uid: uuid.UUID | None = None,
) -> QuizView:
    """Return the stored quiz and unlock the recap (idempotent, PRD §6.2, M4-X15)."""
    async with deps.engine.connect() as conn:
        if quiz_id is None:
            assert sid is not None and uid is not None
            row = await repo.open_attempt(conn, sid, uid)
            if row is None:
                raise QuizMissing("quiz not found")
        else:
            qid = uuid.UUID(quiz_id)
            found = await repo.get_quiz(conn, qid)
            if found is None:
                raise QuizMissing("quiz not found")
            row = found
        view = await quiz_view(conn, row)
    await deps.arena.unlock_recap(session.id)
    return view


async def assign_quiz(deps: QuizDeps, session_id: str, teacher: CurrentUser) -> AssignOut:
    session, sid = await _session(deps, session_id)
    uid, tid = uuid.UUID(session.user_id), uuid.UUID(teacher.id)
    async with deps.engine.begin() as conn:
        existing = await repo.open_attempt(conn, sid, uid)
        if existing is None:
            attempt = await repo.next_attempt_number(conn, sid, uid)
            quiz_id = await repo.insert_quiz(
                conn,
                session_id=sid,
                user_id=uid,
                attempt=attempt,
                status="assigned",
                assigned_by=tid,
                key=None,
            )
            return AssignOut(
                quiz_id=str(quiz_id),
                session_id=session.id,
                status="assigned",
                attempt_number=attempt,
            )
        return AssignOut(
            quiz_id=existing.id,
            session_id=session.id,
            status=existing.status,  # type: ignore[arg-type]
            attempt_number=existing.attempt_number,
        )


def _iso(value: object) -> str:
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


async def attempts_view(deps: QuizDeps, user: CurrentUser, session_id: str) -> AttemptList:
    sid = repo.parse_uuid(session_id)
    if sid is None:
        raise SessionMissing("session not found")
    owner = None if user.has("teacher") else uuid.UUID(user.id)
    async with deps.engine.connect() as conn:
        records = await repo.attempts(conn, session_id=sid, user_id=owner)
    ordered = sorted(records, key=lambda r: r.attempt_number, reverse=True)
    percents = [r.percent for r in ordered if r.percent is not None]
    latest = next((r for r in ordered if r.status == "done"), None)
    return AttemptList(
        session_id=session_id,
        attempts=[
            AttemptRow(
                quiz_id=r.quiz_id,
                attempt_number=r.attempt_number,
                status=r.status,  # type: ignore[arg-type]
                percent=r.percent,
                created_at=_iso(r.created_at),
                finished_at=_iso(r.finished_at) if r.finished_at else None,
            )
            for r in ordered
        ],
        latest_percent=latest.percent if latest else None,
        best_percent=max(percents) if percents else None,
    )


async def mine_view(deps: QuizDeps, user: CurrentUser) -> MineList:
    async with deps.engine.connect() as conn:
        records = await repo.attempts(conn, session_id=None, user_id=uuid.UUID(user.id))
    return MineList(
        items=[
            MineRow(
                quiz_id=r.quiz_id,
                session_id=r.session_id,
                attempt_number=r.attempt_number,
                status=r.status,  # type: ignore[arg-type]
                percent=r.percent,
                created_at=_iso(r.created_at),
            )
            for r in records
        ]
    )


async def _owned_open_quiz(conn: AsyncConnection, user: CurrentUser, quiz_id: str) -> QuizRow:
    """The caller's own quiz, still in progress. Teachers read quizzes but never act in them."""
    qid = repo.parse_uuid(quiz_id)
    row = await repo.get_quiz(conn, qid) if qid else None
    if row is None:
        raise QuizMissing("quiz not found")
    if row.user_id != user.id:
        raise NotAllowed("forbidden")
    if row.status != "in_progress":
        raise Conflict("this quiz is not open for answers")
    return row


async def answer_mcq(
    deps: QuizDeps, user: CurrentUser, quiz_id: str, question_id: str, index: int
) -> AnswerOut:
    async with deps.engine.begin() as conn:
        row = await _owned_open_quiz(conn, user, quiz_id)
        qid = uuid.UUID(row.id)
        spec = await repo.load_spec(conn, qid, row.rubric_version)
        if question_id not in {q.id for q in spec.questions}:
            raise QuizMissing("question not found")
        answered = await repo.chosen_map(conn, qid)
        try:
            result = grade_answer(spec, answered, question_id, index)
        except InvalidAnswer as exc:
            raise BadInput(str(exc)) from None
        if not result.already_answered and not await repo.record_choice(
            conn, qid, question_id, index
        ):  # lost a race: the other request's answer is the first one
            result = grade_answer(spec, await repo.chosen_map(conn, qid), question_id, index)
    return AnswerOut(
        question_id=question_id,
        chosen_index=result.chosen_index,
        correct=result.correct,
        explanation=result.explanation,
        already_answered=result.already_answered,
    )
