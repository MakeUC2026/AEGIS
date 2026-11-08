"""SQL on the four quiz tables (M4 owns them). The only module that names answer columns.

Every function takes an open `AsyncConnection`, so callers compose transactions. Functions that
feed a route (`public_questions`, `answered`) never select answers for unanswered questions.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from app.quiz.models import (
    AnswerKey,
    FreeResponseQuestion,
    McqQuestion,
    PublicFreeResponse,
    PublicMcq,
    PublicQuestion,
    QuizSpec,
)
from app.quiz.schemas import AnsweredMcq, TurnView


def parse_uuid(raw: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(raw)
    except (ValueError, AttributeError, TypeError):
        return None


@dataclass(frozen=True)
class QuizRow:
    id: str
    session_id: str
    user_id: str
    attempt_number: int
    status: str
    rubric_version: str
    assigned_by: str | None
    answer_key: AnswerKey | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


_GET = text(
    "SELECT id, session_id, user_id, attempt_number, status, rubric_version, assigned_by,"
    " answer_key, created_at, started_at, finished_at FROM quiz WHERE id = :id"
)
_OPEN = text(
    "SELECT id, session_id, user_id, attempt_number, status, rubric_version, assigned_by,"
    " answer_key, created_at, started_at, finished_at FROM quiz"
    " WHERE session_id = :s AND user_id = :u AND status <> 'done'"
)


def _row(r: Any) -> QuizRow:
    key = r[7]
    if isinstance(key, str):
        key = json.loads(key)
    return QuizRow(
        id=str(r[0]),
        session_id=str(r[1]),
        user_id=str(r[2]),
        attempt_number=r[3],
        status=r[4],
        rubric_version=r[5],
        assigned_by=str(r[6]) if r[6] else None,
        answer_key=AnswerKey.model_validate(key) if key else None,
        created_at=r[8],
        started_at=r[9],
        finished_at=r[10],
    )


async def get_quiz(conn: AsyncConnection, quiz_id: uuid.UUID) -> QuizRow | None:
    r = (await conn.execute(_GET, {"id": quiz_id})).first()
    return _row(r) if r else None


async def open_attempt(
    conn: AsyncConnection, session_id: uuid.UUID, user_id: uuid.UUID
) -> QuizRow | None:
    r = (await conn.execute(_OPEN, {"s": session_id, "u": user_id})).first()
    return _row(r) if r else None


async def next_attempt_number(
    conn: AsyncConnection, session_id: uuid.UUID, user_id: uuid.UUID
) -> int:
    n = (
        await conn.execute(
            text(
                "SELECT COALESCE(max(attempt_number), 0) + 1 FROM quiz"
                " WHERE session_id = :s AND user_id = :u"
            ),
            {"s": session_id, "u": user_id},
        )
    ).scalar_one()
    return int(n)


async def insert_quiz(
    conn: AsyncConnection,
    *,
    session_id: uuid.UUID,
    user_id: uuid.UUID,
    attempt: int,
    status: str,
    assigned_by: uuid.UUID | None,
    key: AnswerKey | None,
) -> uuid.UUID:
    quiz_id = (
        await conn.execute(
            text(
                "INSERT INTO quiz (session_id, user_id, attempt_number, status, rubric_version,"
                " assigned_by, answer_key, started_at)"
                " VALUES (:s, :u, :n, :st, 'r1', :a, CAST(:k AS jsonb),"
                " CASE WHEN :st = 'in_progress' THEN now() END) RETURNING id"
            ),
            {
                "s": session_id,
                "u": user_id,
                "n": attempt,
                "st": status,
                "a": assigned_by,
                "k": key.model_dump_json() if key else None,
            },
        )
    ).scalar_one()
    return uuid.UUID(str(quiz_id))


async def activate_assigned(conn: AsyncConnection, quiz_id: uuid.UUID, key: AnswerKey) -> bool:
    """assigned -> in_progress. False when another request already did it."""
    done = await conn.execute(
        text(
            "UPDATE quiz SET status = 'in_progress', started_at = now(),"
            " answer_key = CAST(:k AS jsonb) WHERE id = :id AND status = 'assigned'"
        ),
        {"id": quiz_id, "k": key.model_dump_json()},
    )
    return done.rowcount == 1


async def insert_questions(conn: AsyncConnection, quiz_id: uuid.UUID, spec: QuizSpec) -> None:
    for position, q in enumerate(spec.questions, start=1):
        if isinstance(q, McqQuestion):
            params: dict[str, Any] = {
                "options": json.dumps(q.options),
                "ai": q.answer_index,
                "ex": q.explanation,
                "mf": None,
                "ri": None,
            }
        else:
            params = {
                "options": None,
                "ai": None,
                "ex": None,
                "mf": q.max_follow_ups,
                "ri": json.dumps(q.rubric_items),
            }
        await conn.execute(
            text(
                "INSERT INTO quiz_questions (quiz_id, question_id, position, type, topic, prompt,"
                " options, max_follow_ups, rubric_items, answer_index, explanation)"
                " VALUES (:q, :id, :pos, :type, :topic, :prompt, CAST(:options AS jsonb), :mf,"
                " CAST(:ri AS jsonb), :ai, :ex)"
            ),
            {
                "q": quiz_id,
                "id": q.id,
                "pos": position,
                "type": q.type,
                "topic": q.topic,
                "prompt": q.prompt,
                **params,
            },
        )


async def load_spec(conn: AsyncConnection, quiz_id: uuid.UUID, rubric_version: str) -> QuizSpec:
    """The private spec, answers included. Server-side use only (grading)."""
    rows = (
        await conn.execute(
            text(
                "SELECT question_id, type, topic, prompt, options, max_follow_ups, rubric_items,"
                " answer_index, explanation FROM quiz_questions WHERE quiz_id = :q"
                " ORDER BY position"
            ),
            {"q": quiz_id},
        )
    ).all()
    questions: list[McqQuestion | FreeResponseQuestion] = []
    for r in rows:
        if r[1] == "mcq":
            questions.append(
                McqQuestion(
                    id=r[0],
                    topic=r[2],
                    prompt=r[3],
                    options=_json(r[4]),
                    answer_index=r[7],
                    explanation=r[8],
                )
            )
        else:
            questions.append(
                FreeResponseQuestion(
                    id=r[0],
                    topic=r[2],
                    prompt=r[3],
                    max_follow_ups=r[5],
                    rubric_items=_json(r[6]),
                )
            )
    return QuizSpec(rubric_version=rubric_version, questions=questions)


def _json(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


async def public_questions(conn: AsyncConnection, quiz_id: uuid.UUID) -> list[PublicQuestion]:
    rows = (
        await conn.execute(
            text(
                "SELECT question_id, type, topic, prompt, options, max_follow_ups"
                " FROM quiz_questions WHERE quiz_id = :q ORDER BY position"
            ),
            {"q": quiz_id},
        )
    ).all()
    out: list[PublicQuestion] = []
    for qid, kind, topic, prompt, options, max_follow_ups in rows:
        if kind == "mcq":
            out.append(PublicMcq(id=qid, topic=topic, prompt=prompt, options=_json(options)))
        else:
            out.append(
                PublicFreeResponse(
                    id=qid, topic=topic, prompt=prompt, max_follow_ups=max_follow_ups
                )
            )
    return out


async def answered(conn: AsyncConnection, quiz_id: uuid.UUID) -> list[AnsweredMcq]:
    """Answers (and their explanations) for the questions already answered, and only those."""
    rows = (
        await conn.execute(
            text(
                "SELECT question_id, chosen_index, chosen_index = answer_index, explanation"
                " FROM quiz_questions WHERE quiz_id = :q AND chosen_index IS NOT NULL"
                " ORDER BY position"
            ),
            {"q": quiz_id},
        )
    ).all()
    return [
        AnsweredMcq(question_id=r[0], chosen_index=r[1], correct=bool(r[2]), explanation=r[3])
        for r in rows
    ]


async def turns(conn: AsyncConnection, quiz_id: uuid.UUID) -> list[TurnView]:
    rows = (
        await conn.execute(
            text(
                "SELECT t.question_id, t.seq, t.role, t.text FROM quiz_turns t"
                " JOIN quiz_questions qq"
                " ON qq.quiz_id = t.quiz_id AND qq.question_id = t.question_id"
                " WHERE t.quiz_id = :q ORDER BY qq.position, t.seq"
            ),
            {"q": quiz_id},
        )
    ).all()
    return [TurnView(question_id=r[0], seq=r[1], role=r[2], text=r[3]) for r in rows]


@dataclass(frozen=True)
class AttemptRecord:
    quiz_id: str
    session_id: str
    user_id: str
    attempt_number: int
    status: str
    percent: int | None
    created_at: datetime
    finished_at: datetime | None


async def attempts(
    conn: AsyncConnection, *, session_id: uuid.UUID | None, user_id: uuid.UUID | None
) -> list[AttemptRecord]:
    rows = (
        await conn.execute(
            text(
                "SELECT q.id, q.session_id, q.user_id, q.attempt_number, q.status, r.percent,"
                " q.created_at, q.finished_at FROM quiz q"
                " LEFT JOIN quiz_result r ON r.quiz_id = q.id"
                " WHERE (CAST(:s AS uuid) IS NULL OR q.session_id = :s)"
                " AND (CAST(:u AS uuid) IS NULL OR q.user_id = :u)"
                " ORDER BY q.created_at DESC, q.attempt_number DESC"
            ),
            {"s": session_id, "u": user_id},
        )
    ).all()
    return [
        AttemptRecord(str(r[0]), str(r[1]), str(r[2]), r[3], r[4], r[5], r[6], r[7]) for r in rows
    ]


async def chosen_map(conn: AsyncConnection, quiz_id: uuid.UUID) -> dict[str, int]:
    rows = (
        await conn.execute(
            text(
                "SELECT question_id, chosen_index FROM quiz_questions"
                " WHERE quiz_id = :q AND chosen_index IS NOT NULL"
            ),
            {"q": quiz_id},
        )
    ).all()
    return {r[0]: r[1] for r in rows}


async def record_choice(conn: AsyncConnection, quiz_id: uuid.UUID, qid: str, index: int) -> bool:
    """Store the first answer only. False when the question was already answered."""
    done = await conn.execute(
        text(
            "UPDATE quiz_questions SET chosen_index = :i, answered_at = now()"
            " WHERE quiz_id = :q AND question_id = :id AND type = 'mcq' AND chosen_index IS NULL"
        ),
        {"q": quiz_id, "id": qid, "i": index},
    )
    return done.rowcount == 1
