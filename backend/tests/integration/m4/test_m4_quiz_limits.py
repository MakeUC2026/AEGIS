"""M4 hardening (security review findings 1 and 2): model spend is bounded per quiz and per student.

* only one generation runs per student and session at a time (a concurrent start gets 409);
* a student can start only so many generated quizzes per hour (429 with a clear message);
* concurrent follow-up turns and concurrent finishes do not multiply model calls.
"""

from __future__ import annotations

import asyncio
import uuid

from app.quiz import repo
from app.quiz.service import QUIZ_STARTS_PER_HOUR
from tests.m4_quiz_support import QuizWorld, classmate, feedback, good_quiz, grade


async def test_simultaneous_starts_run_one_generation(qw: QuizWorld) -> None:
    s = qw.session()
    llm = qw.script(json=[good_quiz(), good_quiz(), good_quiz()])
    results = await asyncio.gather(*(qw.start(qw.ada, s.id) for _ in range(3)))
    codes = sorted(r.status_code for r in results)
    assert codes.count(200) >= 1 and set(codes) <= {200, 409}
    # one generation; a late start that finds the committed quiz resumes it (200, no model call)
    assert len(llm.json_calls) == 1
    assert (await qw.start(qw.ada, s.id)).status_code == 200  # afterwards it simply resumes
    async with qw.w.engine.connect() as conn:
        assert (await repo.attempts(conn, session_id=uuid.UUID(s.id), user_id=None)).__len__() == 1


async def test_hourly_cap_refuses_a_new_generation_before_calling_the_model(
    qw: QuizWorld,
) -> None:
    s = qw.session()
    llm = qw.script(json=[good_quiz()])
    async with qw.w.engine.begin() as conn:
        for _ in range(QUIZ_STARTS_PER_HOUR):
            await repo.insert_quiz(
                conn,
                session_id=uuid.uuid4(),
                user_id=uuid.UUID(qw.ada.id),
                attempt=1,
                status="done",
                assigned_by=None,
                key=None,
            )
    resp = await qw.start(qw.ada, s.id)
    assert resp.status_code == 429 and "try again" in resp.json()["detail"].lower()
    assert llm.json_calls == []
    async with qw.w.engine.connect() as conn:
        assert await repo.open_attempt(conn, uuid.UUID(s.id), uuid.UUID(qw.ada.id)) is None


async def test_cap_is_per_student_and_resume_is_never_blocked(qw: QuizWorld) -> None:
    mine = qw.session()
    qw.script(json=[good_quiz()])
    assert (await qw.start(qw.ada, mine.id)).status_code == 200
    async with qw.w.engine.begin() as conn:
        for _ in range(QUIZ_STARTS_PER_HOUR):
            await repo.insert_quiz(
                conn,
                session_id=uuid.uuid4(),
                user_id=uuid.UUID(qw.ada.id),
                attempt=1,
                status="done",
                assigned_by=None,
                key=None,
            )
    assert (await qw.start(qw.ada, mine.id)).status_code == 200  # resume: no model call
    other = qw.session(user_id=qw.ben.id)
    qw.script(json=[good_quiz()])
    assert (await qw.start(qw.ben, other.id)).status_code == 200  # Ben is not limited by Ada


async def test_concurrent_turns_do_not_multiply_classmate_calls(qw: QuizWorld) -> None:
    s = qw.session()
    llm = qw.script(json=[good_quiz(), *[classmate() for _ in range(5)]])
    quiz = (await qw.start(qw.ada, s.id)).json()
    url = f"/api/quiz/quizzes/{quiz['quiz_id']}/turns"

    async def say(n: int):  # type: ignore[no-untyped-def]
        return await qw.w.client.post(
            url, json={"question_id": "q6", "text": f"answer {n}"}, headers=qw.ada.headers
        )

    results = await asyncio.gather(*(say(n) for n in range(5)))
    codes = [r.status_code for r in results]
    assert codes.count(200) >= 1 and set(codes) <= {200, 409}
    classmate_calls = len(llm.json_calls) - 1  # minus the generator call
    assert classmate_calls == codes.count(200)  # no spend for a request that then lost


async def test_concurrent_finish_grades_once(qw: QuizWorld) -> None:
    s = qw.session()
    llm = qw.script(json=[good_quiz(), grade(), feedback(), grade(), feedback()])
    quiz = (await qw.start(qw.ada, s.id)).json()
    for n in (6, 7):
        r = await qw.w.client.post(
            f"/api/quiz/quizzes/{quiz['quiz_id']}/turns",
            json={"question_id": f"q{n}", "text": "done"},
            headers=qw.ada.headers,
        )
        assert r.status_code == 200
    before = len(llm.json_calls)
    url = f"/api/quiz/quizzes/{quiz['quiz_id']}/finish"
    results = await asyncio.gather(
        *(qw.w.client.post(url, headers=qw.ada.headers) for _ in range(2))
    )
    codes = sorted(r.status_code for r in results)
    assert codes.count(200) >= 1 and set(codes) <= {200, 409}
    spent = len(llm.json_calls) - before
    assert spent <= 2  # one grade and one feedback call, never doubled
