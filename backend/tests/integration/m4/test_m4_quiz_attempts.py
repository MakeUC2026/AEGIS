"""M4 C3: quiz start, assign, resume, retakes, latest and best.
M4-X11..X15, X17 (nothing stored), X33 (budget) and the quiz status column of the sessions list."""

from __future__ import annotations

import asyncio

from sqlalchemy import text

from app.llm.base import BudgetExhausted
from tests.m4_quiz_support import QuizWorld, good_quiz


async def _rows(qw: QuizWorld, table: str = "quiz") -> int:
    async with qw.w.engine.connect() as conn:
        sql = text(f"SELECT count(*) FROM {table}")  # noqa: S608
        return int((await conn.execute(sql)).scalar_one())


async def _list_status(qw: QuizWorld, who, session_id: str) -> str:  # type: ignore[no-untyped-def]
    resp = await qw.w.client.get("/api/classroom/sessions", headers=who.headers)
    return next(r["quiz_status"] for r in resp.json()["items"] if r["id"] == session_id)


async def test_student_starts_a_quiz_on_their_own_session(qw: QuizWorld) -> None:
    s = qw.session(closed=False)
    llm = qw.script(json=[good_quiz()])
    resp = await qw.start(qw.ada, s.id)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "in_progress" and body["attempt_number"] == 1
    assert len(body["questions"]) == 7 and body["session_id"] == s.id
    assert len(llm.json_calls) == 1
    assert qw.w.arena.unlocked == [s.id]  # X15: still-active session, recap unlocked


async def test_student_cannot_start_on_someone_elses_session(qw: QuizWorld) -> None:  # X11
    s = qw.session()
    llm = qw.script(json=[good_quiz()])
    resp = await qw.start(qw.ben, s.id)
    assert resp.status_code == 403
    assert llm.json_calls == [] and await _rows(qw) == 0
    assert qw.w.arena.unlocked == []


async def test_unknown_session_is_404_and_bad_id_is_422(qw: QuizWorld) -> None:
    qw.script()
    assert (await qw.start(qw.ada, "00000000-0000-4000-8000-00000000ffff")).status_code == 404
    assert (await qw.start(qw.ada, "../etc")).status_code == 422


async def test_starting_again_resumes_without_a_duplicate(qw: QuizWorld) -> None:  # X14
    s = qw.session()
    llm = qw.script(json=[good_quiz()])
    first = (await qw.start(qw.ada, s.id)).json()
    second = (await qw.start(qw.ada, s.id)).json()
    assert second["quiz_id"] == first["quiz_id"] and second["questions"] == first["questions"]
    assert len(llm.json_calls) == 1 and await _rows(qw) == 1
    assert await _rows(qw, "quiz_questions") == 7


async def test_two_simultaneous_starts_make_one_quiz(qw: QuizWorld) -> None:  # X14
    s = qw.session()
    llm = qw.script(json=[good_quiz(), good_quiz()])
    a, b = await asyncio.gather(qw.start(qw.ada, s.id), qw.start(qw.ada, s.id))
    assert {a.status_code, b.status_code} <= {200, 409} and 200 in {a.status_code, b.status_code}
    winner = a if a.status_code == 200 else b
    assert len(llm.json_calls) == 1  # the loser is refused before any model call
    again = await qw.start(qw.ada, s.id)  # the loser simply opens the same quiz
    assert again.status_code == 200 and again.json()["quiz_id"] == winner.json()["quiz_id"]
    assert await _rows(qw) == 1 and await _rows(qw, "quiz_questions") == 7


async def test_assign_then_start_then_status_moves_on(qw: QuizWorld) -> None:  # X12
    s = qw.session()
    qw.script(json=[good_quiz()])
    assigned = await qw.w.client.post(
        "/api/quiz/assign", json={"session_id": s.id}, headers=qw.cho.headers
    )
    assert assigned.status_code == 200 and assigned.json()["status"] == "assigned"
    assert await _list_status(qw, qw.cho, s.id) == "assigned"
    started = (await qw.start(qw.ada, s.id)).json()
    assert started["quiz_id"] == assigned.json()["quiz_id"]
    assert started["status"] == "in_progress" and len(started["questions"]) == 7
    assert await _list_status(qw, qw.cho, s.id) == "in_progress"
    assert await _rows(qw) == 1


async def test_assign_twice_does_not_duplicate(qw: QuizWorld) -> None:
    s = qw.session()
    qw.script()
    body = {"session_id": s.id}
    a = await qw.w.client.post("/api/quiz/assign", json=body, headers=qw.cho.headers)
    b = await qw.w.client.post("/api/quiz/assign", json=body, headers=qw.cho.headers)
    assert a.json()["quiz_id"] == b.json()["quiz_id"] and await _rows(qw) == 1


async def test_assigned_quiz_has_no_questions_until_started(qw: QuizWorld) -> None:
    s = qw.session()
    qw.script()
    qid = (
        await qw.w.client.post(
            "/api/quiz/assign", json={"session_id": s.id}, headers=qw.cho.headers
        )
    ).json()["quiz_id"]
    got = await qw.w.client.get(f"/api/quiz/quizzes/{qid}", headers=qw.ada.headers)
    assert got.json()["questions"] == [] and got.json()["status"] == "assigned"


async def test_students_and_firewall_admins_cannot_assign(qw: QuizWorld) -> None:  # X04
    s = qw.session()
    qw.script()
    for who in (qw.ada, qw.dee):
        resp = await qw.w.client.post(
            "/api/quiz/assign", json={"session_id": s.id}, headers=who.headers
        )
        assert resp.status_code == 403
    assert await _rows(qw) == 0


async def test_retake_after_done_is_a_new_attempt_with_latest_and_best(
    qw: QuizWorld,
) -> None:  # X13
    s = qw.session()
    qw.script(json=[good_quiz(), good_quiz()])
    first = (await qw.start(qw.ada, s.id)).json()
    await qw.force_done(first["quiz_id"], percent=90)
    second = (await qw.start(qw.ada, s.id)).json()
    assert second["attempt_number"] == 2 and second["quiz_id"] != first["quiz_id"]
    await qw.force_done(second["quiz_id"], percent=60)
    attempts = await qw.w.client.get(f"/api/quiz/sessions/{s.id}/attempts", headers=qw.ada.headers)
    body = attempts.json()
    assert [a["attempt_number"] for a in body["attempts"]] == [2, 1]
    assert body["latest_percent"] == 60 and body["best_percent"] == 90
    row = next(
        r
        for r in (await qw.w.client.get("/api/classroom/sessions", headers=qw.cho.headers)).json()[
            "items"
        ]
        if r["id"] == s.id
    )
    assert (row["quiz_status"], row["quiz_score"], row["quiz_best"]) == ("done", 60, 90)


async def test_attempts_are_private_to_the_student_and_visible_to_the_teacher(
    qw: QuizWorld,
) -> None:
    s = qw.session()
    qw.script(json=[good_quiz()])
    await qw.start(qw.ada, s.id)
    url = f"/api/quiz/sessions/{s.id}/attempts"
    assert len((await qw.w.client.get(url, headers=qw.cho.headers)).json()["attempts"]) == 1
    assert (await qw.w.client.get(url, headers=qw.ben.headers)).json()["attempts"] == []


async def test_mine_lists_only_my_quizzes(qw: QuizWorld) -> None:
    s = qw.session()
    qw.script(json=[good_quiz()])
    await qw.start(qw.ada, s.id)
    mine = await qw.w.client.get("/api/quiz/mine", headers=qw.ada.headers)
    assert [m["session_id"] for m in mine.json()["items"]] == [s.id]
    assert (await qw.w.client.get("/api/quiz/mine", headers=qw.ben.headers)).json()["items"] == []


async def test_get_quiz_is_owner_or_teacher_only(qw: QuizWorld) -> None:
    s = qw.session()
    qw.script(json=[good_quiz()])
    qid = (await qw.start(qw.ada, s.id)).json()["quiz_id"]
    url = f"/api/quiz/quizzes/{qid}"
    assert (await qw.w.client.get(url, headers=qw.ada.headers)).status_code == 200
    assert (await qw.w.client.get(url, headers=qw.cho.headers)).status_code == 200
    assert (await qw.w.client.get(url, headers=qw.ben.headers)).status_code == 403
    assert (await qw.w.client.get(url, headers=qw.dee.headers)).status_code == 403
    missing = "/api/quiz/quizzes/00000000-0000-4000-8000-00000000ffff"
    assert (await qw.w.client.get(missing, headers=qw.ada.headers)).status_code == 404
    assert (
        await qw.w.client.get("/api/quiz/quizzes/not-a-uuid", headers=qw.ada.headers)
    ).status_code == 404


async def test_failed_generation_stores_nothing_and_can_be_retried(qw: QuizWorld) -> None:  # X17
    s = qw.session()
    qw.script(json=[{}, {"questions": []}])
    resp = await qw.start(qw.ada, s.id)
    assert resp.status_code == 502 and "try again" in resp.json()["detail"].lower()
    assert await _rows(qw) == 0 and await _rows(qw, "quiz_questions") == 0
    qw.script(json=[good_quiz()])
    assert (await qw.start(qw.ada, s.id)).status_code == 200


async def test_budget_exhausted_is_refused_with_a_clear_message(qw: QuizWorld) -> None:  # X33
    s = qw.session()
    qw.script(json=[BudgetExhausted("used up")])
    resp = await qw.start(qw.ada, s.id)
    assert resp.status_code == 429 and "budget" in resp.json()["detail"].lower()
    assert await _rows(qw) == 0


async def test_benign_session_quiz_is_valid(qw: QuizWorld) -> None:  # X16
    from tests.m4_quiz_support import benign_session

    s = benign_session(qw.w.arena, qw.read, user_id=qw.ada.id)
    qw.script(json=[good_quiz()])
    resp = await qw.start(qw.ada, s.id)
    assert resp.status_code == 200 and len(resp.json()["questions"]) == 7
    async with qw.w.engine.connect() as conn:
        key = (await conn.execute(text("SELECT answer_key FROM quiz"))).scalar_one()
    assert key["attack_happened"] is False
