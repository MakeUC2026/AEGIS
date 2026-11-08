"""M4 C4: public quiz view and MCQ answers. E-60, M4-X20, X21, X22."""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import text

from tests.m4_quiz_support import QuizWorld, good_quiz

LEAKY = ("answer_index", "explanation", "answer_key", "Because of reason", "rubric_items")


async def _started(qw: QuizWorld) -> dict:  # type: ignore[type-arg]
    s = qw.session()
    qw.script(json=[good_quiz(answer=1)])
    resp = await qw.start(qw.ada, s.id)
    assert resp.status_code == 200
    return resp.json()


def _url(quiz: dict, qid: str) -> str:  # type: ignore[type-arg]
    return f"/api/quiz/quizzes/{quiz['quiz_id']}/questions/{qid}/answer"


async def _answer(qw: QuizWorld, quiz: dict, qid: str, index, who=None):  # type: ignore[no-untyped-def]
    return await qw.w.client.post(
        _url(quiz, qid), json={"index": index}, headers=(who or qw.ada).headers
    )


def _right(quiz: dict, qid: str) -> int:  # type: ignore[type-arg]
    # good_quiz(answer=1) puts the right option at index 1 before the shuffle; look it up by text.
    n = int(qid[1:])
    q = next(x for x in quiz["questions"] if x["id"] == qid)
    return q["options"].index(f"Option {n}B")


async def test_no_response_before_answering_contains_an_answer(qw: QuizWorld) -> None:  # E-60
    quiz = await _started(qw)
    fetched = await qw.w.client.get(f"/api/quiz/quizzes/{quiz['quiz_id']}", headers=qw.ada.headers)
    teacher = await qw.w.client.get(f"/api/quiz/quizzes/{quiz['quiz_id']}", headers=qw.cho.headers)
    for body in (str(quiz), fetched.text, teacher.text):
        for word in LEAKY:
            assert word not in body, word
    assert quiz["answered"] == []
    for q in quiz["questions"]:
        assert set(q) <= {"id", "type", "topic", "prompt", "options", "max_follow_ups"}


async def test_correct_answer_returns_correctness_and_its_explanation(qw: QuizWorld) -> None:
    quiz = await _started(qw)
    resp = await _answer(qw, quiz, "q1", _right(quiz, "q1"))
    assert resp.status_code == 200
    assert resp.json() == {
        "question_id": "q1",
        "chosen_index": _right(quiz, "q1"),
        "correct": True,
        "explanation": "Because of reason 1.",
        "already_answered": False,
    }


async def test_wrong_answer_is_marked_wrong(qw: QuizWorld) -> None:
    quiz = await _started(qw)
    wrong = 0 if _right(quiz, "q2") != 0 else 1
    body = (await _answer(qw, quiz, "q2", wrong)).json()
    assert body["correct"] is False and body["explanation"] == "Because of reason 2."


async def test_answering_q1_reveals_only_q1(qw: QuizWorld) -> None:  # X22
    quiz = await _started(qw)
    resp = await _answer(qw, quiz, "q1", _right(quiz, "q1"))
    assert "reason 2" not in resp.text and "reason 5" not in resp.text
    fetched = await qw.w.client.get(f"/api/quiz/quizzes/{quiz['quiz_id']}", headers=qw.ada.headers)
    body = fetched.json()
    assert [a["question_id"] for a in body["answered"]] == ["q1"]
    for n in (2, 3, 4, 5):
        assert f"reason {n}" not in fetched.text
    assert "answer_index" not in fetched.text


async def test_second_answer_does_not_change_the_first(qw: QuizWorld) -> None:  # X20
    quiz = await _started(qw)
    right, other = _right(quiz, "q1"), (_right(quiz, "q1") + 1) % 4
    first = await _answer(qw, quiz, "q1", other)
    second = await _answer(qw, quiz, "q1", right)
    assert first.json()["correct"] is False
    assert second.json()["correct"] is False and second.json()["already_answered"] is True
    assert second.json()["chosen_index"] == other
    async with qw.w.engine.connect() as conn:
        chosen = (
            await conn.execute(
                text("SELECT chosen_index FROM quiz_questions WHERE question_id='q1'")
            )
        ).scalar_one()
    assert chosen == other


async def test_simultaneous_answers_keep_exactly_one(qw: QuizWorld) -> None:  # X20
    quiz = await _started(qw)
    a, b = await asyncio.gather(_answer(qw, quiz, "q3", 0), _answer(qw, quiz, "q3", 1))
    assert a.json()["chosen_index"] == b.json()["chosen_index"]
    assert {a.json()["already_answered"], b.json()["already_answered"]} <= {True, False}


@pytest.mark.parametrize("bad", [-1, 4, 99, "1", 1.5, True, None])
async def test_bad_index_is_422(qw: QuizWorld, bad: object) -> None:  # X21
    quiz = await _started(qw)
    assert (await _answer(qw, quiz, "q1", bad)).status_code == 422
    async with qw.w.engine.connect() as conn:
        n = (
            await conn.execute(
                text("SELECT count(*) FROM quiz_questions WHERE chosen_index IS NOT NULL")
            )
        ).scalar_one()
    assert n == 0


async def test_unknown_or_free_response_question(qw: QuizWorld) -> None:
    quiz = await _started(qw)
    assert (await _answer(qw, quiz, "q9", 0)).status_code == 404
    assert (await _answer(qw, quiz, "q6", 0)).status_code == 422
    assert (await _answer(qw, quiz, "q1x", 0)).status_code == 422  # path pattern is wider; shape


async def test_only_the_owner_may_answer(qw: QuizWorld) -> None:
    quiz = await _started(qw)
    for who in (qw.ben, qw.cho, qw.dee):
        assert (await _answer(qw, quiz, "q1", 0, who)).status_code == 403


async def test_cannot_answer_once_the_quiz_is_done(qw: QuizWorld) -> None:
    quiz = await _started(qw)
    await qw.force_done(quiz["quiz_id"])
    assert (await _answer(qw, quiz, "q1", 0)).status_code == 409


async def test_cannot_answer_an_assigned_quiz_with_no_questions(qw: QuizWorld) -> None:
    s = qw.session()
    qw.script()
    qid = (
        await qw.w.client.post(
            "/api/quiz/assign", json={"session_id": s.id}, headers=qw.cho.headers
        )
    ).json()["quiz_id"]
    resp = await qw.w.client.post(
        f"/api/quiz/quizzes/{qid}/questions/q1/answer", json={"index": 0}, headers=qw.ada.headers
    )
    assert resp.status_code in (404, 409)
