"""Quiz API shapes. Anything returned before the student answers is built from `PublicQuiz`."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, StrictInt

from app.contracts.common import Contract
from app.quiz.models import PublicQuiz

QuizStatus = Literal["assigned", "in_progress", "grading_failed", "done"]


class AnsweredMcq(Contract):
    """Only ever present for questions the student has already answered."""

    question_id: str
    chosen_index: int
    correct: bool
    explanation: str


class TurnView(Contract):
    question_id: str
    seq: int
    role: Literal["student", "classmate"]
    text: str


class QuizView(PublicQuiz):
    status: QuizStatus
    attempt_number: int
    answered: list[AnsweredMcq] = Field(default_factory=list)
    turns: list[TurnView] = Field(default_factory=list)


class StartIn(Contract):
    session_id: str = Field(max_length=64, pattern=r"^[A-Za-z0-9_-]+$")


class AssignOut(Contract):
    quiz_id: str
    session_id: str
    status: QuizStatus
    attempt_number: int


class AttemptRow(Contract):
    quiz_id: str
    attempt_number: int
    status: QuizStatus
    percent: int | None
    created_at: str
    finished_at: str | None


class AttemptList(Contract):
    session_id: str
    attempts: list[AttemptRow]
    latest_percent: int | None
    best_percent: int | None


class MineRow(Contract):
    quiz_id: str
    session_id: str
    attempt_number: int
    status: QuizStatus
    percent: int | None
    created_at: str


class MineList(Contract):
    items: list[MineRow]


class AnswerIn(Contract):
    index: StrictInt


class AnswerOut(Contract):
    """Correctness and this question's explanation only (M4-X22)."""

    question_id: str
    chosen_index: int
    correct: bool
    explanation: str
    already_answered: bool
