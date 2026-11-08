"""MCQ grading in code (PRD §13.2): 1 point each, the first answer counts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from app.quiz import rubric
from app.quiz.models import McqQuestion, QuizSpec


class InvalidAnswer(ValueError):
    """Unknown question, not an MCQ, or an index outside the options (M4-X21)."""


@dataclass(frozen=True)
class McqResult:
    question_id: str
    chosen_index: int
    correct: bool
    points: int
    explanation: str
    already_answered: bool


def _mcq(spec: QuizSpec, question_id: str) -> McqQuestion:
    for q in spec.mcqs:
        if q.id == question_id:
            return q
    raise InvalidAnswer(f"{question_id} is not a multiple-choice question in this quiz")


def grade_answer(
    spec: QuizSpec, answered: Mapping[str, int], question_id: str, index: int
) -> McqResult:
    """Grade one answer. `answered` holds earlier first answers; the earliest one is kept.

    The result carries this question's explanation only (M4-X22).
    """
    question = _mcq(spec, question_id)
    if type(index) is not int or not 0 <= index < len(question.options):
        raise InvalidAnswer("answer index is outside the options")
    already = question_id in answered
    chosen = answered[question_id] if already else index
    correct = chosen == question.answer_index
    return McqResult(
        question_id=question_id,
        chosen_index=chosen,
        correct=correct,
        points=rubric.MCQ_POINT_EACH if correct else 0,
        explanation=question.explanation,
        already_answered=already,
    )


def mcq_points(spec: QuizSpec, answered: Mapping[str, int]) -> int:
    """Total MCQ points from the stored first answers. Unknown ids are ignored."""
    return sum(
        rubric.MCQ_POINT_EACH
        for q in spec.mcqs
        if answered.get(q.id) is not None and answered[q.id] == q.answer_index
    )
