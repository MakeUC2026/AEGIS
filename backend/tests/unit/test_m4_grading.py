"""M4 A-03: MCQ grading in code (M4-X20, M4-X21, M4-X22)."""

from __future__ import annotations

import pytest

from app.quiz.grading import InvalidAnswer, grade_answer, mcq_points
from app.quiz.models import QuizSpec
from tests.unit.test_m4_models import good


def spec() -> QuizSpec:
    return QuizSpec.model_validate(good())  # every MCQ has answer_index 1


def test_correct_answer_scores_one_point_and_reveals_only_that_explanation() -> None:
    result = grade_answer(spec(), {}, "q2", 1)
    assert result.correct is True
    assert result.points == 1
    assert result.explanation == "Because of reason 2."
    assert result.already_answered is False


def test_wrong_answer_scores_zero_but_still_explains() -> None:
    result = grade_answer(spec(), {}, "q1", 0)
    assert result.correct is False
    assert result.points == 0
    assert result.explanation == "Because of reason 1."


def test_first_answer_wins_when_answered_twice() -> None:
    first = grade_answer(spec(), {}, "q1", 0)  # wrong
    again = grade_answer(spec(), {"q1": 0}, "q1", 1)  # would be right
    assert first.correct is False
    assert again.correct is False
    assert again.points == 0
    assert again.chosen_index == 0
    assert again.already_answered is True


@pytest.mark.parametrize("bad", [-1, 4, 100])
def test_index_out_of_range_is_invalid(bad: int) -> None:
    with pytest.raises(InvalidAnswer):
        grade_answer(spec(), {}, "q1", bad)


def test_out_of_range_is_rejected_even_if_already_answered() -> None:
    with pytest.raises(InvalidAnswer):
        grade_answer(spec(), {"q1": 1}, "q1", 9)


@pytest.mark.parametrize("bad", [True, 1.0, "1", None])
def test_non_integer_index_is_invalid(bad: object) -> None:
    with pytest.raises(InvalidAnswer):
        grade_answer(spec(), {}, "q1", bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("qid", ["q6", "q99", "nope"])
def test_unknown_or_free_response_question_is_invalid(qid: str) -> None:
    with pytest.raises(InvalidAnswer):
        grade_answer(spec(), {}, qid, 0)


def test_mcq_points_counts_only_correct_first_answers() -> None:
    assert mcq_points(spec(), {}) == 0
    assert mcq_points(spec(), {"q1": 1, "q2": 0, "q3": 1}) == 2
    assert mcq_points(spec(), {f"q{n}": 1 for n in range(1, 6)}) == 5


def test_mcq_points_ignores_unknown_ids() -> None:
    assert mcq_points(spec(), {"q1": 1, "q42": 1, "q6": 1}) == 1
