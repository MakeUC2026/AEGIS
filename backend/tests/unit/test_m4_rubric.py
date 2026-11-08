"""M4 A-01: the locked quiz rubric (PRD §13.4, M4-X31, M4-X32)."""

from __future__ import annotations

import pytest

from app.quiz import rubric

# M4-X32: if this fails you changed the rubric. That needs a new version, not a quiet edit.
PINNED_VERSION = "r1"
PINNED_HASH = "d7045b1161e0f56fda9546db9ce2f39346eca9b02f181e73c54e6e30b5a99210"


def test_rubric_has_the_four_prd_items_in_order() -> None:
    assert [i.key for i in rubric.RUBRIC] == [
        "attack",
        "why",
        "defense_layer",
        "prevention",
    ]
    assert all(i.max_points == 3 for i in rubric.RUBRIC)


def test_totals_are_five_mcq_plus_twelve_free_response() -> None:
    assert rubric.MCQ_COUNT == 5
    assert rubric.FREE_RESPONSE_MAX == 12
    assert rubric.TOTAL_POINTS == 17


def test_rubric_hash_is_pinned() -> None:
    assert rubric.RUBRIC_VERSION == PINNED_VERSION
    assert rubric.rubric_hash() == PINNED_HASH


def test_full_marks_is_one_hundred_percent() -> None:
    scores = dict.fromkeys(rubric.ITEM_KEYS, 3)
    assert rubric.percent(mcq_points=5, item_scores=scores) == 100


def test_zero_is_zero_percent() -> None:
    assert rubric.percent(mcq_points=0, item_scores=dict.fromkeys(rubric.ITEM_KEYS, 0)) == 0


def test_percent_rounds_to_whole_number() -> None:
    # 9 of 17 = 52.94 -> 53
    scores = {"attack": 3, "why": 1, "defense_layer": 0, "prevention": 0}
    assert rubric.percent(mcq_points=5, item_scores=scores) == 53


@pytest.mark.parametrize("bad", [-1, 4, 2.5, "3", True])
def test_item_score_must_be_integer_zero_to_three(bad: object) -> None:
    assert rubric.is_valid_item_score(bad) is False


@pytest.mark.parametrize("good", [0, 1, 2, 3])
def test_valid_item_scores(good: int) -> None:
    assert rubric.is_valid_item_score(good) is True


def test_percent_rejects_out_of_range_inputs() -> None:
    with pytest.raises(ValueError):
        rubric.percent(mcq_points=6, item_scores=dict.fromkeys(rubric.ITEM_KEYS, 0))
    with pytest.raises(ValueError):
        rubric.percent(
            mcq_points=0, item_scores={"attack": 4, "why": 0, "defense_layer": 0, "prevention": 0}
        )
    with pytest.raises(ValueError):
        rubric.percent(mcq_points=0, item_scores={"attack": 1})
