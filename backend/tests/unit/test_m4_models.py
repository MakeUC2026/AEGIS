"""M4 A-02 / A-04 (answer key): private quiz spec, public quiz, answer key.

Covers M4-X17 (shape validation), E-60 groundwork (public model has no answers), M4-X16 groundwork.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from app.quiz.models import AnswerKey, QuizSpec, to_public

TOPICS = ["attack", "why", "defense_layer", "prevention", "divert"]


def _mcq(n: int) -> dict[str, Any]:
    return {
        "id": f"q{n}",
        "type": "mcq",
        "topic": TOPICS[(n - 1) % 5],
        "prompt": f"Question {n}?",
        "options": ["A thing", "Another thing", "Third thing", "Fourth thing"],
        "answer_index": 1,
        "explanation": f"Because of reason {n}.",
    }


def _fr(n: int, items: list[str]) -> dict[str, Any]:
    return {
        "id": f"q{n}",
        "type": "free_response",
        "topic": items[0],
        "prompt": "Explain it to a classmate.",
        "max_follow_ups": 3,
        "rubric_items": items,
    }


def good() -> dict[str, Any]:
    return {
        "rubric_version": "r1",
        "questions": [
            *[_mcq(n) for n in range(1, 6)],
            _fr(6, ["attack", "why"]),
            _fr(7, ["defense_layer", "prevention"]),
        ],
    }


def test_valid_spec_parses() -> None:
    spec = QuizSpec.model_validate(good())
    assert len(spec.mcqs) == 5
    assert len(spec.free_responses) == 2


def test_invalid_json_text_rejected() -> None:
    with pytest.raises(ValidationError):
        QuizSpec.model_validate_json("not json at all")


def test_four_mcqs_rejected() -> None:
    data = good()
    data["questions"].pop(0)
    with pytest.raises(ValidationError):
        QuizSpec.model_validate(data)


def test_one_free_response_rejected() -> None:
    data = good()
    data["questions"].pop()
    with pytest.raises(ValidationError):
        QuizSpec.model_validate(data)


@pytest.mark.parametrize("idx", [-1, 4, 99])
def test_answer_index_out_of_range_rejected(idx: int) -> None:
    data = good()
    data["questions"][0]["answer_index"] = idx
    with pytest.raises(ValidationError):
        QuizSpec.model_validate(data)


def test_uncovered_rubric_item_rejected() -> None:
    data = good()
    data["questions"][6]["rubric_items"] = ["defense_layer"]
    with pytest.raises(ValidationError, match="prevention"):
        QuizSpec.model_validate(data)


def test_unknown_rubric_item_rejected() -> None:
    data = good()
    data["questions"][5]["rubric_items"] = ["attack", "why", "vibes"]
    with pytest.raises(ValidationError):
        QuizSpec.model_validate(data)


def test_duplicate_question_ids_rejected() -> None:
    data = good()
    data["questions"][1]["id"] = "q1"
    with pytest.raises(ValidationError):
        QuizSpec.model_validate(data)


def test_duplicate_options_rejected() -> None:
    data = good()
    data["questions"][0]["options"] = ["Same", "Same", "Other", "More"]
    with pytest.raises(ValidationError):
        QuizSpec.model_validate(data)


def test_wrong_rubric_version_rejected() -> None:
    data = good()
    data["rubric_version"] = "r2"
    with pytest.raises(ValidationError):
        QuizSpec.model_validate(data)


def test_unknown_fields_rejected() -> None:
    data = good()
    data["questions"][0]["hint"] = "pick B"
    with pytest.raises(ValidationError):
        QuizSpec.model_validate(data)


def test_max_follow_ups_capped_at_three() -> None:
    data = good()
    data["questions"][5]["max_follow_ups"] = 4
    with pytest.raises(ValidationError):
        QuizSpec.model_validate(data)


def test_public_quiz_has_no_answer_fields_anywhere() -> None:
    spec = QuizSpec.model_validate(good())
    public = to_public(spec, quiz_id="qz-1", session_id="ses-1")
    dumped = json.dumps(public.model_dump(mode="json"))
    for forbidden in ("answer_index", "explanation", "Because of reason"):
        assert forbidden not in dumped
    # Free-response rubric items are grader-facing, not student-facing.
    assert "rubric_items" not in dumped
    assert public.quiz_id == "qz-1"
    assert len(public.questions) == 7


def test_public_model_class_has_no_answer_fields() -> None:
    from app.quiz.models import PublicMcq, PublicQuiz

    for model in (PublicMcq, PublicQuiz):
        assert "answer_index" not in model.model_fields
        assert "explanation" not in model.model_fields


def test_to_public_does_not_mutate_spec() -> None:
    data = good()
    before = copy.deepcopy(data)
    spec = QuizSpec.model_validate(data)
    to_public(spec, quiz_id="qz-1", session_id="ses-1")
    assert spec.model_dump(mode="json") == QuizSpec.model_validate(before).model_dump(mode="json")


# ---- answer key (A-04, M4-X16) ----


def test_answer_key_for_an_attack() -> None:
    key = AnswerKey(
        attack_happened=True,
        attack_family="indirect_injection",
        why_it_worked_or_failed="The bot trusted instructions inside the document.",
        deciding_layer="judge",
        prevention="Treat retrieved documents as data and scan them.",
        was_diverted=False,
    )
    assert key.attack_family == "indirect_injection"


def test_answer_key_no_attack_variant() -> None:
    key = AnswerKey.no_attack("Only normal questions were asked, so nothing needed blocking.")
    assert key.attack_happened is False
    assert key.attack_family is None
    assert key.deciding_layer == "none"
    assert "nothing" in key.why_it_worked_or_failed.lower()


def test_no_attack_key_cannot_name_a_family() -> None:
    with pytest.raises(ValidationError):
        AnswerKey(
            attack_happened=False,
            attack_family="direct_override",
            why_it_worked_or_failed="x",
            deciding_layer="none",
            prevention="y",
            was_diverted=False,
        )


def test_attack_key_must_name_a_family() -> None:
    with pytest.raises(ValidationError):
        AnswerKey(
            attack_happened=True,
            attack_family=None,
            why_it_worked_or_failed="x",
            deciding_layer="rule",
            prevention="y",
            was_diverted=False,
        )


def test_answer_key_unknown_layer_rejected() -> None:
    with pytest.raises(ValidationError):
        AnswerKey(
            attack_happened=True,
            attack_family="shell_abuse",
            why_it_worked_or_failed="x",
            deciding_layer="magic",  # type: ignore[arg-type]
            prevention="y",
            was_diverted=False,
        )
