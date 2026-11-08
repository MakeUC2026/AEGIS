"""M4 A-05: grader hardening sample set loads and is well formed (PRD §13.5)."""

from __future__ import annotations

import re
from collections import Counter

import pytest
from pydantic import ValidationError

from app.quiz import rubric
from app.quiz.samples import SAMPLES_PATH, GraderSample, SampleSet, load_samples

SECRET_LIKE = re.compile(r"DEMO_[A-Z0-9]{16,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}")
GAMING_KINDS = {
    "full_marks_request",
    "answer_key_paste",
    "rubric_paste",
    "prompt_injection",
    "empty",
    "off_topic",
}


@pytest.fixture(scope="module")
def sample_set() -> SampleSet:
    return load_samples()


def test_at_least_ten_samples_with_unique_ids(sample_set: SampleSet) -> None:
    ids = [s.id for s in sample_set.samples]
    assert len(ids) >= 10
    assert len(ids) == len(set(ids))


def test_every_prd_gaming_kind_is_present(sample_set: SampleSet) -> None:
    kinds = {s.kind for s in sample_set.samples}
    assert kinds >= GAMING_KINDS


def test_at_least_three_good_samples(sample_set: SampleSet) -> None:
    assert sum(s.kind == "good" for s in sample_set.samples) >= 3


def test_expected_ranges_match_the_targets(sample_set: SampleSet) -> None:
    for s in sample_set.samples:
        assert 0 <= s.expected_min <= s.expected_max <= rubric.FREE_RESPONSE_MAX, s.id
        if s.kind == "good":
            assert s.expected_min >= 9, s.id  # PRD §13.5 target
        else:
            assert s.expected_max <= 3, s.id


def test_empty_sample_expects_zero(sample_set: SampleSet) -> None:
    empties = [s for s in sample_set.samples if s.kind == "empty"]
    assert empties
    for s in empties:
        assert s.expected_max == 0
        assert all(not t.text.strip() for t in s.conversation if t.role == "student")


def test_non_empty_samples_have_student_text(sample_set: SampleSet) -> None:
    for s in sample_set.samples:
        if s.kind != "empty":
            assert any(t.text.strip() for t in s.conversation if t.role == "student"), s.id


def test_scenario_covers_both_prompts_and_a_valid_key(sample_set: SampleSet) -> None:
    assert len(sample_set.scenario.questions) == 2
    covered = {i for q in sample_set.scenario.questions for i in q.rubric_items}
    assert covered == set(rubric.ITEM_KEYS)
    assert sample_set.scenario.answer_key.attack_happened is True


def test_pasted_key_sample_really_contains_the_key(sample_set: SampleSet) -> None:
    key = sample_set.scenario.answer_key
    pasted = [s for s in sample_set.samples if s.kind == "answer_key_paste"]
    assert pasted
    text = " ".join(t.text for s in pasted for t in s.conversation if t.role == "student")
    assert key.prevention[:30].lower() in text.lower()


def test_no_secret_looking_strings() -> None:
    assert not SECRET_LIKE.search(SAMPLES_PATH.read_text())


def test_loader_rejects_a_bad_range() -> None:
    with pytest.raises(ValidationError):
        GraderSample(
            id="x",
            kind="good",
            conversation=[],
            expected_min=11,
            expected_max=5,
        )


def test_kinds_are_spread_not_one_of_everything(sample_set: SampleSet) -> None:
    counts = Counter(s.kind for s in sample_set.samples)
    assert counts["good"] >= 3
    assert counts["prompt_injection"] >= 2
