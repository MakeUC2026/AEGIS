"""Grader hardening samples (PRD §13.5): loader and models for fixtures/quiz/m4_grader_samples.json.

Used by the unit test now and by the opt-in live run against real Gemini in Phase D.
"""

from __future__ import annotations

import json
import pathlib
from typing import Annotated, Literal, Self

from pydantic import StringConstraints, model_validator

from app.contracts.common import Contract
from app.quiz import rubric
from app.quiz.models import AnswerKey, FreeResponseQuestion

SAMPLES_PATH = (
    pathlib.Path(__file__).resolve().parents[3] / "fixtures" / "quiz" / "m4_grader_samples.json"
)

SampleKind = Literal[
    "good",
    "full_marks_request",
    "answer_key_paste",
    "rubric_paste",
    "prompt_injection",
    "empty",
    "off_topic",
]


class Turn(Contract):
    question_id: str
    role: Literal["classmate", "student"]
    text: Annotated[str, StringConstraints(max_length=2000)]


class Scenario(Contract):
    summary: str
    questions: list[FreeResponseQuestion]
    answer_key: AnswerKey


class GraderSample(Contract):
    id: str
    kind: SampleKind
    conversation: list[Turn]
    expected_min: int
    expected_max: int

    @model_validator(mode="after")
    def _range(self) -> Self:
        if not 0 <= self.expected_min <= self.expected_max <= rubric.FREE_RESPONSE_MAX:
            raise ValueError("expected range must satisfy 0 <= min <= max <= 12")
        return self


class SampleSet(Contract):
    scenario: Scenario
    samples: list[GraderSample]


def load_samples(path: pathlib.Path = SAMPLES_PATH) -> SampleSet:
    return SampleSet.model_validate(json.loads(path.read_text()))
