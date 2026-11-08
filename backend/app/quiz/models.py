"""Quiz models (PRD §13.3).

Two families, kept apart on purpose:

* `QuizSpec` is the private shape the generator returns and the database stores. It holds
  `answer_index` and `explanation`. It must never be returned from a route.
* `PublicQuiz` is the only shape a route may return before the student answers (E-60). It has no
  answer fields at all, so there is nothing to leak by mistake.

`AnswerKey` is the private key the grader and feedback writer use (PRD §13.2).
"""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import Field, StringConstraints, model_validator

from app.contracts.common import Contract
from app.contracts.fixtures import AttackFamily
from app.quiz import rubric

MCQ_OPTIONS_MIN = 3
MCQ_OPTIONS_MAX = 5
MAX_FOLLOW_UPS = 3
FREE_RESPONSE_COUNT = 2

Topic = Literal["attack", "why", "defense_layer", "prevention", "divert"]
RubricKey = Literal["attack", "why", "defense_layer", "prevention"]
DecidingLayer = Literal[
    "rule", "cumulative_scan", "judge", "risky_history", "review", "divert", "none"
]

QuestionId = Annotated[str, StringConstraints(pattern=r"^q[0-9]{1,2}$")]
Prompt = Annotated[str, StringConstraints(min_length=1, max_length=600)]
Option = Annotated[str, StringConstraints(min_length=1, max_length=200)]
Explanation = Annotated[str, StringConstraints(min_length=1, max_length=800)]


class McqQuestion(Contract):
    id: QuestionId
    type: Literal["mcq"] = "mcq"
    topic: Topic
    prompt: Prompt
    options: list[Option] = Field(min_length=MCQ_OPTIONS_MIN, max_length=MCQ_OPTIONS_MAX)
    answer_index: int
    explanation: Explanation

    @model_validator(mode="after")
    def _check(self) -> Self:
        if not 0 <= self.answer_index < len(self.options):
            raise ValueError("answer_index is outside the options")
        if len({o.strip().casefold() for o in self.options}) != len(self.options):
            raise ValueError("options must be distinct")
        return self


class FreeResponseQuestion(Contract):
    id: QuestionId
    type: Literal["free_response"] = "free_response"
    topic: RubricKey
    prompt: Prompt
    max_follow_ups: int = Field(default=MAX_FOLLOW_UPS, ge=0, le=MAX_FOLLOW_UPS)
    rubric_items: list[RubricKey] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_items(self) -> Self:
        if len(set(self.rubric_items)) != len(self.rubric_items):
            raise ValueError("rubric_items must be unique")
        return self


Question = Annotated[McqQuestion | FreeResponseQuestion, Field(discriminator="type")]


class QuizSpec(Contract):
    """Private quiz: generator output and stored form. Never returned from a route."""

    rubric_version: str
    questions: list[Question]

    @property
    def mcqs(self) -> list[McqQuestion]:
        return [q for q in self.questions if isinstance(q, McqQuestion)]

    @property
    def free_responses(self) -> list[FreeResponseQuestion]:
        return [q for q in self.questions if isinstance(q, FreeResponseQuestion)]

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.rubric_version != rubric.RUBRIC_VERSION:
            raise ValueError(f"rubric_version must be {rubric.RUBRIC_VERSION}")
        if len(self.mcqs) != rubric.MCQ_COUNT:
            raise ValueError(f"need exactly {rubric.MCQ_COUNT} multiple-choice questions")
        if len(self.free_responses) != FREE_RESPONSE_COUNT:
            raise ValueError(f"need exactly {FREE_RESPONSE_COUNT} free-response prompts")
        ids = [q.id for q in self.questions]
        if len(set(ids)) != len(ids):
            raise ValueError("question ids must be unique")
        covered = {item for q in self.free_responses for item in q.rubric_items}
        missing = [k for k in rubric.ITEM_KEYS if k not in covered]
        if missing:
            raise ValueError(f"rubric items not covered by free response: {', '.join(missing)}")
        return self


class PublicMcq(Contract):
    id: str
    type: Literal["mcq"] = "mcq"
    topic: Topic
    prompt: str
    options: list[str]


class PublicFreeResponse(Contract):
    id: str
    type: Literal["free_response"] = "free_response"
    topic: RubricKey
    prompt: str
    max_follow_ups: int


PublicQuestion = Annotated[PublicMcq | PublicFreeResponse, Field(discriminator="type")]


class PublicQuiz(Contract):
    """What a route may return. No answers, explanations, rubric items or key."""

    quiz_id: str
    session_id: str
    rubric_version: str
    questions: list[PublicQuestion]


def to_public(spec: QuizSpec, *, quiz_id: str, session_id: str) -> PublicQuiz:
    """Build the public view field by field, so a new private field can never slip through."""
    questions: list[PublicMcq | PublicFreeResponse] = []
    for q in spec.questions:
        if isinstance(q, McqQuestion):
            questions.append(
                PublicMcq(id=q.id, topic=q.topic, prompt=q.prompt, options=list(q.options))
            )
        else:
            questions.append(
                PublicFreeResponse(
                    id=q.id, topic=q.topic, prompt=q.prompt, max_follow_ups=q.max_follow_ups
                )
            )
    return PublicQuiz(
        quiz_id=quiz_id,
        session_id=session_id,
        rubric_version=spec.rubric_version,
        questions=questions,
    )


class AnswerKey(Contract):
    """Private key for the grader and feedback writer (PRD §13.2). Never sent to a browser."""

    attack_happened: bool
    attack_family: AttackFamily | None
    why_it_worked_or_failed: Annotated[str, StringConstraints(min_length=1, max_length=1500)]
    deciding_layer: DecidingLayer
    prevention: Annotated[str, StringConstraints(min_length=1, max_length=1500)]
    was_diverted: bool

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.attack_happened and self.attack_family is None:
            raise ValueError("an attack must name its family")
        if not self.attack_happened and (
            self.attack_family is not None or self.deciding_layer != "none"
        ):
            raise ValueError("a no-attack key has no family and no deciding layer")
        return self

    @classmethod
    def no_attack(
        cls, why: str, prevention: str = "No attack happened, so nothing to fix."
    ) -> Self:
        """Key for a session with only benign messages (M4-X16)."""
        return cls(
            attack_happened=False,
            attack_family=None,
            why_it_worked_or_failed=why,
            deciding_layer="none",
            prevention=prevention,
            was_diverted=False,
        )
