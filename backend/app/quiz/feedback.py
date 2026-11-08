"""Feedback writer (PRD §13.2): sees only the grade and the answer key, never student text.

The function has no parameter that could carry student or transcript text (M4-X30). If the model
fails, a short message built from the same two inputs is used, so a finished grade is never lost
to a feedback error.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

from app.llm.base import BudgetExhausted, JsonModel, LLMError
from app.quiz import rubric
from app.quiz.models import AnswerKey

MAX_FEEDBACK_CHARS = 1200
ATTEMPTS = 2
GOOD_SCORE = 2
Redact = Callable[[str], Awaitable[str]]

FEEDBACK_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"feedback": {"type": "string"}},
    "required": ["feedback"],
}

_TASK = """You write short feedback for a student who just finished a teach-back quiz about \
their own prompt-injection session. You see only their scores and the private answer key. You \
have NOT seen their words, so never claim to quote or describe what they wrote; talk about what \
the scores show.

Write plain text (no markdown), at most 120 words, speaking to the student as "you", in three \
short parts: what went well (areas scoring 2 or 3), what was missing (areas scoring 0 or 1, \
using the answer key), and one specific thing to look at in your own session (drawn from the \
key, such as the layer that made the difference). Be encouraging and concrete. Never reveal a \
secret value. Return JSON: {"feedback": "<the text>"}."""


@dataclass(frozen=True)
class FeedbackResult:
    text: str
    fallback: bool


def _key_block(key: AnswerKey) -> str:
    if not key.attack_happened:
        return "ANSWER KEY\nno attack happened. " + key.why_it_worked_or_failed
    return (
        "ANSWER KEY\n"
        f"attack family: {(key.attack_family or '').replace('_', ' ')}\n"
        f"why it worked or failed: {key.why_it_worked_or_failed}\n"
        f"deciding layer: {key.deciding_layer.replace('_', ' ')}\n"
        f"diverted: {'yes' if key.was_diverted else 'no'}\n"
        f"prevention: {key.prevention}"
    )


def build_prompt(mcq_points: int, item_scores: Mapping[str, int], key: AnswerKey) -> str:
    lines = [f"mcq: {mcq_points} / {rubric.MCQ_MAX}"]
    lines += [
        f"{i.key}: {item_scores[i.key]} / {i.max_points} ({i.title}; full marks: {i.full_marks})"
        for i in rubric.RUBRIC
    ]
    return "\n\n".join([_TASK, "GRADE\n" + "\n".join(lines), _key_block(key)])


def fallback_feedback(item_scores: Mapping[str, int], key: AnswerKey) -> str:
    strong = [i.title for i in rubric.RUBRIC if item_scores[i.key] >= GOOD_SCORE]
    weak = [i for i in rubric.RUBRIC if item_scores[i.key] < GOOD_SCORE]
    parts = ["Strong: " + (", ".join(strong) if strong else "nothing yet, keep going") + "."]
    if weak:
        parts.append(
            "Missing: " + "; ".join(f"{i.title} ({i.full_marks.lower()})" for i in weak) + "."
        )
    parts.append(f"Look at your session again: {key.prevention}")
    return " ".join(parts)


async def write_feedback(
    llm: JsonModel,
    *,
    model: str,
    mcq_points: int,
    item_scores: Mapping[str, int],
    key: AnswerKey,
    redact: Redact | None,
) -> FeedbackResult:
    prompt = build_prompt(mcq_points, item_scores, key)
    text: str | None = None
    for _ in range(ATTEMPTS):
        try:
            data = await llm.generate_json(model, prompt, FEEDBACK_SCHEMA)
        except BudgetExhausted:
            break
        except LLMError:
            continue
        value = data.get("feedback")
        if isinstance(value, str) and value.strip():
            text = value.strip()
            break
    fallback = text is None
    final = text if text is not None else fallback_feedback(item_scores, key)
    if redact is not None:
        final = await redact(final)
    return FeedbackResult(final[:MAX_FEEDBACK_CHARS], fallback)
