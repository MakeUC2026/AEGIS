"""Quiz generator (PRD §13.2): one structured-output call, validated, retried once.

Never returns a partial quiz: either a full valid `QuizSpec` or `QuizGenerationFailed`.
`BudgetExhausted` is not retried (M4-X33). Generated text is redacted again, option order is
shuffled in code (so a "make every answer A" line in a transcript cannot bias the key), and
question ids are assigned here, not trusted from the model.
"""

from __future__ import annotations

import random
from collections.abc import Awaitable, Callable
from typing import Any

from pydantic import ValidationError

from app.llm.base import BudgetExhausted, JsonModel, LLMError
from app.quiz import rubric
from app.quiz.context import QuizContext
from app.quiz.models import FREE_RESPONSE_COUNT, FreeResponseQuestion, McqQuestion, QuizSpec
from app.quiz.wrap import UntrustedWrapper

Redact = Callable[[str], Awaitable[str]]
MAX_ATTEMPTS = 2
GENERATE_TIMEOUT_S = 90.0  # the Pro model writing 7 questions can take well over 30 s
_TOPICS = ["attack", "why", "defense_layer", "prevention", "divert"]
_RUBRIC = ["attack", "why", "defense_layer", "prevention"]

QUIZ_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "questions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": ["mcq", "free_response"]},
                    "topic": {"type": "string", "enum": _TOPICS},
                    "prompt": {"type": "string"},
                    "options": {"type": "array", "items": {"type": "string"}},
                    "answer_index": {"type": "integer"},
                    "explanation": {"type": "string"},
                    "max_follow_ups": {"type": "integer"},
                    "rubric_items": {"type": "array", "items": {"type": "string", "enum": _RUBRIC}},
                },
                "required": ["type", "topic", "prompt"],
            },
        }
    },
    "required": ["questions"],
}

_TASK = """You write a teach-back quiz for a student who just played a prompt-injection defence \
game against an AI firewall. The quiz must be about THIS session only.

Write exactly 5 multiple-choice questions, then exactly 2 free-response prompts.
- Multiple choice: 3 to 4 distinct options, one correct (answer_index, zero based) and a short \
explanation. Cover these topics, one question each: attack, why, defense_layer, prevention, \
divert (were you diverted, and how could you tell?). Distractors must be plausible and come \
from the other defence modes (off, basic, strict) and other rules or layers, so the student \
must know what actually happened.
- Free response: ask the student to explain to a curious classmate. Together the two prompts \
must cover the rubric items attack, why, defense_layer and prevention (rubric_items). Set \
max_follow_ups to 3.
- Base every answer on the SESSION FACTS and the ANSWER KEY below. Never reveal or guess a \
secret value; the secret appears as [SECRET].
- If the key says no attack happened, ask about what normal use looks like and why nothing \
was blocked."""


def _key_block(context: QuizContext) -> str:
    k = context.answer_key
    if not k.attack_happened:
        return "ANSWER KEY\nno attack happened in this session. " + k.why_it_worked_or_failed
    family = (k.attack_family or "").replace("_", " ")
    return (
        "ANSWER KEY\n"
        f"attack family: {family}\n"
        f"why it worked or failed: {k.why_it_worked_or_failed}\n"
        f"deciding layer: {k.deciding_layer.replace('_', ' ')}\n"
        f"diverted: {'yes' if k.was_diverted else 'no'}\n"
        f"prevention: {k.prevention}"
    )


def build_prompt(context: QuizContext, wrapper: UntrustedWrapper, problem: str | None) -> str:
    parts = [_TASK, wrapper.instruction, context.render(wrapper), _key_block(context)]
    if problem:
        parts.append(f"Your previous answer was invalid: {problem}. Return a corrected quiz.")
    return "\n\n".join(parts)


class QuizGenerationFailed(Exception):
    """The model could not produce a valid quiz after one retry. Nothing was stored."""


async def _clean(raw: dict[str, Any], redact: Redact) -> dict[str, Any]:
    out = dict(raw)
    for field in ("prompt", "explanation"):
        if isinstance(out.get(field), str):
            out[field] = await redact(out[field])
    if isinstance(out.get("options"), list):
        out["options"] = [await redact(o) if isinstance(o, str) else o for o in out["options"]]
    return out


async def _parse(data: dict[str, Any], redact: Redact, rng: random.Random) -> QuizSpec:
    items = data.get("questions")
    if not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
        raise ValueError("questions must be a list of objects")
    mcqs: list[McqQuestion] = []
    frees: list[FreeResponseQuestion] = []
    for item in items:
        item = await _clean(item, redact)
        if item.get("type") == "mcq":
            mcqs.append(_shuffled(item, f"q{len(mcqs) + 1}", rng))
        elif item.get("type") == "free_response":
            frees.append(
                FreeResponseQuestion(
                    id=f"q{rubric.MCQ_COUNT + len(frees) + 1}",
                    topic=item.get("topic"),  # type: ignore[arg-type]
                    prompt=item.get("prompt"),  # type: ignore[arg-type]
                    max_follow_ups=item.get("max_follow_ups", 3),
                    rubric_items=item.get("rubric_items", []),
                )
            )
        else:
            raise ValueError("unknown question type")
    if len(mcqs) > rubric.MCQ_COUNT or len(frees) > FREE_RESPONSE_COUNT:
        raise ValueError("too many questions")
    return QuizSpec(rubric_version=rubric.RUBRIC_VERSION, questions=[*mcqs, *frees])


def _shuffled(item: dict[str, Any], qid: str, rng: random.Random) -> McqQuestion:
    options, index = item.get("options"), item.get("answer_index")
    if not isinstance(options, list) or type(index) is not int or not 0 <= index < len(options):
        raise ValueError("mcq needs options and an answer_index inside them")
    order = list(range(len(options)))
    rng.shuffle(order)
    return McqQuestion(
        id=qid,
        topic=item.get("topic"),  # type: ignore[arg-type]
        prompt=item.get("prompt"),  # type: ignore[arg-type]
        options=[options[i] for i in order],
        answer_index=order.index(index),
        explanation=item.get("explanation"),  # type: ignore[arg-type]
    )


async def generate_quiz(
    llm: JsonModel,
    *,
    model: str,
    context: QuizContext,
    redact: Redact,
    rng: random.Random | None = None,
) -> QuizSpec:
    rng = rng or random.SystemRandom()
    problem: str | None = None
    for _ in range(MAX_ATTEMPTS):
        prompt = build_prompt(context, UntrustedWrapper(), problem)
        try:
            data = await llm.generate_json(model, prompt, QUIZ_SCHEMA, timeout_s=GENERATE_TIMEOUT_S)
            return await _parse(data, redact, rng)
        except BudgetExhausted:
            raise
        except LLMError:
            problem = "the model call failed"
        except (ValidationError, ValueError, TypeError) as exc:
            problem = str(exc).splitlines()[0][:200] if str(exc) else "bad shape"
    raise QuizGenerationFailed(problem or "invalid quiz")
