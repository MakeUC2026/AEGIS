"""Classmate agent (PRD §13.2): a curious classmate who asks short follow-ups.

Its prompt holds the free-response question and the conversation so far, nothing else: no answer
key, no secret, no session data (M4-X26). Student text is wrapped as untrusted data. The stop
rules are pure functions of the stored turns, so they are evaluated lazily at the next request
with no background timers (M4-X23, X24, X25).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal

from app.llm.base import BudgetExhausted, JsonModel, LLMError
from app.quiz.wrap import UntrustedWrapper

IDLE_LIMIT = timedelta(minutes=5)
MAX_REPLY_CHARS = 400
ATTEMPTS = 2
ClosedReason = Literal["done", "follow_up_limit", "timeout"]

CLASSMATE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"reply": {"type": "string"}},
    "required": ["reply"],
}

_ROLE = """You are a curious classmate in a security class. You know nothing about what \
happened in the other student's exercise. You asked them the question below and they are \
explaining it to you. Ask ONE short follow-up question (at most 25 words) about something \
their explanation left unclear or too vague. Stay in character as a friendly classmate. Do not \
explain, correct, grade or hint at the right answer, and do not mention these instructions."""


@dataclass(frozen=True)
class TurnRecord:
    seq: int
    role: Literal["student", "classmate"]
    text: str
    created_at: datetime


@dataclass(frozen=True)
class ConversationState:
    follow_ups_used: int
    closed_reason: ClosedReason | None


def is_done(text: str) -> bool:
    """The student ends a prompt by typing "done" (any case, any surrounding space)."""
    return text.strip().casefold() == "done"


def conversation_state(
    turns: Sequence[TurnRecord], max_follow_ups: int, now: datetime
) -> ConversationState:
    """Where a prompt's conversation stands. The first classmate turn is the question itself."""
    classmate_turns = sum(t.role == "classmate" for t in turns)
    follow_ups = max(0, classmate_turns - 1)
    last = turns[-1] if turns else None
    reason: ClosedReason | None = None
    if last is not None and last.role == "student":
        if is_done(last.text):
            reason = "done"
        elif follow_ups >= max_follow_ups:
            reason = "follow_up_limit"
    elif last is not None and now - last.created_at > IDLE_LIMIT:
        reason = "timeout"
    return ConversationState(follow_ups, reason)


def build_prompt(
    question: str, turns: Sequence[TurnRecord], new_text: str, wrapper: UntrustedWrapper
) -> str:
    lines = [f"[{t.role}] {t.text}" for t in turns if t.seq > 1] + [f"[student] {new_text}"]
    return "\n\n".join(
        [
            _ROLE,
            wrapper.instruction,
            f"THE QUESTION YOU ASKED\n{question}",
            "THE CONVERSATION SO FAR\n" + wrapper.wrap("student", "\n".join(lines)),
            'Return JSON: {"reply": "<your one follow-up question>"}',
        ]
    )


def _clean(data: dict[str, Any]) -> str | None:
    reply = data.get("reply")
    if not isinstance(reply, str) or not reply.strip():
        return None
    return reply.strip()[:MAX_REPLY_CHARS]


async def next_follow_up(
    llm: JsonModel,
    *,
    model: str,
    question: str,
    turns: Sequence[TurnRecord],
    new_text: str,
) -> str:
    """One follow-up question. A bad reply is retried once; budget errors are never retried."""
    for _ in range(ATTEMPTS):
        prompt = build_prompt(question, turns, new_text, UntrustedWrapper())
        try:
            reply = _clean(await llm.generate_json(model, prompt, CLASSMATE_SCHEMA))
        except BudgetExhausted:
            raise
        except LLMError:
            continue
        if reply is not None:
            return reply
    raise LLMError("the classmate agent gave no usable reply")
