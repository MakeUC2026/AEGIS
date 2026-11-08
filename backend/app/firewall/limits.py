"""Hard limits (M2 A-02; PRD §7.6; spec AEGIS-DOM-102).

Basic and Strict deny an oversized item; it is never truncated before checks, so the checks
see everything. Off truncates and the caller logs the truncation. Checks always use the full
session record; only the bot's model history is trimmed to the last 20 messages.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal

from app.contracts.common import Mode

PLAYER_TEXT_MAX = 4000
TOOL_RESULT_MAX = 8000
CALL_ARGS_MAX = 4000
REPLY_MAX = 4000
TOOL_ROUNDS_MAX = 5
BOT_HISTORY_MESSAGES = 20
CUMULATIVE_OUTPUT_MAX = 50_000  # Strict only: further replies are denied past this

TextKind = Literal["player_text", "tool_result", "reply"]
LimitAction = Literal["ok", "deny", "truncate"]

TEXT_LIMITS: Mapping[str, int] = MappingProxyType(
    {"player_text": PLAYER_TEXT_MAX, "tool_result": TOOL_RESULT_MAX, "reply": REPLY_MAX}
)


@dataclass(frozen=True)
class LimitOutcome:
    action: LimitAction
    text: str
    length: int  # the original length, for the log
    limit: int


@dataclass(frozen=True)
class ArgsOutcome:
    action: LimitAction
    args: Mapping[str, Any] = field(default_factory=dict)
    length: int = 0
    limit: int = CALL_ARGS_MAX


def check_text(kind: TextKind, text: str, mode: Mode) -> LimitOutcome:
    limit = TEXT_LIMITS[kind]
    if len(text) <= limit:
        return LimitOutcome("ok", text, len(text), limit)
    if mode == "off":
        return LimitOutcome("truncate", text[:limit], len(text), limit)
    return LimitOutcome("deny", text, len(text), limit)


def _value_chars(value: Any) -> int:
    return len(value) if isinstance(value, str) else len(json.dumps(value, ensure_ascii=False))


def args_chars(args: Mapping[str, Any]) -> int:
    return sum(_value_chars(v) for v in args.values())


def _truncate_to_fit(args: Mapping[str, Any]) -> dict[str, Any]:
    """Cut the longest string values until the total fits. Returns a new dict."""
    current = dict(args)
    excess = args_chars(current) - CALL_ARGS_MAX
    while excess > 0:
        strings = {k: v for k, v in current.items() if isinstance(v, str) and v}
        if not strings:
            break
        key = max(strings, key=lambda k: len(strings[k]))
        cut = min(excess, len(strings[key]))
        current = {**current, key: strings[key][: len(strings[key]) - cut]}
        excess -= cut
    return current


def check_args(args: Mapping[str, Any], mode: Mode) -> ArgsOutcome:
    total = args_chars(args)
    if total <= CALL_ARGS_MAX:
        return ArgsOutcome("ok", args, total)
    if mode != "off":
        return ArgsOutcome("deny", args, total)
    trimmed = _truncate_to_fit(args)
    if args_chars(trimmed) > CALL_ARGS_MAX:
        return ArgsOutcome("deny", args, total)  # nothing left to cut: fail closed even in Off
    return ArgsOutcome("truncate", trimmed, total)


def tool_rounds_exhausted(rounds_done: int) -> bool:
    return rounds_done >= TOOL_ROUNDS_MAX


def bot_history[T](messages: Sequence[T]) -> tuple[T, ...]:
    return tuple(messages[-BOT_HISTORY_MESSAGES:])


def cumulative_exceeded(visible_chars: int, mode: Mode) -> bool:
    return mode == "strict" and visible_chars > CUMULATIVE_OUTPUT_MAX
