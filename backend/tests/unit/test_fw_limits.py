"""M2 A-02 hard limits (spec AEGIS-DOM-102; PRD §7.6).

Basic and Strict deny oversized items (never truncate before checks); Off truncates and logs.
Cases: M2-X07, M2-X08, M2-X09, M2-X10, M2-X35.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from app.firewall.limits import (
    BOT_HISTORY_MESSAGES,
    CALL_ARGS_MAX,
    CUMULATIVE_OUTPUT_MAX,
    PLAYER_TEXT_MAX,
    REPLY_MAX,
    TOOL_RESULT_MAX,
    TOOL_ROUNDS_MAX,
    args_chars,
    bot_history,
    check_args,
    check_text,
    cumulative_exceeded,
    tool_rounds_exhausted,
)


def test_limit_values_match_the_prd() -> None:
    assert (PLAYER_TEXT_MAX, TOOL_RESULT_MAX, CALL_ARGS_MAX, REPLY_MAX) == (4000, 8000, 4000, 4000)
    assert (TOOL_ROUNDS_MAX, BOT_HISTORY_MESSAGES, CUMULATIVE_OUTPUT_MAX) == (5, 20, 50_000)


# --- M2-X07: player text boundary -----------------------------------------------------------


@pytest.mark.parametrize("mode", ["off", "basic", "strict"])
def test_exactly_at_the_limit_is_fine_in_every_mode(mode: str) -> None:
    out = check_text("player_text", "a" * 4000, mode)
    assert (out.action, out.text, out.length) == ("ok", "a" * 4000, 4000)


@pytest.mark.parametrize("mode", ["basic", "strict"])
def test_one_over_is_denied_untruncated_in_enforcing_modes(mode: str) -> None:
    out = check_text("player_text", "a" * 4001, mode)
    assert (out.action, out.length, out.limit) == ("deny", 4001, 4000)
    assert out.text == "a" * 4001  # checks always see the full item


def test_one_over_is_truncated_and_flagged_in_off() -> None:
    out = check_text("player_text", "a" * 4001, "off")
    assert (out.action, out.text, out.length) == ("truncate", "a" * 4000, 4001)


# --- M2-X08: tool result, reply and call arguments -------------------------------------------


@pytest.mark.parametrize(("kind", "limit"), [("tool_result", 8000), ("reply", 4000)])
def test_other_text_limits(kind: str, limit: int) -> None:
    assert check_text(kind, "x" * limit, "strict").action == "ok"  # type: ignore[arg-type]
    assert check_text(kind, "x" * (limit + 1), "basic").action == "deny"  # type: ignore[arg-type]
    off = check_text(kind, "x" * (limit + 1), "off")  # type: ignore[arg-type]
    assert (off.action, len(off.text)) == ("truncate", limit)


def test_args_total_counts_every_value() -> None:
    assert args_chars({"to": "ab", "subject": "cde", "body": "f"}) == 6
    assert args_chars({"n": 12345}) == 5  # non-strings by their JSON text


def test_args_within_limit_pass_unchanged() -> None:
    args = {"to": "a@b.co", "subject": "s", "body": "b" * 3900}
    out = check_args(args, "strict")
    assert (out.action, out.args) == ("ok", args)


def test_args_each_under_schema_but_together_over_are_denied() -> None:
    args = {"to": "a@b.co", "subject": "s" * 300, "body": "b" * 3800}  # 4106 in total
    assert check_args(args, "basic").action == "deny"
    assert check_args(args, "strict").args == args  # never truncated before checks


def test_off_truncates_the_longest_values_until_the_args_fit() -> None:
    args = {"to": "a@b.co", "subject": "s" * 300, "body": "b" * 3800}
    out = check_args(args, "off")
    assert out.action == "truncate"
    assert args_chars(out.args) == CALL_ARGS_MAX
    assert out.args["to"] == "a@b.co"  # short values left alone
    assert args["body"] == "b" * 3800  # input not mutated


# --- M2-X09, M2-X10, M2-X35 -------------------------------------------------------------------


def test_tool_rounds() -> None:
    assert [tool_rounds_exhausted(n) for n in range(7)] == [False] * 5 + [True, True]


def test_bot_sees_only_the_last_twenty_messages() -> None:
    messages = [f"m{i}" for i in range(25)]
    assert bot_history(messages) == tuple(messages[5:])
    assert bot_history(messages[:3]) == tuple(messages[:3])


def test_cumulative_output_cap_is_strict_only() -> None:
    assert cumulative_exceeded(50_000, "strict") is False
    assert cumulative_exceeded(50_001, "strict") is True
    assert cumulative_exceeded(10**6, "basic") is False
    assert cumulative_exceeded(10**6, "off") is False


# --- Properties ----------------------------------------------------------------------------------


@settings(max_examples=200)
@given(
    args=st.dictionaries(st.text(max_size=8), st.text(max_size=3000), max_size=4),
    mode=st.sampled_from(["off", "basic", "strict"]),
)
def test_property_args_outcome_is_consistent(args: dict[str, str], mode: str) -> None:
    out = check_args(args, mode)  # type: ignore[arg-type]
    fits = args_chars(args) <= CALL_ARGS_MAX
    assert (out.action == "ok") == fits
    if out.action == "truncate":
        assert mode == "off" and args_chars(out.args) <= CALL_ARGS_MAX
    if out.action == "deny":
        assert mode != "off" and out.args == args
