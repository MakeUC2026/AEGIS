"""Arena turn and session state machines (PRD §6.3; harness-os AEGIS-DOM-001, 34 cases)."""

from __future__ import annotations

import itertools

import pytest

from app.arena.lifecycle import (
    SESSION_STATES,
    TURN_STATES,
    InvalidTransition,
    check_secret_transition,
    check_session_transition,
    check_turn_transition,
)

VALID_TURN = {
    ("sent", "replied"),
    ("sent", "blocked"),
    ("sent", "awaiting_review"),
    ("sent", "not_sent"),
    ("not_sent", "sent"),
    ("awaiting_review", "replied"),
    ("awaiting_review", "human_denied"),
    ("awaiting_review", "blocked"),
}
TURN_CASES = list(itertools.permutations(TURN_STATES, 2))


def test_state_sets_match_spec() -> None:
    assert set(TURN_STATES) == {
        "sent",
        "replied",
        "blocked",
        "awaiting_review",
        "human_denied",
        "not_sent",
    }
    assert set(SESSION_STATES) == {"active", "closed"}
    assert len(TURN_CASES) == 30  # 30 turn cases + 2 session + 2 secret = 34


@pytest.mark.parametrize(("src", "dst"), TURN_CASES)
def test_turn_transition(src: str, dst: str) -> None:
    if (src, dst) in VALID_TURN:
        check_turn_transition(src, dst)
    else:
        with pytest.raises(InvalidTransition):
            check_turn_transition(src, dst)


def test_session_transitions() -> None:
    check_session_transition("active", "closed")
    with pytest.raises(InvalidTransition):
        check_session_transition("closed", "active")


def test_secret_state_only_moves_forward() -> None:
    check_secret_transition("fresh", "compromised")
    with pytest.raises(InvalidTransition):
        check_secret_transition("compromised", "fresh")
