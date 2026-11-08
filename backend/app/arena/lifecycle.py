"""Arena state machines (PRD §6.3 diagram; harness-os spec AEGIS-DOM-001)."""

from __future__ import annotations

TURN_STATES = ("sent", "replied", "blocked", "awaiting_review", "human_denied", "not_sent")
SESSION_STATES = ("active", "closed")
SECRET_STATES = ("fresh", "compromised")

_TURN = frozenset(
    {
        ("sent", "replied"),  # allow or divert
        ("sent", "blocked"),  # deny
        ("sent", "awaiting_review"),  # review
        ("sent", "not_sent"),  # AFF unreachable or 30 s timeout
        ("not_sent", "sent"),  # retry, same message ID
        ("awaiting_review", "replied"),  # approved
        ("awaiting_review", "human_denied"),  # reviewer "not ok"
        ("awaiting_review", "blocked"),  # expired
    }
)
_SESSION = frozenset({("active", "closed")})
_SECRET = frozenset({("fresh", "compromised")})


class InvalidTransition(ValueError):
    """A state change the PRD §6.3 lifecycle does not allow."""


def _check(table: frozenset[tuple[str, str]], kind: str, src: str, dst: str) -> None:
    if (src, dst) not in table:
        raise InvalidTransition(f"{kind}: {src} -> {dst} is not allowed")


def check_turn_transition(src: str, dst: str) -> None:
    _check(_TURN, "turn", src, dst)


def check_session_transition(src: str, dst: str) -> None:
    _check(_SESSION, "session", src, dst)


def check_secret_transition(src: str, dst: str) -> None:
    _check(_SECRET, "secret", src, dst)
