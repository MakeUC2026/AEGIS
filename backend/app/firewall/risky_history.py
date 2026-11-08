"""Strict Sentinel layer 2: risky history (PRD §7.3, §7.5, M3 A-02).

Phase A holds the scoring math. The single-query `lookup`, `record_behavior` and
`add_candidate` (C7 `RiskyHistoryPort`) land with the `0004_firewall_intel` migration (B-02).
"""

from __future__ import annotations

from typing import Literal

from app.contracts.sentinel import RiskyHistorySignals

USER_TOOL_POINTS_EACH = 15
USER_TOOL_POINTS_MAX = 30
USER_TOOL_WINDOW_DAYS = 7
PRIOR_DIVERT_POINTS = 20
SIMILARITY_HIGH = 0.85  # +25
SIMILARITY_LOW = 0.75  # +10


def similarity_points(top: float | None) -> Literal[0, 10, 25]:
    """Only one bucket applies (PRD §7.3)."""
    if top is None:
        return 0
    if top >= SIMILARITY_HIGH:
        return 25
    if top >= SIMILARITY_LOW:
        return 10
    return 0


def score_signals(
    *,
    tool: str | None,
    matched_pattern_ids: list[str],
    same_tool_events: int,
    has_prior_divert: bool,
    similarity_top: float | None,
    latency_ms: int,
) -> RiskyHistorySignals:
    """Layer 2 points from already-filtered counts.

    `same_tool_events`: this user's non-shadow events on `tool` in the last 7 days.
    `has_prior_divert`: any earlier non-shadow divert by this user.
    An input check (`tool is None`) skips the user-tool signal (M3-X06).
    """
    user_points = (
        0 if tool is None else min(USER_TOOL_POINTS_EACH * same_tool_events, USER_TOOL_POINTS_MAX)
    )
    return RiskyHistorySignals(
        forced_deny=bool(matched_pattern_ids),
        matched_pattern_ids=matched_pattern_ids,
        user_tool_events_points=user_points,
        prior_divert_points=PRIOR_DIVERT_POINTS if has_prior_divert else 0,
        similarity_points=similarity_points(similarity_top),
        similarity_top=similarity_top,
        latency_ms=latency_ms,
    )
