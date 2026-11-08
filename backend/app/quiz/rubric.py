"""Locked quiz rubric (PRD §13.4).

Do not edit the items or their wording without bumping RUBRIC_VERSION and the pinned hash in
tests/unit/test_m4_rubric.py. The grader prompt may change; the rubric may not (PRD §13.5).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass

RUBRIC_VERSION = "r1"
MCQ_COUNT = 5
MCQ_POINT_EACH = 1
ITEM_MAX = 3


@dataclass(frozen=True)
class RubricItem:
    key: str
    title: str
    max_points: int
    full_marks: str


RUBRIC: tuple[RubricItem, ...] = (
    RubricItem("attack", "Attack", ITEM_MAX, "Names the technique and how it reached the bot"),
    RubricItem(
        "why",
        "Why it worked or failed",
        ITEM_MAX,
        "Explains what the bot trusted or which check stopped it",
    ),
    RubricItem(
        "defense_layer",
        "Defense layer",
        ITEM_MAX,
        "Names the layer that made the difference "
        "(rule, cumulative scan, judge, risky history, review, divert)",
    ),
    RubricItem("prevention", "Prevention", ITEM_MAX, "Gives a concrete fix"),
)

ITEM_KEYS: tuple[str, ...] = tuple(i.key for i in RUBRIC)
FREE_RESPONSE_MAX = sum(i.max_points for i in RUBRIC)
MCQ_MAX = MCQ_COUNT * MCQ_POINT_EACH
TOTAL_POINTS = MCQ_MAX + FREE_RESPONSE_MAX


def rubric_hash() -> str:
    """Stable SHA-256 over the version and every item. Pinned in a test (M4-X32)."""
    payload = {
        "version": RUBRIC_VERSION,
        "mcq_count": MCQ_COUNT,
        "mcq_point_each": MCQ_POINT_EACH,
        "items": [
            {"key": i.key, "title": i.title, "max": i.max_points, "full": i.full_marks}
            for i in RUBRIC
        ],
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def is_valid_item_score(value: object) -> bool:
    """Integers 0..3 only. Rejects bool, floats, strings (M4-X29)."""
    return type(value) is int and 0 <= value <= ITEM_MAX


def percent(*, mcq_points: int, item_scores: Mapping[str, int]) -> int:
    """Total over 17, as a rounded whole percentage (PRD §13.4)."""
    if not 0 <= mcq_points <= MCQ_MAX:
        raise ValueError(f"mcq_points must be 0..{MCQ_MAX}")
    if set(item_scores) != set(ITEM_KEYS):
        raise ValueError("item_scores must hold exactly the rubric items")
    if not all(is_valid_item_score(v) for v in item_scores.values()):
        raise ValueError("item scores must be integers 0..3")
    total = mcq_points + sum(item_scores.values())
    return round(total * 100 / TOTAL_POINTS)
