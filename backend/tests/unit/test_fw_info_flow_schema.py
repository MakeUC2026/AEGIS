"""M2 D-04, part 1: no field for what must not flow (PRD I-3; spec AEGIS-DOM-130).

The shapes the browser and the teacher see (`PlayerView` and everything inside it, and the C3
read models) have no field that could carry a judge reason, a tool's arguments, blocked text or
a trace-back value. A new field with such a name fails this test and has to be argued for.
The C6 admin shapes are admin-only by design and are not walked.
"""

from __future__ import annotations

import types
import typing
from typing import Any

import pytest
from pydantic import BaseModel

from app.contracts import firewall, firewall_read
from app.contracts.firewall import TurnResult

# Names that would carry something I-3 keeps out of student and teacher views.
BANNED_NAMES = {
    "judge_reason", "reason",  # the judge's reasoning
    "args", "arguments", "canonical_args", "held_args", "tool_args", "held_tool_args",  # arguments
    "blocked_text", "withheld", "held_reply", "student_command",  # text that was stopped
    "trace_id", "trace_back", "trace_back_id", "ip", "ip_hash", "client_ip_hash", "subnet", "asn",
    "asn_org", "country", "user_agent", "client_fingerprint", "fingerprint_hash",  # network data
    "methods_used",  # forensic tags attached to a trace-back
}  # fmt: skip

PLAYER_ROOTS = [firewall.PlayerView]
C3_ROOTS = [
    firewall_read.TranscriptItem,
    firewall_read.DecisionItem,
    firewall_read.TicketItem,
    firewall_read.DivertItem,
    firewall_read.ForensicItem,
    firewall_read.SessionSummary,
    firewall_read.ManifestSummary,
    firewall_read.RuleCount,
    firewall_read.PatternCount,
    firewall_read.DecisionCount,
    firewall_read.FamilyCount,
    firewall.Catalog,
]


def _models_in(annotation: Any, seen: set[type[BaseModel]]) -> None:
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        if annotation in seen:
            return
        seen.add(annotation)
        for field in annotation.model_fields.values():
            _models_in(field.annotation, seen)
        return
    for arg in typing.get_args(annotation):
        if isinstance(arg, (type, types.GenericAlias, types.UnionType)) or typing.get_origin(arg):
            _models_in(arg, seen)


def _walk(roots: list[type[BaseModel]]) -> set[type[BaseModel]]:
    seen: set[type[BaseModel]] = set()
    for root in roots:
        _models_in(root, seen)
    return seen


@pytest.mark.parametrize(
    "models", [_walk(PLAYER_ROOTS), _walk(C3_ROOTS)], ids=["player view", "C3 read models"]
)
def test_no_model_has_a_field_that_could_carry_what_i3_keeps_out(
    models: set[type[BaseModel]],
) -> None:
    assert models  # the walk found something
    for model in models:
        banned = BANNED_NAMES & set(model.model_fields)
        assert not banned, f"{model.__name__} has {sorted(banned)}"


def test_the_walk_reaches_the_nested_models() -> None:
    names = {m.__name__ for m in _walk(PLAYER_ROOTS)}
    assert {"PlayerView", "FeedItem", "ToolEffect"} <= names
    assert "RuleSummary" in {m.__name__ for m in _walk(C3_ROOTS)}  # through the catalog


def test_the_facts_are_game_logic_only_and_not_part_of_the_player_view() -> None:
    assert "facts" not in firewall.PlayerView.model_fields
    assert "player_view" in TurnResult.model_fields and "facts" in TurnResult.model_fields
