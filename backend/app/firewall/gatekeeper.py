"""Score combiner and Gatekeeper (M2 A-07; PRD §7.3, §7.4, D-01, D-02; spec AEGIS-DOM-105).

Score: `max(min(100, layer1 + layer2), judge)`. The judge can only raise it; a judge error or
timeout raises it to at least the Deny threshold. Bands come from the level's thresholds.

Hard overrides (each can only make the decision stricter):
- a rule with action review, deny or divert forces at least that action;
- an approved risky pattern, B-02 forged approval, an invalid tool call, an oversized item
  (PRD §7.6), any rule failure or a risky-history error forces Deny (fail closed);
- B-01 (secret in an outbound item) forces Deny in Basic and Off, Divert in Strict.
Strictest wins: Divert > Deny > Review > Allow.

Modes: Basic and Strict enforce the computed action. Off records it as `shadow_decision`
and enforces Allow, except an invalid tool call, which is denied in every mode.
An enforced Divert on a level with divert disabled becomes Deny (M2-DD-01).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal

from app.contracts.common import Mode, ScoreBand
from app.contracts.sentinel import JudgeVerdict, RiskyHistorySignals
from app.firewall.leak import LeakMatch
from app.firewall.rules import Evaluation
from app.firewall.sentinel_l1 import MAX_SCORE, Layer1Result

GateAction = Literal["allow", "review", "deny", "divert"]

JUDGE_FLOOR = 20  # PRD §18.2: the judge runs only when layers 1 + 2 reach this
_STRICTNESS: Mapping[str, int] = MappingProxyType({"allow": 0, "review": 1, "deny": 2, "divert": 3})
_FORCING_RULE_ACTIONS = frozenset({"review", "deny", "divert"})


@dataclass(frozen=True)
class GateInput:
    mode: Mode
    thresholds: Mapping[str, int]
    divert_enabled: bool
    layer1: Layer1Result
    rules: Evaluation = field(default_factory=lambda: Evaluation((), (), 0.0))
    history: RiskyHistorySignals | None = None
    history_error: bool = False
    judge: JudgeVerdict | None = None
    judge_error: bool = False
    leak: LeakMatch | None = None
    canonical_error: bool = False
    limit_exceeded: bool = False  # Off truncates instead, so this only shadows there


@dataclass(frozen=True)
class GateDecision:
    decision: GateAction  # what is enforced
    shadow_decision: GateAction | None  # Off only
    computed: GateAction  # before the mode is applied
    score: int
    breakdown: Mapping[str, int | None]
    rule_ids: tuple[str, ...]
    risky_pattern_ids: tuple[str, ...]
    priority_alert: bool
    score_band: ScoreBand


def judge_needed(layer12_score: int) -> bool:
    return layer12_score >= JUDGE_FLOOR


def band_action(score: int, thresholds: Mapping[str, int]) -> GateAction:
    if score >= thresholds["divert"]:
        return "divert"
    if score >= thresholds["deny"]:
        return "deny"
    if score >= thresholds["review"]:
        return "review"
    return "allow"


def score_band(score: int, thresholds: Mapping[str, int]) -> ScoreBand:
    if score < thresholds["review"]:
        return "low"
    if score < thresholds["deny"]:
        return "medium"
    return "high"


def _strictest(actions: list[GateAction]) -> GateAction:
    return max(actions, key=lambda a: _STRICTNESS[a])


def _layer2_points(history: RiskyHistorySignals | None) -> int:
    if history is None:
        return 0
    return history.user_tool_events_points + history.prior_divert_points + history.similarity_points


def _score(inp: GateInput) -> int:
    layer12 = min(MAX_SCORE, inp.layer1.score + _layer2_points(inp.history))
    judged = max(layer12, inp.judge.risk) if inp.judge is not None else layer12
    if inp.judge_error:
        judged = max(judged, inp.thresholds["deny"])
    return min(judged, MAX_SCORE)


def _forced(inp: GateInput) -> list[GateAction]:
    actions: list[GateAction] = [
        hit.action  # type: ignore[misc]
        for hit in inp.rules.hits
        if hit.action in _FORCING_RULE_ACTIONS
    ]
    fail_closed = (
        bool(inp.rules.failures)
        or inp.history_error
        or inp.canonical_error
        or inp.limit_exceeded
        or inp.layer1.forged_approval
        or (inp.history is not None and inp.history.forced_deny)
    )
    if fail_closed:
        actions = [*actions, "deny"]
    if inp.leak is not None:
        actions = [*actions, "divert" if inp.mode == "strict" else "deny"]
    return actions


def _breakdown(inp: GateInput) -> Mapping[str, int | None]:
    history = inp.history
    return MappingProxyType(
        {
            **inp.layer1.breakdown,
            "user_history": history.user_tool_events_points if history else None,
            "prior_divert": history.prior_divert_points if history else None,
            "similarity": history.similarity_points if history else None,
            "judge": inp.judge.risk if inp.judge is not None else None,
        }
    )


def _rule_ids(inp: GateInput) -> tuple[str, ...]:
    builtins = (("B-01",) if inp.leak is not None else ()) + (
        ("B-02",) if inp.layer1.forged_approval else ()
    )
    return tuple(hit.rule_id for hit in inp.rules.hits) + builtins


def decide(inp: GateInput) -> GateDecision:
    score = _score(inp)
    computed = _strictest([band_action(score, inp.thresholds), *_forced(inp)])
    if inp.mode == "off":
        enforced: GateAction = "deny" if inp.canonical_error else "allow"
        shadow: GateAction | None = computed
    else:
        enforced = "deny" if computed == "divert" and not inp.divert_enabled else computed
        shadow = None
    return GateDecision(
        decision=enforced,
        shadow_decision=shadow,
        computed=computed,
        score=score,
        breakdown=_breakdown(inp),
        rule_ids=_rule_ids(inp),
        risky_pattern_ids=tuple(inp.history.matched_pattern_ids) if inp.history else (),
        priority_alert=score >= inp.thresholds["alert"],
        score_band=score_band(score, inp.thresholds),
    )
