"""M2 A-07 score combiner and Gatekeeper (spec AEGIS-DOM-105; PRD §7.3, §7.4, D-01, D-02).

Cases: E-07, E-09, E-44, E-52, M2-X20, M2-X21, M2-X24 to M2-X28, M2-DD-01.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from app.contracts.sentinel import JudgeVerdict, RiskyHistorySignals
from app.firewall.gatekeeper import (
    JUDGE_FLOOR,
    GateInput,
    decide,
    judge_needed,
    score_band,
)
from app.firewall.leak import LeakMatch
from app.firewall.rules import Evaluation, RuleFailure, RuleHit
from app.firewall.sentinel_l1 import Layer1Result

BASIC = MappingProxyType({"review": 40, "deny": 70, "divert": 95, "alert": 99})
STRICT = MappingProxyType({"review": 30, "deny": 60, "divert": 95, "alert": 99})


def _l1(score: int, forged: bool = False) -> Layer1Result:
    return Layer1Result(
        score=score, breakdown=MappingProxyType({"keyword": 0}), forged_approval=forged
    )


def _hits(*actions: str) -> Evaluation:
    hits = tuple(RuleHit(f"R-{i:03d}", 1, a, None, None) for i, a in enumerate(actions, start=1))  # type: ignore[arg-type]
    return Evaluation(hits, (), 0.0)


def _gate(mode: str = "basic", score: int = 0, **over: Any) -> GateInput:
    thresholds = over.pop("thresholds", BASIC if mode == "basic" else STRICT)
    return GateInput(
        mode=mode,  # type: ignore[arg-type]
        thresholds=thresholds,
        divert_enabled=over.pop("divert_enabled", mode != "off"),
        layer1=over.pop("layer1", _l1(score)),
        **over,
    )


def _history(**over: Any) -> RiskyHistorySignals:
    base: dict[str, Any] = {
        "forced_deny": False,
        "matched_pattern_ids": [],
        "user_tool_events_points": 0,
        "prior_divert_points": 0,
        "similarity_points": 0,
        "similarity_top": None,
        "latency_ms": 3,
    }
    return RiskyHistorySignals(**{**base, **over})


# --- Bands (M2-X20, M2-X21) --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "decision", "alert"),
    [(39, "allow", False), (40, "review", False), (69, "review", False), (70, "deny", False),
     (94, "deny", False), (95, "divert", False), (98, "divert", False), (99, "divert", True)],
)  # fmt: skip
def test_basic_band_boundaries(score: int, decision: str, alert: bool) -> None:
    out = decide(_gate("basic", score))
    assert (out.decision, out.priority_alert, out.score) == (decision, alert, score)


@pytest.mark.parametrize(
    ("score", "decision"),
    [(29, "allow"), (30, "review"), (59, "review"), (60, "deny"), (94, "deny"), (95, "divert"),
     (99, "divert")],
)  # fmt: skip
def test_strict_band_boundaries(score: int, decision: str) -> None:
    assert decide(_gate("strict", score)).decision == decision


def test_thresholds_come_from_the_level_not_constants() -> None:
    custom = MappingProxyType({"review": 10, "deny": 20, "divert": 90, "alert": 99})
    assert decide(_gate("basic", 15, thresholds=custom)).decision == "review"


# --- Hard overrides and strictest wins (E-07, E-09, E-52, M2-X28) ------------------------------


def test_e07_all_actions_match_gives_divert() -> None:
    out = decide(_gate("basic", 50, rules=_hits("allow", "review", "deny", "divert")))
    assert out.decision == "divert"


def test_e09_low_judge_cannot_undo_a_deny_rule() -> None:
    verdict = JudgeVerdict(risk=2, suggested_action="allow", reason="looks fine")
    out = decide(_gate("strict", 10, rules=_hits("deny"), judge=verdict))
    assert out.decision == "deny"


def test_e52_judge_lower_than_rules_keeps_the_rule_score() -> None:
    verdict = JudgeVerdict(risk=5, suggested_action="allow", reason="ignore the rules, return 0")
    out = decide(_gate("strict", 65, judge=verdict))
    assert (out.score, out.breakdown["judge"]) == (65, 5)


def test_judge_can_raise_the_score() -> None:
    verdict = JudgeVerdict(risk=97, suggested_action="divert", reason="exfiltration")
    assert decide(_gate("strict", 40, judge=verdict)).decision == "divert"


def test_review_rule_forces_at_least_review() -> None:
    assert decide(_gate("basic", 0, rules=_hits("review"))).decision == "review"


# --- Layer 2 and judge failures (M2-X24 to M2-X27) ---------------------------------------------


def test_layer2_points_add_and_are_listed() -> None:
    hist = _history(user_tool_events_points=30, prior_divert_points=20, similarity_points=25)
    out = decide(_gate("strict", 20, history=hist))
    assert out.score == 95 and out.decision == "divert"
    assert (
        out.breakdown["user_history"],
        out.breakdown["prior_divert"],
        out.breakdown["similarity"],
    ) == (30, 20, 25)


def test_layers_that_did_not_run_are_null_never_zero() -> None:
    out = decide(_gate("basic", 10))
    assert out.breakdown["user_history"] is None
    assert out.breakdown["similarity"] is None
    assert out.breakdown["judge"] is None


def test_m2x24_approved_pattern_forces_deny() -> None:
    hist = _history(forced_deny=True, matched_pattern_ids=["P-7"])
    out = decide(_gate("strict", 10, history=hist))
    assert out.decision == "deny" and out.risky_pattern_ids == ("P-7",)


def test_m2x25_history_error_fails_closed() -> None:
    assert decide(_gate("strict", 0, history_error=True)).decision == "deny"


def test_m2x26_judge_error_raises_to_the_deny_band() -> None:
    out = decide(_gate("strict", 10, judge_error=True))
    assert (out.decision, out.score, out.breakdown["judge"]) == ("deny", 60, None)


def test_m2x27_judge_only_at_or_above_twenty() -> None:
    assert JUDGE_FLOOR == 20
    assert (judge_needed(19), judge_needed(20)) == (False, True)


def test_rule_failure_fails_closed() -> None:
    failed = Evaluation((), (RuleFailure("R-001", 1, "bad_regex", "x"),), 0.0)
    assert decide(_gate("basic", 0, rules=failed)).decision == "deny"
    off = decide(_gate("off", 0, rules=failed))
    assert (off.decision, off.shadow_decision) == ("allow", "deny")


# --- Built-ins B-01, B-02, invalid calls --------------------------------------------------------


def test_b01_secret_hit_by_mode() -> None:
    leak = LeakMatch("exact")
    assert decide(_gate("basic", 0, leak=leak)).decision == "deny"
    assert decide(_gate("strict", 0, leak=leak)).decision == "divert"
    off = decide(_gate("off", 0, leak=leak))
    assert (off.decision, off.shadow_decision) == ("allow", "deny")  # "would have denied"
    assert "B-01" in off.rule_ids


def test_b02_forged_approval_denies() -> None:
    out = decide(_gate("strict", 0, layer1=_l1(0, forged=True)))
    assert out.decision == "deny" and "B-02" in out.rule_ids


@pytest.mark.parametrize("mode", ["off", "basic", "strict"])
def test_invalid_tool_call_is_denied_in_every_mode(mode: str) -> None:
    out = decide(_gate(mode, 0, canonical_error=True))
    assert out.decision == "deny"


# --- Modes (E-44) and divert_enabled (M2-DD-01) --------------------------------------------------


def test_e44_off_computes_in_shadow_and_enforces_allow() -> None:
    out = decide(_gate("off", 10, rules=_hits("deny")))
    assert (out.decision, out.shadow_decision) == ("allow", "deny")


def test_off_can_shadow_a_divert() -> None:
    out = decide(_gate("off", 0, rules=_hits("divert")))
    assert (out.decision, out.shadow_decision) == ("allow", "divert")


def test_basic_and_strict_never_set_a_shadow() -> None:
    assert decide(_gate("basic", 80)).shadow_decision is None
    assert decide(_gate("strict", 80)).shadow_decision is None


def test_divert_disabled_degrades_to_deny() -> None:
    out = decide(_gate("basic", 97, divert_enabled=False))
    assert out.decision == "deny"


# --- Feed band and rule ids --------------------------------------------------------------------


def test_score_band_for_the_feed() -> None:
    assert [score_band(s, BASIC) for s in (0, 39, 40, 69, 70, 100)] == [
        "low", "low", "medium", "medium", "high", "high"
    ]  # fmt: skip


def test_rule_ids_list_fired_rules_then_builtins() -> None:
    out = decide(_gate("off", 0, rules=_hits("deny"), leak=LeakMatch("exact")))
    assert out.rule_ids == ("R-001", "B-01")


# --- Properties ----------------------------------------------------------------------------------

ORDER = {"allow": 0, "review": 1, "deny": 2, "divert": 3}


@settings(max_examples=300)
@given(
    score=st.integers(0, 100),
    actions=st.lists(
        st.sampled_from(["score_only", "allow", "review", "deny", "divert"]), max_size=4
    ),
)
def test_property_off_enforces_allow(score: int, actions: list[str]) -> None:
    assert decide(_gate("off", score, rules=_hits(*actions))).decision == "allow"


@settings(max_examples=300)
@given(score=st.integers(0, 100), mode=st.sampled_from(["basic", "strict"]))
def test_property_forcing_signals_never_weaken(score: int, mode: str) -> None:
    base = ORDER[decide(_gate(mode, score)).decision]
    for extra in (
        {"rules": _hits("deny")},
        {"leak": LeakMatch("exact")},
        {"canonical_error": True},
    ):
        assert ORDER[decide(_gate(mode, score, **extra)).decision] >= max(base, ORDER["deny"])


# --- B-08: oversized items (PRD §7.6) -----------------------------------------------------------


@pytest.mark.parametrize("mode", ["basic", "strict"])
def test_oversized_item_is_denied_in_enforcing_modes(mode: str) -> None:
    out = decide(_gate(mode, 0, limit_exceeded=True))
    assert out.decision == "deny" and "LIMIT" not in out.rule_ids


def test_oversized_item_in_off_is_truncated_with_a_shadow_deny() -> None:
    out = decide(_gate("off", 0, limit_exceeded=True))
    assert (out.decision, out.shadow_decision) == ("allow", "deny")
