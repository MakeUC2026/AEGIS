"""Builders for well-formed `TurnResult`s used by fakes and tests."""

from __future__ import annotations

from app.contracts.common import Decision, ScoreBand, Stage
from app.contracts.firewall import (
    HUMAN_DENIED_MESSAGE,
    NEUTRAL_REFUSAL,
    PENDING_REVIEW_MESSAGE,
    Facts,
    FeedDecision,
    FeedItem,
    PlayerStatus,
    PlayerView,
    ToolEffect,
    TurnResult,
)

FAKE_REPLY = "(fake firewall) Done."

_DEFAULT_REPLY: dict[str, str] = {
    "replied": FAKE_REPLY,
    "blocked": NEUTRAL_REFUSAL,
    "awaiting_review": PENDING_REVIEW_MESSAGE,
    "human_denied": HUMAN_DENIED_MESSAGE,
}
_DEFAULT_DECISION: dict[str, Decision] = {
    "replied": "allow",
    "blocked": "deny",
    "awaiting_review": "review",
    "human_denied": "human_deny",
}
_DEFAULT_BAND: dict[str, ScoreBand] = {
    "replied": "low",
    "blocked": "high",
    "awaiting_review": "medium",
    "human_denied": "medium",
}


def _feed_decision(decision: Decision) -> FeedDecision:
    # The defense feed never reveals a divert (PRD §6.2): it reads as allow.
    return "allow" if decision == "divert" else decision


def fake_turn(
    *,
    status: PlayerStatus = "replied",
    reply: str | None = None,
    rule_ids: list[str] | None = None,
    tool_effects: list[ToolEffect] | None = None,
    stage: Stage = "input_check",
    decision: Decision | None = None,
    shadow_decision: FeedDecision | None = None,
    score_band: ScoreBand | None = None,
    ticket_id: str | None = None,
    secret_attempted: bool = False,
    secret_delivered: bool = False,
    diverted: bool = False,
) -> TurnResult:
    """Build a consistent TurnResult. `diverted=True` makes it look like `replied` + allow."""
    resolved: Decision = decision or ("divert" if diverted else _DEFAULT_DECISION[status])
    rules = list(rule_ids or [])
    feed_shadow = shadow_decision if shadow_decision in {"allow", "deny", "review"} else None
    feed = FeedItem(
        stage=stage,
        decision=_feed_decision(resolved),
        rule_ids=rules,
        score_band=score_band or _DEFAULT_BAND[status],
        shadow_decision=feed_shadow,  # type: ignore[arg-type]
    )
    view = PlayerView(
        status=status,
        reply=_DEFAULT_REPLY[status] if reply is None else reply,
        tool_effects=list(tool_effects or []),
        ticket_id=ticket_id,
        defense_feed=[feed],
    )
    facts = Facts(
        decision=resolved,
        rule_ids=rules,
        secret_attempted=secret_attempted or secret_delivered,
        secret_delivered=secret_delivered,
        diverted=diverted,
    )
    return TurnResult(player_view=view, facts=facts)


def with_ticket(result: TurnResult, ticket_id: str) -> TurnResult:
    """Return a copy of a held result carrying the ticket id (no mutation)."""
    view = result.player_view.model_copy(update={"ticket_id": ticket_id})
    return result.model_copy(update={"player_view": view})
