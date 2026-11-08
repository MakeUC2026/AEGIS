"""Building the arena's `TurnResult` (M2 B-08; PRD §6.2, §9.4, I-3; spec AEGIS-DOM-112).

`player_view` is the only part the browser sees: status, reply (the neutral refusal when
blocked), tool effects (attacker mail is the visible one) and one feed line per checked item.
A divert is reported as `allow` in the feed (PRD §6.2); Off adds the shadow decision. Judge
reasons, tool arguments and blocked text never appear here. `facts` is for game logic only.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.contracts.common import Decision
from app.contracts.firewall import (
    NEUTRAL_REFUSAL,
    PENDING_REVIEW_MESSAGE,
    Facts,
    FeedItem,
    PlayerStatus,
    PlayerView,
    ToolEffect,
    TurnResult,
)
from app.firewall.checks import Checked

_FIXED_REPLY: dict[str, str] = {
    "blocked": NEUTRAL_REFUSAL,
    "awaiting_review": PENDING_REVIEW_MESSAGE,  # the held reply is never shown before approval
}
_FACT_DECISION: dict[str, Decision] = {"blocked": "deny", "awaiting_review": "review"}


def feed_item(checked: Checked) -> FeedItem:
    gate = checked.gate
    decision = "allow" if gate.decision == "divert" else gate.decision
    return FeedItem(
        stage=checked.stage,
        decision=decision,
        rule_ids=list(gate.rule_ids),
        score_band=gate.score_band,
        # Off: only a shadow that differs from what happened is worth a "would have" line.
        shadow_decision=gate.shadow_decision if gate.shadow_decision != "allow" else None,
    )


def turn_result(
    status: PlayerStatus,
    reply: str | None,
    effects: Sequence[ToolEffect],
    checks: Sequence[Checked],
    secret_delivered: bool,
    ticket_id: str | None = None,
) -> TurnResult:
    rule_ids = list(dict.fromkeys(r for c in checks for r in c.gate.rule_ids))
    view = PlayerView(
        status=status,
        reply=_FIXED_REPLY.get(status, reply),
        tool_effects=list(effects),
        ticket_id=ticket_id,
        defense_feed=[feed_item(c) for c in checks],
    )
    facts = Facts(
        decision=_FACT_DECISION.get(status, "allow"),
        rule_ids=rule_ids,
        secret_attempted=any(c.leak is not None for c in checks if c.stage != "input_check"),
        secret_delivered=secret_delivered,
        diverted=False,
    )
    return TurnResult(player_view=view, facts=facts)


def expired_result() -> TurnResult:
    """A held item whose review expired (or whose session closed): it counts as Deny."""
    return TurnResult(
        player_view=PlayerView(
            status="blocked",
            reply=NEUTRAL_REFUSAL,
            tool_effects=[],
            ticket_id=None,
            defense_feed=[
                FeedItem(stage="review_resolved", decision="deny", rule_ids=[], score_band="high")
            ],
        ),
        facts=Facts(
            decision="deny",
            rule_ids=[],
            secret_attempted=False,
            secret_delivered=False,
            diverted=False,
        ),
    )
