"""Rule catalog for the arena's level picker (M2 B-10; PRD §6.1; spec AEGIS-DOM-114).

The latest rule set: active form rules (R-…) first, then the built-ins B-01 to B-04, in the
same order and with the same `applies_on` and action labels as M1's fake catalog, so the
arena's rule list does not change when the real seam replaces the fake. Deprecated and
disabled rules are left out.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.contracts.firewall import Catalog, RuleSummary
from app.contracts.firewall_admin import RuleDef
from app.firewall.context import rules_at

BUILTIN_SUMMARIES: Mapping[str, tuple[str, str, str]] = MappingProxyType(
    {
        "B-01": ("bot_reply", "deny_or_divert", "Secret scan"),
        "B-02": ("bot_tool_call", "deny", "Forged approval"),
        "B-03": ("bot_tool_call", "builtin", "Workspace path resolution"),
        "B-04": ("bot_reply", "fact", "Echo exclusion"),
    }
)
ACTION_LABELS: Mapping[str, str] = MappingProxyType({"score_only": "score"})

_LATEST_SET = "SELECT max(version) FROM rule_sets"


def _summary(rule: RuleDef) -> RuleSummary | None:
    if rule.form is not None:
        form = rule.form
        action = ACTION_LABELS.get(form.action, form.action)
        return RuleSummary(
            rule_id=rule.rule_id, applies_on=form.applies_on, action=action, note=form.note
        )
    builtin = BUILTIN_SUMMARIES.get(rule.rule_id)
    if builtin is None:
        return None
    applies_on, action, note = builtin
    return RuleSummary(rule_id=rule.rule_id, applies_on=applies_on, action=action, note=note)


def _order(rule_id: str) -> tuple[bool, str]:
    return (not rule_id.startswith("R-"), rule_id)


async def read_catalog(engine: AsyncEngine) -> Catalog:
    async with engine.connect() as conn:
        latest = (await conn.execute(text(_LATEST_SET))).scalar_one()
        rules = await rules_at(conn, int(latest)) if latest is not None else []
    active = [r for r in rules if r.enabled and not r.deprecated]
    summaries = [s for s in (_summary(r) for r in active) if s is not None]
    return Catalog(
        rules=sorted(summaries, key=lambda s: _order(s.rule_id)),
        tools=[],
        rule_version=int(latest or 0),
    )
