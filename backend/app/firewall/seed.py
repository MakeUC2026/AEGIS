"""Starting-rules seed (M2 B-02; PRD §9.2) and the demo seed hook (M1 D-02, M2 DM1-2).

Writes rule set version 1: the form rules R-001 to R-006 (`starting_rules.py`) and the
built-ins B-01 to B-04, which are code, so they carry no form. Idempotent: existing rows are
left alone (`ON CONFLICT DO NOTHING` never fires the append-only trigger), so a re-run
changes nothing. `scripts/seed_demo.py` and the Compose start-up seed call `seed(engine)`
through `app/demo.py` (`PART_SEEDERS`).
"""

from __future__ import annotations

import json

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.firewall.starting_rules import RULE_SET_VERSION, STARTING_RULES

BUILTIN_RULE_IDS: tuple[str, ...] = ("B-01", "B-02", "B-03", "B-04")
_RULE_VERSION = 1

_INSERT_SET = (
    "INSERT INTO rule_sets (version, note) VALUES (:version, :note)"
    " ON CONFLICT (version) DO NOTHING"
)
_INSERT_RULE = (
    "INSERT INTO rules (rule_id, version, set_version, builtin, enabled, deprecated, form)"
    " VALUES (:rule_id, :version, :set_version, :builtin, true, false, CAST(:form AS jsonb))"
    " ON CONFLICT (rule_id, version) DO NOTHING"
)


async def seed(engine: AsyncEngine) -> None:
    form_rows = [
        {"rule_id": rule_id, "builtin": False, "form": json.dumps(form.model_dump(mode="json"))}
        for rule_id, form in STARTING_RULES
    ]
    builtin_rows = [
        {"rule_id": rule_id, "builtin": True, "form": None} for rule_id in BUILTIN_RULE_IDS
    ]
    async with engine.begin() as conn:
        await conn.execute(
            text(_INSERT_SET), {"version": RULE_SET_VERSION, "note": "starting rules (PRD 9.2)"}
        )
        await conn.execute(
            text(_INSERT_RULE),
            [
                {**row, "version": _RULE_VERSION, "set_version": RULE_SET_VERSION}
                for row in (*form_rows, *builtin_rows)
            ],
        )
