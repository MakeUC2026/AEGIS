"""Shared audit log writer (M1 §0.1 note 1, PRD §11, §12.4).

Takes the caller's open connection so the audit row commits or rolls back with the
change it describes (PRD §15.1 Atomicity). Secret values are never audited.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

FORBIDDEN_KEYS: frozenset[str] = frozenset({"value", "secret", "secret_value"})

_INSERT = text(
    "INSERT INTO audit_log (actor_id, entity, entity_id, action, before, after)"
    " VALUES (:actor_id, :entity, :entity_id, :action,"
    " CAST(:before AS jsonb), CAST(:after AS jsonb)) RETURNING id"
)


def _check(payload: dict[str, Any] | None) -> str | None:
    if payload is None:
        return None
    leaked = FORBIDDEN_KEYS & set(payload)
    if leaked:
        raise ValueError(f"audit payload must not contain a secret value: {sorted(leaked)}")
    return json.dumps(payload, default=str)


async def record_audit(
    conn: AsyncConnection,
    *,
    actor_id: str | None,
    entity: str,
    entity_id: str,
    action: str,
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
) -> int:
    result = await conn.execute(
        _INSERT,
        {
            "actor_id": actor_id,
            "entity": entity,
            "entity_id": entity_id,
            "action": action,
            "before": _check(before),
            "after": _check(after),
        },
    )
    return int(result.scalar_one())
