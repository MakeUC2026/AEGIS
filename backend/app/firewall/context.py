"""Turn context loader (M2 B-08; spec AEGIS-DOM-112).

Everything one turn needs, read once: the manifest (thresholds, weights, tools, prompt,
model), the session secret, the rule set the session pinned, the bot's model history
(blocked turns excluded, M2-DD-30), what the student has already seen (for the cumulative
scan and the delivery fact), the student's own inputs (echo exclusion), earlier denies and
recent message times (layer-1 signals).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.contracts.common import Mode
from app.contracts.firewall import NotFound, ToolDef
from app.contracts.firewall_admin import RuleDef, RuleForm
from app.llm.base import ChatMessage, ToolCall

_SESSION = (
    "SELECT s.owner_ref, s.mode, s.secret, m.manifest_id, m.level_id, m.thresholds, m.weights,"
    " m.agent, m.bot_model_id, m.rule_set_version, m.divert_enabled"
    " FROM fw_sessions s JOIN fw_manifests m ON m.fw_session_id = s.fw_session_id"
    " WHERE s.fw_session_id = :sid"
)
_RULES = (
    "SELECT DISTINCT ON (rule_id) rule_id, version, builtin, enabled, deprecated, form,"
    " created_at, created_by FROM rules WHERE set_version <= :v"
    " ORDER BY rule_id, version DESC"
)
_CONVERSATION = (
    "SELECT seq, role, content, visible, call_id, model_payload, created_at"
    " FROM fw_conversation WHERE fw_session_id = :sid"
    " AND message_id IS DISTINCT FROM CAST(:exclude AS text) ORDER BY seq"
)
_DENIES = (
    "SELECT count(*) FROM fw_events WHERE fw_session_id = :sid"
    " AND (decision IN ('deny', 'human_deny') OR shadow_decision IN ('deny', 'human_deny'))"
)


@dataclass(frozen=True)
class TurnContext:
    fw_session_id: str
    owner_ref: str
    manifest_id: str
    level_id: str
    mode: Mode
    secret: str
    thresholds: Mapping[str, int]
    weights: Mapping[str, int]
    divert_enabled: bool
    tools: tuple[ToolDef, ...]
    system_prompt: str
    bot_model_id: str
    rules: tuple[RuleDef, ...]
    history: tuple[ChatMessage, ...]
    visible_output: tuple[str, ...]
    student_inputs: tuple[str, ...]
    student_times: tuple[datetime, ...]
    earlier_denies: int
    next_seq: int


def _json(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


def _rule(row: Mapping[str, Any]) -> RuleDef:
    form = _json(row["form"])
    return RuleDef(
        rule_id=row["rule_id"],
        version=row["version"],
        builtin=row["builtin"],
        enabled=row["enabled"],
        deprecated=row["deprecated"],
        form=RuleForm(**form) if form else None,
        created_at=row["created_at"],
        created_by=str(row["created_by"]) if row["created_by"] else None,
    )


async def rules_at(conn: AsyncConnection, set_version: int) -> list[RuleDef]:
    """Each rule's newest version at or below `set_version` (deprecated ones included)."""
    rows = (await conn.execute(text(_RULES), {"v": set_version})).mappings()
    return [_rule(r) for r in rows]


def _history_message(row: Mapping[str, Any], payload: Mapping[str, Any]) -> ChatMessage | None:
    role = row["role"]
    if role == "student":
        return ChatMessage(role="user", content=row["content"])
    if role == "bot":
        return ChatMessage(role="assistant", content=row["content"])
    if role == "tool_call":
        calls = [ToolCall(**tc) for tc in payload.get("tool_calls", [])]
        return ChatMessage(role="assistant", content=row["content"] or None, tool_calls=calls)
    if role == "tool_result":
        return ChatMessage(role="tool", content=row["content"], tool_call_id=row["call_id"])
    return None


async def _conversation(conn: AsyncConnection, sid: str, exclude: str | None) -> dict[str, Any]:
    history: list[ChatMessage] = []
    visible: list[str] = []
    inputs: list[str] = []
    times: list[datetime] = []
    last_seq = 0
    for row in (
        await conn.execute(text(_CONVERSATION), {"sid": sid, "exclude": exclude})
    ).mappings():
        payload = _json(row["model_payload"]) or {}
        last_seq = row["seq"]
        if row["role"] == "student":
            inputs.append(row["content"])
            times.append(row["created_at"])
        if row["visible"]:
            visible.append(payload.get("visible") or row["content"])
        message = _history_message(row, payload) if payload.get("in_history", True) else None
        if message is not None:
            history.append(message)
    return {
        "history": tuple(history),
        "visible_output": tuple(visible),
        "student_inputs": tuple(inputs),
        "student_times": tuple(times),
        "next_seq": last_seq + 1,
    }


async def load_context(
    engine: AsyncEngine, fw_session_id: str, exclude_message: str | None = None
) -> TurnContext:
    """`exclude_message`: a parked turn being continued (C-02) reads the session without its
    own parked rows, which its continuation carries instead."""
    async with engine.connect() as conn:
        row = (await conn.execute(text(_SESSION), {"sid": fw_session_id})).mappings().first()
        if row is None:
            raise NotFound("session not found")
        rules = await rules_at(conn, row["rule_set_version"])
        conversation = await _conversation(conn, fw_session_id, exclude_message)
        denies = (await conn.execute(text(_DENIES), {"sid": fw_session_id})).scalar_one()
    agent = _json(row["agent"])
    return TurnContext(
        fw_session_id=fw_session_id,
        owner_ref=str(row["owner_ref"]),
        manifest_id=row["manifest_id"],
        level_id=row["level_id"],
        mode=row["mode"],
        secret=row["secret"],
        thresholds=_json(row["thresholds"]),
        weights=_json(row["weights"]),
        divert_enabled=row["divert_enabled"],
        tools=tuple(ToolDef(**t) for t in agent["tools"]),
        system_prompt=agent["system_prompt"],
        bot_model_id=row["bot_model_id"],
        rules=tuple(r for r in rules if not r.deprecated),
        earlier_denies=int(denies),
        **conversation,
    )
