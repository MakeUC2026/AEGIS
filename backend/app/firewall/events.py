"""Event writer (M2 B-03; PRD §10.1, §10.2; spec AEGIS-DOM-107).

One `fw_events` row per check per stage, in every mode. Rules:
- `shadow_decision` is set only in Off (also a database CHECK);
- a layer that did not run stays `null` in `score_breakdown`, never 0;
- `forensic_status` is `pending` when the decision or the shadow decision is deny,
  human_deny or divert, or when an Off allow delivered the secret (PRD §10.2); otherwise null.

`insert_event` writes on the caller's connection, so the row commits or rolls back with the
rest of the turn (PRD §15.1). The `fw_events_forensic` NOTIFY comes from a trigger and is
delivered only when that transaction commits.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from app.contracts.common import Decision, ExecutionStatus, Mode, Stage
from app.firewall.gatekeeper import GateDecision

SourceTrust = Literal["player", "tool_result", "bot_output"]
FORENSIC_DECISIONS = frozenset({"deny", "human_deny", "divert"})
EVENT_ID_PREFIX = "evt-"

_INSERT = (
    "INSERT INTO fw_events (event_id, time, trace_id, fw_session_id, user_id, message_id,"
    " manifest_id, level_id, mode, stage, source_trust, tool, call_id, args_hash,"
    " sentinel_score, score_breakdown, thresholds_used, rule_ids_fired,"
    " risky_pattern_ids_matched, judge_risk, judge_reason, shadow_decision, decision,"
    " execution_status, ticket_id, secret_attempted, secret_delivered, diverted, trace_back_id,"
    " atlas_techniques, latency_ms, forensic_status, client_ip_hash, priority_alert)"
    " VALUES (:event_id, :time, :trace_id, :fw_session_id, CAST(:user_id AS uuid), :message_id,"
    " :manifest_id, :level_id, :mode, :stage, :source_trust, :tool, :call_id, :args_hash,"
    " :sentinel_score, CAST(:score_breakdown AS jsonb), CAST(:thresholds_used AS jsonb),"
    " :rule_ids, :risky_pattern_ids, :judge_risk, :judge_reason, :shadow_decision, :decision,"
    " :execution_status, :ticket_id, :secret_attempted, :secret_delivered, :diverted,"
    " :trace_back_id, :atlas_techniques, CAST(:latency_ms AS jsonb), :forensic_status,"
    " :client_ip_hash, :priority_alert)"
)


def new_event_id() -> str:
    return EVENT_ID_PREFIX + uuid.uuid4().hex


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class EventRow:
    fw_session_id: str
    user_id: str
    message_id: str
    manifest_id: str
    level_id: str
    mode: Mode
    stage: Stage
    source_trust: SourceTrust
    decision: Decision
    execution_status: ExecutionStatus
    sentinel_score: int
    score_breakdown: Mapping[str, int | None]
    thresholds_used: Mapping[str, int]
    shadow_decision: Decision | None = None
    rule_ids: tuple[str, ...] = ()
    risky_pattern_ids: tuple[str, ...] = ()
    tool: str | None = None
    call_id: str | None = None
    args_hash: str | None = None
    judge_risk: int | None = None
    judge_reason: str | None = None
    ticket_id: str | None = None
    secret_attempted: bool = False
    secret_delivered: bool = False
    diverted: bool = False
    trace_id: str | None = None
    trace_back_id: str | None = None
    atlas_techniques: tuple[str, ...] = ()
    latency_ms: Mapping[str, int] = field(default_factory=dict)
    client_ip_hash: str | None = None
    priority_alert: bool = False
    event_id: str = field(default_factory=new_event_id)
    time: datetime = field(default_factory=_utcnow)

    def __post_init__(self) -> None:
        if self.shadow_decision is not None and self.mode != "off":
            raise ValueError("shadow_decision is set only in Off mode")


def forensic_status_for(row: EventRow) -> str | None:
    flagged = row.decision in FORENSIC_DECISIONS or row.shadow_decision in FORENSIC_DECISIONS
    off_leak = row.mode == "off" and row.secret_delivered
    return "pending" if flagged or off_leak else None


def row_from_decision(
    gate: GateDecision, thresholds: Mapping[str, int], **context: Any
) -> EventRow:
    """An event row for one Gatekeeper decision; `context` supplies the item's identity."""
    return EventRow(
        decision=gate.decision,
        shadow_decision=gate.shadow_decision,
        sentinel_score=gate.score,
        score_breakdown=dict(gate.breakdown),
        thresholds_used=dict(thresholds),
        rule_ids=gate.rule_ids,
        risky_pattern_ids=gate.risky_pattern_ids,
        judge_risk=gate.breakdown.get("judge"),
        priority_alert=gate.priority_alert,
        diverted=gate.decision == "divert",
        **context,
    )


async def insert_event(conn: AsyncConnection, row: EventRow) -> str:
    await conn.execute(
        text(_INSERT),
        {
            "event_id": row.event_id,
            "time": row.time,
            "trace_id": row.trace_id,
            "fw_session_id": row.fw_session_id,
            "user_id": row.user_id,
            "message_id": row.message_id,
            "manifest_id": row.manifest_id,
            "level_id": row.level_id,
            "mode": row.mode,
            "stage": row.stage,
            "source_trust": row.source_trust,
            "tool": row.tool,
            "call_id": row.call_id,
            "args_hash": row.args_hash,
            "sentinel_score": row.sentinel_score,
            "score_breakdown": json.dumps(dict(row.score_breakdown)),
            "thresholds_used": json.dumps(dict(row.thresholds_used)),
            "rule_ids": list(row.rule_ids),
            "risky_pattern_ids": list(row.risky_pattern_ids),
            "judge_risk": row.judge_risk,
            "judge_reason": row.judge_reason,
            "shadow_decision": row.shadow_decision,
            "decision": row.decision,
            "execution_status": row.execution_status,
            "ticket_id": row.ticket_id,
            "secret_attempted": row.secret_attempted,
            "secret_delivered": row.secret_delivered,
            "diverted": row.diverted,
            "trace_back_id": row.trace_back_id,
            "atlas_techniques": list(row.atlas_techniques),
            "latency_ms": json.dumps(dict(row.latency_ms)),
            "forensic_status": forensic_status_for(row),
            "client_ip_hash": row.client_ip_hash,
            "priority_alert": row.priority_alert,
        },
    )
    return row.event_id
