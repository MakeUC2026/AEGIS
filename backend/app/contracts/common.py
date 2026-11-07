"""Shared enums and base types for every contract (PRD §10.1, §14).

Frozen at Gate 1. Changes need approval from all four machines (PRD §14.1).
"""

from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict

Mode = Literal["off", "basic", "strict"]
Stage = Literal[
    "input_check",
    "tool_call_check",
    "tool_executed",
    "output_check",
    "review_resolved",
    "finalize",
]
Decision = Literal["allow", "deny", "review", "human_deny", "divert"]
ExecutionStatus = Literal["not_executed", "executed", "held", "diverted"]
TicketStatus = Literal["pending", "approved", "human_denied", "expired"]
ScoreBand = Literal["low", "medium", "high"]
Role = Literal["student", "teacher", "firewall_admin"]

ROLES: frozenset[str] = frozenset({"student", "teacher", "firewall_admin"})

# Timezone-aware timestamps only; naive datetimes are rejected at the boundary.
UtcDatetime = AwareDatetime


class Contract(BaseModel):
    """Base for every contract model: immutable, no unknown fields."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class ClientMeta(Contract):
    """Network data from the arena request, used only when a turn is diverted (PRD §8.5)."""

    ip: str | None = None
    user_agent: str | None = None
    fingerprint_hash: str | None = None
