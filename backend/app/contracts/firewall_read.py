"""C3: AFF read functions for Classroom and the arena recap (PRD §14.4 plus M1 §3.1).

Provider: M2 (`app/firewall/read_api.py`); `get_forensics` and
`get_attack_family_counts` by M3 (`app/firewall/forensics_read.py`).
Server-side only. No judge reasons, tool arguments, blocked text or trace-back
fields ever appear here, and every text field comes back with the secret
replaced by `[SECRET]`.
"""

from __future__ import annotations

from typing import Literal, Protocol, runtime_checkable

from app.contracts.common import (
    Contract,
    Decision,
    ExecutionStatus,
    Mode,
    Stage,
    TicketStatus,
    UtcDatetime,
)

SECRET_PLACEHOLDER = "[SECRET]"  # noqa: S105 - redaction marker, not a credential


class TranscriptItem(Contract):
    message_id: str
    time: UtcDatetime
    speaker: Literal["student", "bot", "tool"]
    text: str  # what the student saw, secret redacted
    status: Literal["replied", "blocked", "awaiting_review", "human_denied"] | None = None
    is_decoy: bool = False


class DecisionItem(Contract):
    event_id: str
    time: UtcDatetime
    message_id: str
    stage: Stage
    decision: Decision
    shadow_decision: Decision | None
    execution_status: ExecutionStatus
    sentinel_score: int
    score_breakdown: dict[str, int | None]  # a layer that did not run is None, never 0
    thresholds_used: dict[str, int]
    rule_ids: list[str]
    risky_pattern_ids: list[str]


class TicketItem(Contract):
    ticket_id: str
    stage: Stage
    status: TicketStatus
    created_at: UtcDatetime
    decided_at: UtcDatetime | None
    decided_by: str | None  # users.id of the firewall admin


class DivertItem(Contract):
    """What the student attempted and what they believed they got. No network data."""

    event_id: str
    time: UtcDatetime
    stage: Stage
    tool: str | None
    attempted_summary: str
    decoy_shown: str


class ForensicItem(Contract):
    event_id: str
    attack_family: str
    atlas_techniques: list[str]
    summary: str
    missed_signals: list[str]
    would_have_blocked_in: list[Mode]


class InsightFilters(Contract):
    level_id: str | None = None
    mode: Mode | None = None
    since: UtcDatetime | None = None
    until: UtcDatetime | None = None
    include_admin_test: bool = True


class RuleCount(Contract):
    rule_id: str
    count: int


class PatternCount(Contract):
    pattern_id: str
    count: int


class DecisionCount(Contract):
    mode: Mode
    decision: Decision
    count: int


class FamilyCount(Contract):
    attack_family: str
    count: int


class SessionSummary(Contract):
    fw_session_id: str
    diverted_count: int
    max_sentinel_score: int | None
    secret_delivered_at: UtcDatetime | None
    echo_excluded: bool


class ManifestSummary(Contract):
    manifest_id: str
    level_id: str
    level_version: int
    mode: Mode
    rule_version: int
    pattern_version: int
    thresholds: dict[str, int]
    weights: dict[str, int]
    bot_model_id: str
    judge_model_id: str | None
    judge_policy_hash: str | None


@runtime_checkable
class FirewallReadPort(Protocol):
    async def get_transcript(self, fw_session_id: str) -> list[TranscriptItem]: ...

    async def get_decisions(self, fw_session_id: str) -> list[DecisionItem]: ...

    async def get_tickets(self, fw_session_id: str) -> list[TicketItem]: ...

    async def get_diverts(self, fw_session_id: str) -> list[DivertItem]: ...

    async def get_forensics(self, fw_session_id: str) -> list[ForensicItem]: ...

    async def get_rule_fire_counts(self, filters: InsightFilters) -> list[RuleCount]: ...

    async def get_risky_pattern_counts(self, filters: InsightFilters) -> list[PatternCount]: ...

    async def get_decision_counts(self, filters: InsightFilters) -> list[DecisionCount]: ...

    async def get_attack_family_counts(self, filters: InsightFilters) -> list[FamilyCount]: ...

    async def get_session_summaries(self, fw_session_ids: list[str]) -> list[SessionSummary]: ...

    async def get_manifest_summary(self, fw_session_id: str) -> ManifestSummary: ...

    async def redact_for_session(self, fw_session_id: str, text: str) -> str: ...
