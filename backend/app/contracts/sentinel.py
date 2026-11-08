"""C7: Sentinel plug-ins (new seam, M1 §3.1). Provider M3, consumer M2's Sentinel.

`record_behavior` and `add_candidate` receive M2's open connection so they join
the Deny / Human Deny / Divert transaction (PRD §15.1). They make no network calls.
"""

from __future__ import annotations

from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import Field

from app.contracts.common import Contract, Mode, Stage, UtcDatetime


class CheckedItem(Contract):
    event_id: str
    stage: Stage
    mode: Mode
    user_id: str
    fw_session_id: str
    manifest_id: str
    pattern_version: int
    tool: str | None
    canonical_args: dict[str, Any] | None
    args_hash: str | None
    text: str  # normalized text under check
    layer1_score: int
    context_excerpt: str  # delimited, untrusted, for the judge


class RiskyHistorySignals(Contract):
    forced_deny: bool
    matched_pattern_ids: list[str]
    user_tool_events_points: int = Field(ge=0, le=30)
    prior_divert_points: Literal[0, 20]
    similarity_points: Literal[0, 10, 25]
    similarity_top: float | None
    latency_ms: int


class RiskyBehaviorRecord(Contract):
    time: UtcDatetime
    user_id: str
    fw_session_id: str
    event_id: str
    stage: Stage
    tool: str | None
    args_hash: str | None
    action: Literal["deny", "human_deny", "divert"]
    sentinel_score: int
    rule_ids: list[str]
    input_text: str
    trace_id: str | None
    shadow: bool


class PatternCandidate(Contract):
    tool: str
    canonical_args: dict[str, Any]
    source_event_id: str
    user_id: str


class JudgeVerdict(Contract):
    risk: int = Field(ge=0, le=100)
    suggested_action: Literal["allow", "review", "deny", "divert"]
    reason: str


class RiskyHistoryError(Exception):
    """Lookup failed (DB or embedding). M2 fails closed to Deny."""


class JudgeError(Exception):
    """Unparseable or schema-invalid judge answer."""


class JudgeTimeout(JudgeError):
    """Judge took longer than 8 s (PRD §7.3)."""


@runtime_checkable
class RiskyHistoryPort(Protocol):
    async def lookup(self, item: CheckedItem) -> RiskyHistorySignals: ...

    async def record_behavior(self, record: RiskyBehaviorRecord, conn: Any) -> None: ...

    async def add_candidate(self, candidate: PatternCandidate, conn: Any) -> None: ...

    async def current_pattern_version(self) -> int: ...


@runtime_checkable
class JudgePort(Protocol):
    async def assess(self, item: CheckedItem) -> JudgeVerdict: ...

    def policy_hash(self) -> str: ...

    def model_id(self) -> str: ...
