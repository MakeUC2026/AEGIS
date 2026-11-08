"""In-memory C7 fakes: risky history and judge."""

from __future__ import annotations

from collections import deque
from typing import Any

from app.contracts.sentinel import (
    CheckedItem,
    JudgeVerdict,
    PatternCandidate,
    RiskyBehaviorRecord,
    RiskyHistorySignals,
)

ZERO_SIGNALS = RiskyHistorySignals(
    forced_deny=False,
    matched_pattern_ids=[],
    user_tool_events_points=0,
    prior_divert_points=0,
    similarity_points=0,
    similarity_top=None,
    latency_ms=0,
)


class InMemoryRiskyHistory:
    def __init__(self, signals: list[RiskyHistorySignals | Exception] | None = None) -> None:
        self._signals: deque[RiskyHistorySignals | Exception] = deque(signals or [])
        self.records: list[RiskyBehaviorRecord] = []
        self.candidates: list[PatternCandidate] = []
        self.lookups: list[CheckedItem] = []
        self.pattern_version = 0

    async def lookup(self, item: CheckedItem) -> RiskyHistorySignals:
        self.lookups.append(item)
        if not self._signals:
            return ZERO_SIGNALS
        nxt = self._signals.popleft()
        if isinstance(nxt, Exception):
            raise nxt
        return nxt

    async def record_behavior(self, record: RiskyBehaviorRecord, conn: Any) -> None:
        self.records.append(record)

    async def add_candidate(self, candidate: PatternCandidate, conn: Any) -> None:
        self.candidates.append(candidate)

    async def current_pattern_version(self) -> int:
        return self.pattern_version


class StubJudge:
    """Scripted judge: pops a risk (or raises a scripted error) per call."""

    def __init__(
        self, risks: list[int] | None = None, errors: list[Exception] | None = None
    ) -> None:
        self._risks: deque[int] = deque(risks or [])
        self._errors: deque[Exception] = deque(errors or [])
        self.assessed: list[CheckedItem] = []

    async def assess(self, item: CheckedItem) -> JudgeVerdict:
        self.assessed.append(item)
        if self._errors:
            raise self._errors.popleft()
        risk = self._risks.popleft() if self._risks else 0
        return JudgeVerdict(
            risk=risk, suggested_action="allow" if risk < 30 else "deny", reason="stub"
        )

    def policy_hash(self) -> str:
        return "sha256:stub"

    def model_id(self) -> str:
        return "stub-judge"
