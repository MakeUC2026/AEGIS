"""C4 (arena read) and C8 (arena admin and teacher operations) (PRD §14.5, M1 §3.1).

Provider: M1 (`app/arena/service.py`). Consumers: M3 (Levels screen), M4 (classroom, quiz).
Every C8 write is recorded in `audit_log`.
"""

from __future__ import annotations

from typing import Literal, Protocol, runtime_checkable

from pydantic import Field, model_validator

from app.contracts.common import Contract, Mode, UtcDatetime

THRESHOLD_KEYS: frozenset[str] = frozenset({"review", "deny", "divert", "alert"})
SCORE_MAX = 100
REVIEW_TIMEOUT_MIN_S = 10
REVIEW_TIMEOUT_MAX_S = 3600


def validate_thresholds(thresholds: dict[str, int]) -> dict[str, int]:
    """PRD §7.4 bands must be ordered: review < deny < divert <= alert <= 100."""
    if set(thresholds) != THRESHOLD_KEYS:
        raise ValueError(f"thresholds must have exactly {sorted(THRESHOLD_KEYS)}")
    review, deny, divert, alert = (thresholds[k] for k in ("review", "deny", "divert", "alert"))
    if not (0 < review < deny < divert <= alert <= SCORE_MAX):
        raise ValueError("thresholds must satisfy 0 < review < deny < divert <= alert <= 100")
    return thresholds


def validate_weights(weights: dict[str, int]) -> dict[str, int]:
    bad = [k for k, v in weights.items() if not 0 <= v <= SCORE_MAX]
    if bad:
        raise ValueError(f"weights out of range 0..100: {sorted(bad)}")
    return weights


class ArenaSession(Contract):
    id: str
    user_id: str
    level_id: str
    level_version: int
    mode: Mode
    fw_session_id: str
    manifest_id: str
    secret_version: int
    status: Literal["active", "closed"]
    secret_obtained_at: UtcDatetime | None
    started_at: UtcDatetime
    closed_at: UtcDatetime | None
    admin_test: bool
    recap_unlocked_at: UtcDatetime | None


class SessionFilters(Contract):
    user_id: str | None = None  # forced to the caller for students
    level_id: str | None = None
    mode: Mode | None = None
    outcome: Literal["obtained", "not_obtained"] | None = None
    status: Literal["active", "closed"] | None = None
    admin_test: bool | None = None
    limit: int = Field(default=200, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class LevelSummary(Contract):
    level_id: str
    level_version: int
    number: int
    name: str
    mode: Mode
    secret_tier: str
    rule_version: int
    weights: dict[str, int]
    thresholds: dict[str, int]
    review_timeout_s: int
    divert_enabled: bool
    created_at: UtcDatetime


class LevelConfigUpdate(Contract):
    """A Levels-screen edit. Omitted fields keep the current value. Saves a new version."""

    level_id: str
    mode: Mode | None = None
    rule_version: int | None = Field(default=None, ge=0)
    weights: dict[str, int] | None = None
    thresholds: dict[str, int] | None = None
    review_timeout_s: int | None = Field(
        default=None, ge=REVIEW_TIMEOUT_MIN_S, le=REVIEW_TIMEOUT_MAX_S
    )
    divert_enabled: bool | None = None

    @model_validator(mode="after")
    def _check(self) -> LevelConfigUpdate:
        if self.thresholds is not None:
            validate_thresholds(self.thresholds)
        if self.weights is not None:
            validate_weights(self.weights)
        return self


class SecretStatus(Contract):
    level_id: str
    secret_version: int
    compromised: bool
    compromised_by_user: str | None
    compromised_by_session: str | None
    compromised_at: UtcDatetime | None
    created_at: UtcDatetime


@runtime_checkable
class ArenaServicePort(Protocol):
    # C4
    async def list_sessions(self, filters: SessionFilters) -> list[ArenaSession]: ...

    async def get_session(self, session_id: str) -> ArenaSession | None: ...

    async def list_levels(self) -> list[LevelSummary]: ...

    # C8
    async def save_level_version(self, update: LevelConfigUpdate, actor: str) -> LevelSummary: ...

    async def rotate_secret(self, level_id: str, actor: str) -> SecretStatus: ...

    async def get_secret_status(self) -> list[SecretStatus]: ...

    async def unlock_recap(self, session_id: str) -> None: ...
