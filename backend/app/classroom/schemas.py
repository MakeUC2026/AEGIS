"""Classroom API models (PRD 12). Responses are separate from the C3/C4 contracts so a new
contract field can never reach the browser by accident."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.contracts.common import Mode

QuizStatus = Literal["not_taken", "assigned", "in_progress", "done"]
Outcome = Literal["obtained", "not_obtained"]
YesNo = Literal["yes", "no"]

MAX_PAGE = 1000


class SessionQuery(BaseModel):
    """Query string of GET /sessions. Unknown values are a 422; unknown keys are ignored."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    student: str | None = Field(default=None, max_length=64)
    level: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    mode: Mode | None = None
    outcome: Outcome | None = None
    diverted: YesNo | None = None
    quiz_status: QuizStatus | None = None
    admin_test: bool | None = None
    limit: int = Field(default=200, ge=1, le=MAX_PAGE)
    offset: int = Field(default=0, ge=0)


class SessionRow(BaseModel):
    id: str
    student_id: str
    student_name: str | None
    level_id: str
    level_name: str | None
    mode: Mode
    status: Literal["active", "closed"]
    admin_test: bool
    secret_obtained: bool
    secret_obtained_at: str | None
    diverted_count: int
    max_sentinel_score: int | None
    started_at: str
    quiz_status: QuizStatus
    quiz_score: int | None
    quiz_best: int | None
    quiz_attempts: int


class SessionList(BaseModel):
    items: list[SessionRow]
    total: int


class OutcomeBlock(BaseModel):
    obtained: bool
    obtained_at: datetime | None
    duration_s: int | None
    echo_excluded: bool


class TranscriptRow(BaseModel):
    message_id: str
    time: datetime
    speaker: Literal["student", "bot", "tool"]
    text: str
    status: str | None
    is_decoy: bool


class DecisionRow(BaseModel):
    event_id: str
    time: datetime
    message_id: str
    stage: str
    decision: str
    shadow_decision: str | None
    execution_status: str
    sentinel_score: int
    score_breakdown: dict[str, int | None]
    thresholds_used: dict[str, int]
    rule_ids: list[str]
    risky_pattern_ids: list[str]


class ConfigBlock(BaseModel):
    level_id: str
    level_version: int
    mode: Mode
    rule_version: int
    pattern_version: int
    thresholds: dict[str, int]
    weights: dict[str, int]
    bot_model_id: str
    judge_model_id: str | None


class HeldRow(BaseModel):
    ticket_id: str
    stage: str
    status: Literal["pending", "approved", "human_denied", "expired"]
    created_at: datetime
    decided_at: datetime | None
    decided_by_name: str | None


class DivertRow(BaseModel):
    event_id: str
    time: datetime
    stage: str
    tool: str | None
    attempted_summary: str
    decoy_shown: str


class ForensicRow(BaseModel):
    event_id: str
    attack_family: str
    atlas_techniques: list[str]
    summary: str
    missed_signals: list[str]
    would_have_blocked_in: list[Mode]


class SessionDetail(BaseModel):
    """`view="student"` carries only the owner's own transcript and outcome; the staff-only
    blocks are null so a student cannot read the answers before the quiz (PRD 6.2, 13)."""

    view: Literal["staff", "student"]
    session: SessionRow
    outcome: OutcomeBlock
    transcript: list[TranscriptRow]
    decisions: list[DecisionRow] | None
    config: ConfigBlock | None
    held_items: list[HeldRow] | None
    diverts: list[DivertRow] | None
    forensics: list[ForensicRow] | None


class InsightQuery(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    level: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    mode: Mode | None = None
    include_admin_test: bool = False


class Overview(BaseModel):
    students: int
    sessions: int
    sessions_per_student: float
    active_today: int  # students with a session started in the last 24 hours


class LevelOutcome(BaseModel):
    level_id: str
    level_name: str
    sessions: int
    obtained: int
    not_obtained: int
    rate: float


class RuleCountRow(BaseModel):
    rule_id: str
    count: int


class DecisionCountRow(BaseModel):
    mode: Mode
    decision: str
    count: int


class DefenseActivity(BaseModel):
    top_rules: list[RuleCountRow]
    decisions: list[DecisionCountRow]
    divert_count: int


class FamilyRow(BaseModel):
    attack_family: str
    count: int


class PatternRow(BaseModel):
    pattern_id: str
    count: int


class ItemAverage(BaseModel):
    item: str
    title: str
    average: float
    n: int


class QuizPanel(BaseModel):
    taken: int  # sessions whose latest attempt is done
    open: int  # sessions whose latest attempt is assigned, in progress or awaiting regrade
    average_percent: int | None
    lowest_items: list[ItemAverage]


class Insights(BaseModel):
    overview: Overview
    outcomes: list[LevelOutcome]
    defense: DefenseActivity
    attack_families: list[FamilyRow]
    risky_patterns: list[PatternRow]
    quiz: QuizPanel


class SecretRow(BaseModel):
    """Status only. `SecretStatus` carries no secret value and neither does this."""

    level_id: str
    level_name: str | None
    secret_version: int
    compromised: bool
    compromised_by_id: str | None
    compromised_by_name: str | None
    compromised_by_session: str | None
    compromised_at: datetime | None
    created_at: datetime


class SecretList(BaseModel):
    items: list[SecretRow]
