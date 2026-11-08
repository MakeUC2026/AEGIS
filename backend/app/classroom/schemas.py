"""Classroom API models (PRD 12). Responses are separate from the C3/C4 contracts so a new
contract field can never reach the browser by accident."""

from __future__ import annotations

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
