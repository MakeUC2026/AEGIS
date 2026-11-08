"""Firewall admin console API (M3 C-10, PRD §11). Gate 0 placeholder by M1; owned by M3 (§0.2
rule 4).

Every route sits behind `require_role("firewall_admin")` on the server (I-4): 401 without a
token, 403 for students and teachers (M3-X38, E-55). Tickets, rules, events, diverts and
trace-back go through C6 (M2), levels through C8 (M1); those providers write their own audit
rows. Drafts and risky patterns are M3's and are audited in `decisions.py` (M3-X40).
"""

from __future__ import annotations

import re
from collections.abc import Awaitable
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.admin import decisions
from app.auth.deps import require_role
from app.contracts.arena import (
    REVIEW_TIMEOUT_MAX_S,
    REVIEW_TIMEOUT_MIN_S,
    LevelConfigUpdate,
    LevelSummary,
    validate_thresholds,
)
from app.contracts.common import Decision, Mode
from app.contracts.firewall import NotFound
from app.contracts.firewall_admin import (
    OPERATORS_BY_CHECK,
    RULE_WEIGHT_MAX,
    RULE_WEIGHT_MIN,
    ConflictError,
    DivertAdminItem,
    EventFilter,
    EventRow,
    RuleDef,
    RuleForm,
    TicketDecision,
    TicketQueueItem,
    TraceBack,
)
from app.contracts.fixtures import AttackFamily
from app.contracts.users import CurrentUser
from app.firewall import ports
from app.firewall.risky_patterns import Condition
from app.workers.drafts import Benign, load_benign

MAX_BODY_BYTES = 64 * 1024
MAX_CONDITIONS = 20
MAX_WEIGHTS = 50
LIST_MAX = 500

Admin = Annotated[CurrentUser, Depends(require_role("firewall_admin"))]


async def _body_limit(request: Request) -> None:
    """Oversized bodies are refused with 413 (DAST)."""
    declared = request.headers.get("content-length", "")
    too_big = declared.isdigit() and int(declared) > MAX_BODY_BYTES
    if too_big or len(await request.body()) > MAX_BODY_BYTES:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "request body too large")


router = APIRouter(
    prefix="/api/admin",
    tags=["admin"],
    dependencies=[Depends(require_role("firewall_admin")), Depends(_body_limit)],
)


def get_benign() -> Benign:
    """Benign fixtures, read fresh for each validation (tests override this dependency)."""
    return load_benign()


def _engine(request: Request) -> AsyncEngine:
    engine: AsyncEngine = request.app.state.engine
    return engine


BenignDep = Annotated[Benign, Depends(get_benign)]
EngineDep = Annotated[AsyncEngine, Depends(_engine)]


async def _run[T](awaitable: Awaitable[T], *, refusals: bool = True) -> T:
    """Typed provider and decision errors become HTTP errors; nothing else is swallowed.
    `refusals=False` lets a route see the provider's `ConflictError` itself (ticket decisions)."""
    try:
        return await awaitable
    except (decisions.Missing, NotFound) as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found") from exc
    except decisions.Conflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except ConflictError as exc:
        if not refusals:
            raise
        raise HTTPException(
            status.HTTP_409_CONFLICT, str(exc)
        ) from exc  # a refusal, with its reason
    except decisions.Invalid as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, {"reasons": exc.reasons}
        ) from exc


class _Body(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class TicketDecisionBody(_Body):
    decision: TicketDecision


class EnabledBody(_Body):
    enabled: bool


WeightKey = Annotated[str, StringConstraints(min_length=1, max_length=64)]
Weight = Annotated[int, Field(ge=RULE_WEIGHT_MIN, le=RULE_WEIGHT_MAX)]


class LevelEdit(_Body):
    """A Levels-screen save (M3-X35). Weights 5-60 here; M1's contract still allows 0-100."""

    mode: Mode | None = None
    rule_version: int | None = Field(default=None, ge=0)
    weights: dict[WeightKey, Weight] | None = Field(default=None, max_length=MAX_WEIGHTS)
    thresholds: dict[str, int] | None = None
    review_timeout_s: int | None = Field(
        default=None, ge=REVIEW_TIMEOUT_MIN_S, le=REVIEW_TIMEOUT_MAX_S
    )
    divert_enabled: bool | None = None

    @field_validator("thresholds")
    @classmethod
    def _ordered(cls, value: dict[str, int] | None) -> dict[str, int] | None:
        return None if value is None else validate_thresholds(value)


class DraftEdit(_Body):
    body: dict[str, Any]


class PatternEdit(_Body):
    conditions: list[Condition] = Field(max_length=MAX_CONDITIONS)


class Reasons(_Body):
    reasons: list[str]


# --- review queue (E-46, M3-X34) --------------------------------------------------------------


@router.get("/tickets")
async def list_tickets(response: Response) -> list[TicketQueueItem]:
    """Priority alerts (99+) first, then the soonest expiry. `x-server-time` is the server clock
    the countdown corrects for skew (plan §10)."""
    tickets = await ports.get_firewall_admin().list_pending_tickets()
    response.headers["x-server-time"] = datetime.now(UTC).isoformat()
    return sorted(tickets, key=lambda t: (not t.priority_alert, t.expires_at))


# M3 may read `fw_tickets` (§0.2 rule 2): it tells "expired" from "already decided" for the UI.
_TICKET_STATE = text(
    "SELECT status = 'expired' OR (status = 'pending' AND expires_at <= now()) AS expired"
    " FROM fw_tickets WHERE ticket_id = :t"
)
_CONFLICT_MESSAGE = {
    "expired": "This ticket expired before it was decided; it counts as Deny.",
    "already_decided": "This ticket was already decided by another admin.",
}


async def _conflict_reason(engine: AsyncEngine, ticket_id: str) -> str:
    async with engine.connect() as conn:
        expired = (await conn.execute(_TICKET_STATE, {"t": ticket_id})).scalar_one_or_none()
    return "expired" if expired else "already_decided"


@router.post("/tickets/{ticket_id}/decision")
async def decide_ticket(
    ticket_id: str, body: TicketDecisionBody, user: Admin, engine: EngineDep
) -> dict[str, str]:
    try:
        await _run(
            ports.get_firewall_admin().decide_ticket(ticket_id, body.decision, user.id),
            refusals=False,
        )
    except ConflictError as exc:  # already decided or expired (409, E-46, M3-X34)
        reason = await _conflict_reason(engine, ticket_id)
        detail = {"reason": reason, "message": _CONFLICT_MESSAGE[reason]}
        raise HTTPException(status.HTTP_409_CONFLICT, detail) from exc
    return {"ticket_id": ticket_id, "decision": body.decision}


# --- rules (M3-X36, X37): RuleForm checks operators against the field type -----------------


@router.get("/rules")
async def list_rules() -> list[RuleDef]:
    return await ports.get_firewall_admin().list_rules()


@router.get("/rules/operators")
async def rule_operators() -> dict[str, Any]:
    """The client-side operator table for the Rules form (M3-X36); the API still re-checks."""
    return {
        "operators_by_check": {k: sorted(v) for k, v in OPERATORS_BY_CHECK.items()},
        "weight_min": RULE_WEIGHT_MIN,
        "weight_max": RULE_WEIGHT_MAX,
    }


_RULE_ID = re.compile(r"(R-[0-9]{3}|B-[0-9]{2})")
_RULE_HISTORY = text(
    "SELECT rule_id, version, set_version, builtin, enabled, deprecated, form, created_at,"
    " created_by::text AS created_by FROM rules WHERE rule_id = :r ORDER BY version DESC"
)


@router.get("/rules/{rule_id}/history")
async def rule_history(rule_id: str, engine: EngineDep) -> list[dict[str, Any]]:
    """Every stored version of one rule, newest first, deprecations included (M3-X37). Reads
    M2's append-only `rules` table directly (§0.2 rule 2)."""
    if not _RULE_ID.fullmatch(rule_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    async with engine.connect() as conn:
        rows = [dict(r) for r in (await conn.execute(_RULE_HISTORY, {"r": rule_id})).mappings()]
    if not rows:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    return rows


@router.post("/rules", status_code=status.HTTP_201_CREATED)
async def create_rule(form: RuleForm, user: Admin) -> RuleDef:
    return await _run(ports.get_firewall_admin().create_rule(form, user.id))


@router.put("/rules/{rule_id}")
async def update_rule(rule_id: str, form: RuleForm, user: Admin) -> RuleDef:
    return await _run(ports.get_firewall_admin().update_rule(rule_id, form, user.id))


@router.post("/rules/{rule_id}/deprecate")
async def deprecate_rule(rule_id: str, user: Admin) -> RuleDef:
    """Deprecation keeps the rule and its history; there is no delete route (M3-X37)."""
    return await _run(ports.get_firewall_admin().deprecate_rule(rule_id, user.id))


@router.post("/rules/{rule_id}/enabled")
async def set_rule_enabled(rule_id: str, body: EnabledBody, user: Admin) -> RuleDef:
    """Switch any rule on or off (built-ins and form rules alike)."""
    admin = ports.get_firewall_admin()
    return await _run(admin.set_rule_enabled(rule_id, body.enabled, user.id))


@router.post("/rules/{rule_id}/restore")
async def restore_rule(rule_id: str, user: Admin) -> RuleDef:
    """Undo a deprecation (the console's soft delete). History is untouched."""
    return await _run(ports.get_firewall_admin().restore_rule(rule_id, user.id))


# --- levels (C8, M3-X35) ----------------------------------------------------------------------


@router.get("/levels")
async def list_levels() -> list[LevelSummary]:
    return await ports.get_arena_service().list_levels()


@router.post("/levels/{level_id}/versions", status_code=status.HTTP_201_CREATED)
async def save_level(level_id: str, edit: LevelEdit, user: Admin) -> LevelSummary:
    update = LevelConfigUpdate(level_id=level_id, **edit.model_dump(exclude_none=True))
    return await _run(ports.get_arena_service().save_level_version(update, user.id))


# --- drafts (C-06) ----------------------------------------------------------------------------

DraftStatus = Literal["pending", "failed_validation", "approved", "rejected"]


@router.get("/drafts")
async def list_drafts(
    engine: EngineDep, draft_status: Annotated[DraftStatus, Query(alias="status")] = "pending"
) -> list[dict[str, Any]]:
    return await decisions.list_drafts(engine, draft_status)


@router.get("/drafts/{draft_id}")
async def get_draft(draft_id: str, engine: EngineDep) -> dict[str, Any]:
    return await _run(decisions.get_draft(engine, draft_id))


@router.patch("/drafts/{draft_id}")
async def edit_draft(
    draft_id: str, edit: DraftEdit, user: Admin, engine: EngineDep, benign: BenignDep
) -> dict[str, Any]:
    return await _run(decisions.edit_draft(engine, draft_id, edit.body, user.id, benign))


@router.post("/drafts/{draft_id}/approve")
async def approve_draft(
    draft_id: str, user: Admin, engine: EngineDep, benign: BenignDep
) -> dict[str, Any]:
    admin = ports.get_firewall_admin()
    return await _run(decisions.approve_draft(engine, draft_id, user.id, benign, admin))


@router.post("/drafts/{draft_id}/reject")
async def reject_draft(draft_id: str, user: Admin, engine: EngineDep) -> dict[str, Any]:
    return await _run(decisions.reject_draft(engine, draft_id, user.id))


# --- risky patterns (C-07; E-39, E-40, E-41, M3-X12) ------------------------------------------

PatternStatus = Literal["candidate", "approved", "rejected", "retired"]


@router.get("/patterns")
async def list_patterns(
    engine: EngineDep,
    pattern_status: Annotated[PatternStatus | None, Query(alias="status")] = None,
) -> list[dict[str, Any]]:
    return await decisions.list_patterns(engine, pattern_status)


@router.patch("/patterns/{pattern_id}")
async def edit_pattern(
    pattern_id: str, edit: PatternEdit, user: Admin, engine: EngineDep
) -> dict[str, Any]:
    conditions = [c.model_dump() for c in edit.conditions]
    return await _run(decisions.edit_pattern(engine, pattern_id, conditions, user.id))


@router.post("/patterns/{pattern_id}/check")
async def check_pattern(pattern_id: str, engine: EngineDep, benign: BenignDep) -> Reasons:
    return Reasons(reasons=await _run(decisions.check_pattern(engine, pattern_id, benign)))


@router.post("/patterns/{pattern_id}/approve")
async def approve_pattern(
    pattern_id: str, user: Admin, engine: EngineDep, benign: BenignDep
) -> dict[str, Any]:
    return await _run(decisions.approve_pattern(engine, pattern_id, user.id, benign))


@router.post("/patterns/{pattern_id}/reject")
async def reject_pattern(pattern_id: str, user: Admin, engine: EngineDep) -> dict[str, Any]:
    return await _run(decisions.reject_pattern(engine, pattern_id, user.id))


@router.post("/patterns/{pattern_id}/retire")
async def retire_pattern(pattern_id: str, user: Admin, engine: EngineDep) -> dict[str, Any]:
    return await _run(decisions.retire_pattern(engine, pattern_id, user.id))


# --- events, diverts and trace-back (C6; E-55) ------------------------------------------------


@router.get("/events")
async def list_events(filters: Annotated[EventFilter, Query()]) -> list[EventRow]:
    return await ports.get_firewall_admin().list_events(filters)


@router.get("/diverts")
async def list_diverts(filters: Annotated[EventFilter, Query()]) -> list[DivertAdminItem]:
    return await ports.get_firewall_admin().list_diverts_admin(filters)


@router.get("/trace-back/{trace_id}")
async def get_trace_back(trace_id: str) -> TraceBack:
    return await _run(ports.get_firewall_admin().get_trace_back(trace_id))


# --- forensics and audit log (P1 screens) -----------------------------------------------------

_FORENSICS = text(
    "SELECT event_id, fw_session_id, mode, level_id, stage, decision, status, attack_family,"
    " atlas_techniques, summary, missed_signals, would_have_blocked_in, failure_reason,"
    " model_id, event_time, created_at FROM forensic_reports"
    " WHERE (CAST(:family AS text) IS NULL OR attack_family = CAST(:family AS text))"
    " AND (CAST(:mode AS text) IS NULL OR mode = CAST(:mode AS text))"
    " AND (CAST(:decision AS text) IS NULL OR decision = CAST(:decision AS text))"
    " ORDER BY created_at DESC LIMIT :limit"
)
_AUDIT = text(
    "SELECT a.id, a.time, a.actor_id::text AS actor_id, u.name AS actor_name, a.entity,"
    " a.entity_id, a.action, a.before, a.after FROM audit_log a"
    " LEFT JOIN users u ON u.id = a.actor_id"
    " WHERE CAST(:entity AS text) IS NULL OR a.entity = CAST(:entity AS text)"
    " ORDER BY a.id DESC LIMIT :limit"
)


@router.get("/forensics")
async def list_forensics(
    engine: EngineDep,
    attack_family: AttackFamily | None = None,
    mode: Mode | None = None,
    decision: Decision | None = None,
    limit: Annotated[int, Query(ge=1, le=LIST_MAX)] = 100,
) -> list[dict[str, Any]]:
    params = {"family": attack_family, "mode": mode, "decision": decision, "limit": limit}
    async with engine.connect() as conn:
        return [dict(r) for r in (await conn.execute(_FORENSICS, params)).mappings()]


@router.get("/audit")
async def list_audit(
    engine: EngineDep,
    entity: Annotated[str | None, Query(max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=LIST_MAX)] = 100,
) -> list[dict[str, Any]]:
    """The Audit screen reads M1's `audit_log` directly (plan §0.1 note 1: M3 owns the screen)."""
    async with engine.connect() as conn:
        rows = (await conn.execute(_AUDIT, {"entity": entity, "limit": limit})).mappings()
        return [dict(r) for r in rows]
