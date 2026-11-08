"""Classroom routes. Gate 0 placeholder created by M1; owned by M4 from here on (§0.2 rule 4).
Read other parts only through C3 and C4 (`app.firewall.ports`), resolved inside the handler so
`ports.override(...)` works in tests."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy.ext.asyncio import AsyncEngine

from app.auth.deps import require_role, require_user
from app.classroom.access import get_engine
from app.classroom.detail import SessionForbidden, SessionNotFound, session_detail_view
from app.classroom.insights import insights_view
from app.classroom.schemas import (
    InsightQuery,
    Insights,
    SecretList,
    SecretRow,
    SessionDetail,
    SessionList,
    SessionQuery,
)
from app.classroom.secrets import rotate_view, secrets_view
from app.classroom.sessions import list_sessions_view
from app.contracts.firewall import NotFound
from app.contracts.users import CurrentUser
from app.firewall.ports import get_arena_service, get_firewall_read

router = APIRouter(
    prefix="/api/classroom", tags=["classroom"]
)

Engine = Annotated[AsyncEngine, Depends(get_engine)]
Caller = Annotated[CurrentUser, Depends(require_user)]
Staff = Annotated[CurrentUser, Depends(require_role("teacher", "firewall_admin"))]
Teacher = Annotated[CurrentUser, Depends(require_role("teacher"))]


@router.get("/sessions")
async def list_sessions(
    user: Caller, query: Annotated[SessionQuery, Query()], engine: Engine
) -> SessionList:
    return await list_sessions_view(
        user, query, engine=engine, arena=get_arena_service(), read=get_firewall_read()
    )


PathId = Annotated[str, Path(max_length=64, pattern=r"^[A-Za-z0-9_-]+$")]


@router.get("/sessions/{session_id}")
async def session_detail(session_id: PathId, user: Caller, engine: Engine) -> SessionDetail:
    try:
        return await session_detail_view(
            user, session_id, engine=engine, arena=get_arena_service(), read=get_firewall_read()
        )
    except SessionNotFound:
        raise HTTPException(status_code=404, detail="session not found") from None
    except SessionForbidden:
        raise HTTPException(status_code=403, detail="forbidden") from None


@router.get("/insights")
async def insights(_: Staff, query: Annotated[InsightQuery, Query()], engine: Engine) -> Insights:
    return await insights_view(
        query, engine=engine, arena=get_arena_service(), read=get_firewall_read()
    )


@router.get("/secrets")
async def secrets(_: Staff, engine: Engine) -> SecretList:
    return await secrets_view(engine=engine, arena=get_arena_service())


@router.post("/secrets/{level_id}/rotate")
async def rotate_secret(level_id: PathId, user: Staff, engine: Engine) -> SecretRow:
    try:
        return await rotate_view(level_id, user, engine=engine, arena=get_arena_service())
    except NotFound:
        raise HTTPException(status_code=404, detail="level not found") from None
