"""Classroom routes. Gate 0 placeholder created by M1; owned by M4 from here on (§0.2 rule 4).
Read other parts only through C3 and C4 (`app.firewall.ports`), resolved inside the handler so
`ports.override(...)` works in tests."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy.ext.asyncio import AsyncEngine

from app.auth.deps import require_user
from app.classroom.access import get_engine
from app.classroom.detail import SessionForbidden, SessionNotFound, session_detail_view
from app.classroom.schemas import SessionDetail, SessionList, SessionQuery
from app.classroom.sessions import list_sessions_view
from app.contracts.users import CurrentUser
from app.firewall.ports import get_arena_service, get_firewall_read

router = APIRouter(prefix="/api/classroom", tags=["classroom"])

Engine = Annotated[AsyncEngine, Depends(get_engine)]
Caller = Annotated[CurrentUser, Depends(require_user)]


@router.get("/sessions")
async def list_sessions(
    user: Caller, query: Annotated[SessionQuery, Query()], engine: Engine
) -> SessionList:
    return await list_sessions_view(
        user, query, engine=engine, arena=get_arena_service(), read=get_firewall_read()
    )


SessionId = Annotated[str, Path(max_length=64, pattern=r"^[A-Za-z0-9_-]+$")]


@router.get("/sessions/{session_id}")
async def session_detail(session_id: SessionId, user: Caller, engine: Engine) -> SessionDetail:
    try:
        return await session_detail_view(
            user, session_id, engine=engine, arena=get_arena_service(), read=get_firewall_read()
        )
    except SessionNotFound:
        raise HTTPException(status_code=404, detail="session not found") from None
    except SessionForbidden:
        raise HTTPException(status_code=403, detail="forbidden") from None
