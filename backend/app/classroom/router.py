"""Classroom routes. Gate 0 placeholder created by M1; owned by M4 from here on (§0.2 rule 4).
Read other parts only through C3 and C4 (`app.firewall.ports`), resolved inside the handler so
`ports.override(...)` works in tests."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncEngine

from app.auth.deps import require_user
from app.classroom.access import get_engine
from app.classroom.schemas import SessionList, SessionQuery
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
