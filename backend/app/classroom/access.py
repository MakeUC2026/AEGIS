"""Role helper for the classroom routes (PRD 4.2, M4-X01, X02). Routes still use
`require_user` / `require_role`; this decides what a caller may see inside a route."""

from __future__ import annotations

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncEngine

from app.contracts.users import CurrentUser


def is_staff(user: CurrentUser) -> bool:
    """Teachers and firewall admins see every session. A student-only caller does not."""
    return user.has("teacher") or user.has("firewall_admin")


def session_scope_user_id(user: CurrentUser, requested: str | None) -> str | None:
    """Student filter, fixed on the server: students always get themselves (M4-X01)."""
    return requested if is_staff(user) else user.id


def can_view_session(user: CurrentUser, owner_id: str) -> bool:
    return is_staff(user) or user.id == owner_id


def get_engine(request: Request) -> AsyncEngine:
    engine: AsyncEngine = request.app.state.engine
    return engine
