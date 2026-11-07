"""C5: `require_user()` and `require_role()` (PRD §4.1, §14.6). Every route uses them.

Roles always come from the verified token; `users.role` is only a display cache.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.auth.claims import EMAIL_CLAIM, NAME_CLAIM, primary_role, profile_value, roles_from_claims
from app.auth.verifier import AuthError
from app.contracts.common import ClientMeta, Role
from app.contracts.users import CurrentUser

MAX_SUB_LEN = 255
_BEARER = re.compile(r"Bearer ([A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*)")
_UPSERT = text(
    "INSERT INTO users (auth0_sub, name, email, role) VALUES (:sub, :name, :email, :role)"
    " ON CONFLICT (auth0_sub) DO UPDATE SET"
    " name = COALESCE(EXCLUDED.name, users.name),"
    " email = COALESCE(EXCLUDED.email, users.email),"
    " role = EXCLUDED.role, updated_at = now()"
    " RETURNING id"
)


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_user(request: Request) -> CurrentUser:
    match = _BEARER.fullmatch(request.headers.get("authorization", "").strip())
    if match is None:
        raise _unauthorized("missing or malformed bearer token")
    try:
        claims = await request.app.state.verifier.verify(match.group(1))
    except AuthError as exc:
        raise _unauthorized("invalid token") from exc
    sub = claims.get("sub")
    if not isinstance(sub, str) or not 0 < len(sub) <= MAX_SUB_LEN:
        raise _unauthorized("invalid subject")
    roles = roles_from_claims(claims)
    name, email = profile_value(claims, NAME_CLAIM), profile_value(claims, EMAIL_CLAIM)
    engine: AsyncEngine = request.app.state.engine
    async with engine.begin() as conn:
        result = await conn.execute(
            _UPSERT, {"sub": sub, "name": name, "email": email, "role": primary_role(roles)}
        )
        user_id = str(result.scalar_one())
    return CurrentUser(id=user_id, auth0_sub=sub, name=name, email=email, roles=roles)


def require_role(*allowed: Role) -> Callable[..., Awaitable[CurrentUser]]:
    """Dependency factory: 403 unless the caller holds at least one of `allowed`."""
    wanted = frozenset(allowed)

    async def _dep(user: Annotated[CurrentUser, Depends(require_user)]) -> CurrentUser:
        if not user.roles & wanted:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
        return user

    return _dep


def client_meta(request: Request) -> ClientMeta:
    """ClientMeta built by ProxySecretMiddleware from trusted proxy headers."""
    found = getattr(request.state, "client_meta", None)
    return found if isinstance(found, ClientMeta) else ClientMeta()
