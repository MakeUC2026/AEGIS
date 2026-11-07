"""Identity route: `/api/me` (PRD §4.3 step 4: first API call upserts the user)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.auth.deps import require_user
from app.contracts.users import CurrentUser

router = APIRouter(prefix="/api", tags=["identity"])


class MeResponse(BaseModel):
    id: str
    name: str | None
    email: str | None
    roles: list[str]


@router.get("/me")
async def me(user: Annotated[CurrentUser, Depends(require_user)]) -> MeResponse:
    return MeResponse(id=user.id, name=user.name, email=user.email, roles=sorted(user.roles))
