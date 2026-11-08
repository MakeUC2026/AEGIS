"""Arena HTTP routes (M1 B-05..B-13; spec AEGIS-API-001). Students and firewall admins
(admin test sessions) may play; teachers may not (PRD §4.2)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from app.arena.play import ArenaError, ArenaPlay
from app.auth.deps import client_meta, require_role
from app.contracts.users import CurrentUser
from app.firewall import ports

router = APIRouter(prefix="/api/arena", tags=["arena"])
Player = Annotated[CurrentUser, Depends(require_role("student", "firewall_admin"))]

MESSAGE_ID_PATTERN = r"^[A-Za-z0-9_-]{1,64}$"
MAX_TICKET_ID_CHARS = 128
MAX_TEXT_CHARS = 16000  # transport bound only; the arena never truncates (M1-X23)


class StartIn(BaseModel):
    level_id: str = Field(pattern=r"^lvl-[0-9]{1,3}$")


class MessageIn(BaseModel):
    message_id: str = Field(pattern=MESSAGE_ID_PATTERN)
    text: str = Field(min_length=1, max_length=MAX_TEXT_CHARS)

    @field_validator("text")
    @classmethod
    def _no_nul(cls, v: str) -> str:
        # Postgres text cannot store NUL; refuse (422) rather than alter the text (M1-X23).
        if "\x00" in v:
            raise ValueError("text must not contain NUL characters")
        return v


def get_play(request: Request) -> ArenaPlay:
    state = request.app.state
    return ArenaPlay(
        state.engine, ports.get_firewall(), ports.get_firewall_read(), state.settings, state.budget
    )


Play = Annotated[ArenaPlay, Depends(get_play)]


async def _run(coro: Any) -> Any:
    try:
        return await coro
    except ArenaError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.detail) from exc


@router.get("/levels")
async def levels(user: Player, play: Play) -> dict:
    return await _run(play.levels_view(user))


@router.post("/sessions", status_code=201)
async def start(body: StartIn, user: Player, play: Play) -> dict:
    return await _run(play.start(user, body.level_id))


@router.get("/sessions")
async def my_sessions(user: Player, play: Play) -> list[dict]:
    return await _run(play.my_sessions(user))


@router.get("/sessions/{session_id}")
async def detail(session_id: str, user: Player, play: Play) -> dict:
    return await _run(play.detail(user, _uuid(session_id)))


@router.post("/sessions/{session_id}/messages")
async def send(
    session_id: str, body: MessageIn, request: Request, user: Player, play: Play
) -> dict:
    return await _run(
        play.send(user, _uuid(session_id), body.message_id, body.text, client_meta(request))
    )


@router.get("/sessions/{session_id}/tickets/{ticket_id}")
async def ticket(session_id: str, ticket_id: str, user: Player, play: Play) -> dict:
    if "\x00" in ticket_id or len(ticket_id) > MAX_TICKET_ID_CHARS:
        raise HTTPException(status_code=404, detail="ticket not found")
    return await _run(play.check_ticket(user, _uuid(session_id), ticket_id))


@router.post("/sessions/{session_id}/close")
async def close(session_id: str, user: Player, play: Play) -> dict:
    return await _run(play.close(user, _uuid(session_id)))


@router.get("/sessions/{session_id}/recap")
async def recap(session_id: str, user: Player, play: Play) -> dict:
    return await _run(play.recap(user, _uuid(session_id)))


def _uuid(value: str) -> str:
    import uuid

    try:
        return str(uuid.UUID(value))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="session not found") from exc
