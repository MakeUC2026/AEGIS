"""Quiz routes (PRD §13). Gate 0 placeholder created by M1; owned by M4 from here on.

Every route uses `require_user` / `require_role`. Other parts are read through C3/C4
(`app.firewall.ports`), resolved inside the handler so `ports.override(...)` works in tests.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy.ext.asyncio import AsyncEngine

from app.auth.deps import require_role, require_user
from app.classroom.access import get_engine
from app.contracts.users import CurrentUser
from app.firewall.ports import get_arena_service, get_firewall_read
from app.llm.base import BudgetExhausted, LLMError
from app.quiz import service
from app.quiz.errors import QuizError
from app.quiz.generator import QuizGenerationFailed
from app.quiz.llm import QuizRuntime, get_runtime
from app.quiz.schemas import AssignOut, AttemptList, MineList, QuizView, StartIn
from app.quiz.service import QuizDeps

router = APIRouter(prefix="/api/quiz", tags=["quiz"])

Engine = Annotated[AsyncEngine, Depends(get_engine)]
Runtime = Annotated[QuizRuntime, Depends(get_runtime)]
Caller = Annotated[CurrentUser, Depends(require_user)]
Teacher = Annotated[CurrentUser, Depends(require_role("teacher"))]
PathId = Annotated[str, Path(max_length=64, pattern=r"^[A-Za-z0-9_-]+$")]

BUDGET_MESSAGE = (
    "The daily model budget is used up, so quizzes cannot be made right now. Try again tomorrow."
)
GENERATION_MESSAGE = "We could not make a valid quiz this time. Please try again."
MODEL_MESSAGE = "The quiz model did not answer. Please try again."


def _deps(engine: AsyncEngine, runtime: QuizRuntime) -> QuizDeps:
    return QuizDeps(
        engine=engine, arena=get_arena_service(), read=get_firewall_read(), runtime=runtime
    )


def _http(exc: Exception) -> HTTPException:
    if isinstance(exc, QuizError):
        return HTTPException(status_code=exc.status_code, detail=exc.detail)
    if isinstance(exc, BudgetExhausted):
        return HTTPException(status_code=429, detail=BUDGET_MESSAGE)
    if isinstance(exc, QuizGenerationFailed):
        return HTTPException(status_code=502, detail=GENERATION_MESSAGE)
    return HTTPException(status_code=502, detail=MODEL_MESSAGE)


_HANDLED = (QuizError, BudgetExhausted, QuizGenerationFailed, LLMError)


@router.post("/quizzes")
async def start_quiz(body: StartIn, user: Caller, engine: Engine, runtime: Runtime) -> QuizView:
    try:
        return await service.start_quiz(_deps(engine, runtime), user, body.session_id)
    except _HANDLED as exc:
        raise _http(exc) from None


@router.post("/assign")
async def assign_quiz(body: StartIn, user: Teacher, engine: Engine, runtime: Runtime) -> AssignOut:
    try:
        return await service.assign_quiz(_deps(engine, runtime), body.session_id, user)
    except _HANDLED as exc:
        raise _http(exc) from None


@router.get("/quizzes/{quiz_id}")
async def get_quiz(quiz_id: PathId, user: Caller, engine: Engine, runtime: Runtime) -> QuizView:
    try:
        return await service.get_quiz_view(_deps(engine, runtime), user, quiz_id)
    except _HANDLED as exc:
        raise _http(exc) from None


@router.get("/mine")
async def mine(user: Caller, engine: Engine, runtime: Runtime) -> MineList:
    return await service.mine_view(_deps(engine, runtime), user)


@router.get("/sessions/{session_id}/attempts")
async def attempts(
    session_id: PathId, user: Caller, engine: Engine, runtime: Runtime
) -> AttemptList:
    try:
        return await service.attempts_view(_deps(engine, runtime), user, session_id)
    except _HANDLED as exc:
        raise _http(exc) from None


__all__: list[Any] = ["router"]
