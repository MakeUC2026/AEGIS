"""Model access for the quiz: one JSON client plus the Pro and Flash model ids (PRD §3.2).

Routes get a `QuizRuntime` from `get_runtime`. Tests set `app.state.quiz_runtime` to a
`ScriptedLLM` runtime; otherwise a `GeminiClient` is built once from settings, charged to the
global `DailyBudget` (PRD §15.1), and cached on `app.state`.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException, Request

from app.config import Settings
from app.llm.base import JsonModel
from app.llm.budget import DailyBudget
from app.llm.gemini import GeminiClient


@dataclass(frozen=True)
class QuizRuntime:
    llm: JsonModel
    pro_model: str  # generator and grader
    flash_model: str  # classmate and feedback writer


def build_runtime(settings: Settings, engine) -> QuizRuntime:  # type: ignore[no-untyped-def]
    key = settings.gemini_api_key.get_secret_value()
    if not (key and settings.gemini_pro_model_id and settings.gemini_flash_model_id):
        raise HTTPException(status_code=503, detail="quiz models are not configured")
    client = GeminiClient(
        api_key=key,
        budget=DailyBudget(engine, settings.daily_llm_budget),
        embedding_model=settings.gemini_embedding_model_id,
    )
    return QuizRuntime(
        llm=client,
        pro_model=settings.gemini_pro_model_id,
        flash_model=settings.gemini_flash_model_id,
    )


def get_runtime(request: Request) -> QuizRuntime:
    state = request.app.state
    runtime = getattr(state, "quiz_runtime", None)
    if runtime is None:
        runtime = build_runtime(state.settings, state.engine)
        state.quiz_runtime = runtime
    return runtime  # type: ignore[no-any-return]
