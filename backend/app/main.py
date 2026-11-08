"""FastAPI app factory (M1 A-06). Mounts every part's router; nobody else edits this file.

Routers: identity (M1), arena (M1), admin (M3), classroom (M4), quiz (M4).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncEngine

from app.admin.router import router as admin_router
from app.arena.router import router as arena_router
from app.auth.proxy import ProxySecretMiddleware
from app.auth.router import router as identity_router
from app.auth.verifier import make_verifier
from app.classroom.router import router as classroom_router
from app.config import Settings, get_settings
from app.db.engine import make_engine
from app.llm.budget import DailyBudget
from app.quiz.router import router as quiz_router
from app.security_headers import SECURITY_HEADERS, SecurityHeadersMiddleware

PART_ROUTERS: tuple[APIRouter, ...] = (
    identity_router,
    arena_router,
    admin_router,
    classroom_router,
    quiz_router,
)


def create_app(
    settings: Settings | None = None,
    engine: AsyncEngine | None = None,
    extra_routers: Iterable[APIRouter] = (),
) -> FastAPI:
    cfg = settings or get_settings()
    owns_engine = engine is None
    db = engine or make_engine(cfg.database_url)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        if owns_engine:
            await db.dispose()

    hide_docs = cfg.app_env == "production"
    app = FastAPI(
        title="Injection Arena API",
        lifespan=lifespan,
        docs_url=None if hide_docs else "/docs",
        redoc_url=None,
        openapi_url=None if hide_docs else "/openapi.json",
    )
    app.state.settings = cfg
    app.state.engine = db
    app.state.verifier = make_verifier(cfg)
    app.state.budget = DailyBudget(db, cfg.daily_llm_budget)
    app.add_middleware(ProxySecretMiddleware, secret=cfg.proxy_secret.get_secret_value())
    # Added last, so it is outermost and also stamps ProxySecretMiddleware's 401s.
    app.add_middleware(SecurityHeadersMiddleware)

    @app.exception_handler(Exception)
    async def unhandled(_: Request, __: Exception) -> JSONResponse:
        # Runs in ServerErrorMiddleware, outside every add_middleware entry, so it sets the
        # security headers itself. The body never echoes the exception.
        headers = {k.decode(): v.decode() for k, v in SECURITY_HEADERS}
        return JSONResponse({"detail": "internal error"}, status_code=500, headers=headers)

    for router in (*PART_ROUTERS, *extra_routers):
        app.include_router(router)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


def __getattr__(name: str) -> FastAPI:
    # `uvicorn app.main:app` builds the app lazily, so importing this module in tests
    # never reads production settings.
    if name == "app":
        return create_app()
    raise AttributeError(name)
