"""C2: the real Agent Firewall behind M1's arena (M2 B-11, DM1-3; PRD §14.3).

`RealFirewall` implements `FirewallPort` by delegating to the B-phase modules. `create()` is
the factory M1's `ports.py` calls (`app.firewall.interface:create`) when `firewall` is not in
AEGIS_USE_FAKES: it wires the shared database engine, the Gemini bot client (with M1's daily
budget) and whichever C7 ports are active (fakes until M3's real ones land).

Without a Gemini key the firewall still starts; every turn then fails as `BotUnavailable`
and the arena shows "not sent" (M2-DD-34). `check_ticket` is the arena's poll for a held
turn (C-04, `tickets.py`).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine

from app.config import Settings, get_settings
from app.contracts.common import ClientMeta
from app.contracts.firewall import (
    Catalog,
    FirewallPort,
    RegisterSession,
    SessionHandle,
    TicketResult,
    TurnResult,
)
from app.contracts.sentinel import JudgePort, RiskyHistoryPort
from app.db.engine import make_engine
from app.firewall.catalog import read_catalog
from app.firewall.closing import close_session
from app.firewall.decoy_gemini import GeminiDecoys
from app.firewall.decoys import DecoyGenerator
from app.firewall.pipeline import run_message
from app.firewall.sessions import register_session
from app.firewall.tickets import check_ticket
from app.firewall.trace_back import Tracer
from app.llm.base import ChatMessage, ChatModel, ChatResult, JsonModel, LLMError
from app.llm.budget import DailyBudget
from app.llm.gemini import GeminiClient


class _MissingModel:
    """Stands in for the bot model when no key is configured: fails every call cleanly."""

    async def chat_with_tools(
        self,
        model: str,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]],
        timeout_s: float = 30.0,
    ) -> ChatResult:
        raise LLMError("GEMINI_API_KEY is not set; the arena bot is unavailable")


class RealFirewall:
    def __init__(
        self,
        engine: AsyncEngine,
        llm: ChatModel,
        risky: RiskyHistoryPort,
        judge: JudgePort,
        decoys: DecoyGenerator | None = None,
        tracer: Tracer | None = None,
    ) -> None:
        self._engine = engine
        self._llm = llm
        self._risky = risky
        self._judge = judge
        self._decoys = decoys
        self._tracer = tracer

    async def read_catalog(self) -> Catalog:
        return await read_catalog(self._engine)

    async def register_session(self, req: RegisterSession) -> SessionHandle:
        return await register_session(self._engine, req, self._risky, self._judge)

    async def send_message(
        self,
        owner_ref: str,
        fw_session_id: str,
        message_id: str,
        text: str,
        client: ClientMeta,
    ) -> TurnResult:
        return await run_message(
            self._engine,
            self._llm,
            owner_ref,
            fw_session_id,
            message_id,
            text,
            client,
            risky=self._risky,
            decoys=self._decoys,
            tracer=self._tracer,
        )

    async def check_ticket(self, owner_ref: str, ticket_id: str) -> TicketResult:
        return await check_ticket(self._engine, owner_ref, ticket_id)

    async def close_session(self, owner_ref: str, fw_session_id: str) -> None:
        await close_session(self._engine, owner_ref, fw_session_id)


def build_llm(settings: Settings, engine: AsyncEngine) -> ChatModel:
    key = settings.gemini_api_key.get_secret_value()
    if not key:
        return _MissingModel()
    return GeminiClient(
        api_key=key,
        budget=DailyBudget(engine, settings.daily_llm_budget),
        embedding_model=settings.gemini_embedding_model_id,
    )


def build_decoys(settings: Settings, llm: ChatModel) -> DecoyGenerator | None:
    """Gemini decoys (C-06) need a key and a model ID; without them Divert uses its templates.

    The bot model is preferred: measured on the dev key, `gemini-2.5-flash` answers a decoy in
    1.5 to 3.4 s, inside the 5 s limit, while `gemini-3.5-flash` took 4 to 12 s (M2-DD-47)."""
    model_id = settings.bot_model_id or settings.gemini_flash_model_id
    if model_id and isinstance(llm, JsonModel):
        return GeminiDecoys(llm, model_id)
    return None


def create() -> FirewallPort:
    from app.firewall import ports  # imported here: ports imports this module lazily

    settings = get_settings()
    engine = make_engine(settings.database_url)
    llm = build_llm(settings, engine)
    tracer = Tracer.from_settings(settings.proxy_secret.get_secret_value())
    return RealFirewall(
        engine,
        llm,
        ports.get_risky_history(),
        ports.get_judge(),
        build_decoys(settings, llm),
        tracer,
    )
