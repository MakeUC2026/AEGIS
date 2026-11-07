"""ports.py wiring (AEGIS_USE_FAKES) and the ScriptedLLM stub (I-6)."""

from __future__ import annotations

import pytest

from app.contracts.fakes import FakeFirewall
from app.firewall import ports
from app.llm.base import ChatMessage, ChatResult, ToolCall
from app.llm.scripted import ScriptedLLM, UnexpectedLLMCall


def test_fakes_selected_by_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_USE_FAKES", "firewall,read")
    ports.reset()
    fw = ports.get_firewall()
    assert isinstance(fw, FakeFirewall)
    assert ports.get_firewall() is fw  # singleton per process


def test_unknown_fake_name_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_USE_FAKES", "firewall,bogus")
    ports.reset()
    with pytest.raises(ValueError, match="bogus"):
        ports.get_firewall()


def test_missing_real_implementation_is_a_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_USE_FAKES", "")
    ports.reset()
    with pytest.raises(ports.PortUnavailable, match="firewall"):
        ports.get_firewall()


def test_fake_override_for_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_USE_FAKES", "firewall")
    ports.reset()
    mine = FakeFirewall()
    ports.override("firewall", mine)
    assert ports.get_firewall() is mine
    ports.reset()


async def test_scripted_llm_replays_in_order_and_records_calls() -> None:
    llm = ScriptedLLM(
        json_answers=[{"risk": 10}, {"risk": 90}],
        chat_answers=[
            ChatResult(
                content=None,
                tool_calls=[ToolCall(id="c1", name="search_docs", arguments={"query": "notes"})],
            )
        ],
        embeddings=[[0.0] * 768],
    )
    assert await llm.generate_json("m", "p1", {"type": "object"}) == {"risk": 10}
    assert await llm.generate_json("m", "p2", {"type": "object"}) == {"risk": 90}
    chat = await llm.chat_with_tools("grok", [ChatMessage(role="user", content="hi")], tools=[])
    assert chat.tool_calls[0].name == "search_docs"
    assert len(await llm.embed("text")) == 768
    assert [c.prompt for c in llm.json_calls] == ["p1", "p2"]
    with pytest.raises(UnexpectedLLMCall):
        await llm.generate_json("m", "p3", {"type": "object"})


async def test_scripted_llm_raises_scripted_errors() -> None:
    llm = ScriptedLLM(json_answers=[TimeoutError("judge 8s")])
    with pytest.raises(TimeoutError):
        await llm.generate_json("m", "p", {})
