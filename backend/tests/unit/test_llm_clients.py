"""Real model clients against a mocked transport: request shape, parsing, errors, budget."""

from __future__ import annotations

import json

import httpx
import pytest

from app.llm.base import BudgetExhausted, ChatMessage, LLMError, LLMTimeout
from app.llm.gemini import GeminiClient
from app.llm.xai import XaiClient

GEMINI_KEY = "test-gemini-key"
XAI_KEY = "test-xai-key"


class CountingBudget:
    def __init__(self, allow: bool = True) -> None:
        self.allow = allow
        self.spent: list[str] = []

    async def spend(self, provider: str) -> None:
        if not self.allow:
            raise BudgetExhausted("daily model budget used up")
        self.spent.append(provider)


def _gemini(handler, budget: CountingBudget | None = None) -> GeminiClient:  # type: ignore[no-untyped-def]
    return GeminiClient(
        api_key=GEMINI_KEY,
        budget=budget or CountingBudget(),
        transport=httpx.MockTransport(handler),
        embedding_model="gemini-embedding-test",
    )


async def test_gemini_generate_json_sends_schema_and_parses() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["key"] = request.headers.get("x-goog-api-key")
        seen["body"] = json.loads(request.content)
        answer = {"candidates": [{"content": {"parts": [{"text": '{"risk": 42}'}]}}]}
        return httpx.Response(200, json=answer)

    budget = CountingBudget()
    out = await _gemini(handler, budget).generate_json("gemini-flash", "p", {"type": "object"})
    assert out == {"risk": 42}
    assert seen["key"] == GEMINI_KEY and GEMINI_KEY not in seen["url"]  # key in header only
    assert seen["url"].endswith("/models/gemini-flash:generateContent")
    config = seen["body"]["generationConfig"]
    assert config["responseMimeType"] == "application/json"
    assert config["responseJsonSchema"] == {"type": "object"}
    assert budget.spent == ["gemini"]


@pytest.mark.parametrize(
    "payload",
    [
        {"candidates": []},
        {"candidates": [{"content": {"parts": [{"text": "not json"}]}}]},
        {"candidates": [{"content": {"parts": [{"text": "[1, 2]"}]}}]},
    ],
    ids=["no-candidates", "not-json", "not-an-object"],
)
async def test_gemini_unusable_answer_is_llm_error(payload: dict) -> None:
    client = _gemini(lambda _r: httpx.Response(200, json=payload))
    with pytest.raises(LLMError):
        await client.generate_json("m", "p", {})


async def test_gemini_http_error_and_timeout() -> None:
    with pytest.raises(LLMError):
        await _gemini(lambda _r: httpx.Response(500, json={})).generate_json("m", "p", {})

    def slow(_r: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    with pytest.raises(LLMTimeout):
        await _gemini(slow).generate_json("m", "p", {})


async def test_gemini_embed_returns_768_dimensions() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["outputDimensionality"] == 768
        return httpx.Response(200, json={"embedding": {"values": [0.1] * 768}})

    assert len(await _gemini(handler).embed("hello")) == 768


async def test_gemini_embed_wrong_dimension_is_error() -> None:
    client = _gemini(lambda _r: httpx.Response(200, json={"embedding": {"values": [0.1] * 3}}))
    with pytest.raises(LLMError):
        await client.embed("hello")


async def test_budget_exhausted_blocks_the_call() -> None:  # M1-X11
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={})

    with pytest.raises(BudgetExhausted):
        await _gemini(handler, CountingBudget(allow=False)).generate_json("m", "p", {})
    assert calls == []


def _xai(handler, budget: CountingBudget | None = None) -> XaiClient:  # type: ignore[no-untyped-def]
    return XaiClient(
        api_key=XAI_KEY, budget=budget or CountingBudget(), transport=httpx.MockTransport(handler)
    )


async def test_xai_chat_with_tools_request_and_tool_call_parsing() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        message = {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "send_email", "arguments": '{"to": "x@evil.example"}'},
                },
                {
                    "id": "call_2",
                    "type": "function",
                    "function": {"name": "read_file", "arguments": "{broken"},
                },
            ],
        }
        return httpx.Response(200, json={"choices": [{"message": message}]})

    tools = [{"name": "send_email", "description": "d", "parameters": {"type": "object"}}]
    result = await _xai(handler).chat_with_tools(
        "grok-test",
        [ChatMessage(role="system", content="s"), ChatMessage(role="user", content="u")],
        tools,
    )
    assert seen["auth"] == f"Bearer {XAI_KEY}"
    assert seen["body"]["model"] == "grok-test"
    assert seen["body"]["tools"][0] == {"type": "function", "function": tools[0]}
    assert result.tool_calls[0].arguments == {"to": "x@evil.example"}
    assert result.tool_calls[1].arguments == "{broken"  # raw string kept for M2 to deny
    assert result.content is None


async def test_xai_tool_result_messages_are_serialised() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["messages"][-1] == {"role": "tool", "tool_call_id": "call_1", "content": "ok"}
        return httpx.Response(200, json={"choices": [{"message": {"content": "done"}}]})

    msgs = [ChatMessage(role="tool", tool_call_id="call_1", content="ok")]
    assert (await _xai(handler).chat_with_tools("g", msgs, [])).content == "done"


async def test_xai_errors_map_to_llm_errors() -> None:
    with pytest.raises(LLMError):
        await _xai(lambda _r: httpx.Response(429, json={})).chat_with_tools("g", [], [])

    def slow(_r: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("slow")

    with pytest.raises(LLMTimeout):
        await _xai(slow).chat_with_tools("g", [], [])
