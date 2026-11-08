"""Real model clients against a mocked transport: request shape, parsing, errors, budget."""

from __future__ import annotations

import json

import httpx
import pytest

from app.llm.base import BudgetExhausted, ChatMessage, LLMError, LLMTimeout, ToolCall
from app.llm.gemini import GeminiClient

GEMINI_KEY = "test-gemini-key"


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


# --- Gemini as the arena bot: chat with function calling (replaces xAI Grok) ---------------

TOOLS = [
    {
        "name": "send_email",
        "description": "Send an email",
        "parameters": {
            "type": "object",
            "properties": {"to": {"type": "string"}},
            "required": ["to"],
            "additionalProperties": False,
        },
    }
]


def _chat_answer(parts: list[dict]) -> httpx.Response:
    return httpx.Response(
        200, json={"candidates": [{"content": {"role": "model", "parts": parts}}]}
    )


async def test_gemini_chat_request_shape() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return _chat_answer([{"text": "Hello"}])

    budget = CountingBudget()
    msgs = [
        ChatMessage(role="system", content="You are Kestrel."),
        ChatMessage(role="user", content="hi"),
    ]
    out = await _gemini(handler, budget).chat_with_tools("gemini-bot", msgs, TOOLS)
    body = seen["body"]
    assert seen["url"].endswith("/models/gemini-bot:generateContent")
    assert body["systemInstruction"] == {"parts": [{"text": "You are Kestrel."}]}
    assert body["contents"] == [{"role": "user", "parts": [{"text": "hi"}]}]
    decl = body["tools"][0]["functionDeclarations"][0]
    assert decl["name"] == "send_email"
    assert decl["parametersJsonSchema"] == TOOLS[0]["parameters"]  # full JSON schema, unchanged
    assert body["toolConfig"] == {"functionCallingConfig": {"mode": "AUTO"}}
    assert out.content == "Hello" and out.tool_calls == []
    assert budget.spent == ["gemini"]


async def test_gemini_chat_parses_function_calls_with_ids_and_signatures() -> None:
    def handler(_r: httpx.Request) -> httpx.Response:
        return _chat_answer(
            [
                {"text": "Sending now."},
                {
                    "functionCall": {
                        "id": "fc-1",
                        "name": "send_email",
                        "args": {"to": "x@evil.example"},
                    },
                    "thoughtSignature": "sig-abc",
                },
                {"functionCall": {"name": "send_email", "args": {"to": "y@evil.example"}}},
            ]
        )

    out = await _gemini(handler).chat_with_tools(
        "m", [ChatMessage(role="user", content="go")], TOOLS
    )
    assert out.content == "Sending now."
    first, second = out.tool_calls
    assert (first.id, first.name, first.arguments, first.signature) == (
        "fc-1",
        "send_email",
        {"to": "x@evil.example"},
        "sig-abc",
    )
    assert second.id and second.id != first.id  # generated when Gemini sends no id
    assert second.signature is None


async def test_gemini_chat_round_trips_tool_calls_and_results() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        return _chat_answer([{"text": "Done."}])

    call = ToolCall(
        id="fc-1", name="send_email", arguments={"to": "a@company.example"}, signature="sig-abc"
    )
    msgs = [
        ChatMessage(role="user", content="email hr"),
        ChatMessage(role="assistant", content=None, tool_calls=[call]),
        ChatMessage(role="tool", tool_call_id="fc-1", content="sent"),
    ]
    await _gemini(handler).chat_with_tools("m", msgs, TOOLS)
    model_turn, tool_turn = seen["body"]["contents"][1:]
    assert model_turn == {
        "role": "model",
        "parts": [
            {
                "functionCall": {
                    "id": "fc-1",
                    "name": "send_email",
                    "args": {"to": "a@company.example"},
                },
                "thoughtSignature": "sig-abc",
            }
        ],
    }
    assert tool_turn == {
        "role": "user",
        "parts": [
            {
                "functionResponse": {
                    "id": "fc-1",
                    "name": "send_email",
                    "response": {"result": "sent"},
                }
            }
        ],
    }


async def test_gemini_chat_tool_result_for_unknown_call_is_an_error() -> None:
    msgs = [ChatMessage(role="tool", tool_call_id="nope", content="x")]
    with pytest.raises(LLMError):
        await _gemini(lambda _r: _chat_answer([])).chat_with_tools("m", msgs, [])


async def test_gemini_chat_errors_map_to_llm_errors() -> None:
    with pytest.raises(LLMError):
        await _gemini(lambda _r: httpx.Response(429, json={})).chat_with_tools("m", [], [])
    with pytest.raises(LLMError):
        await _gemini(lambda _r: httpx.Response(200, json={"candidates": []})).chat_with_tools(
            "m", [], []
        )

    def slow(_r: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("slow")

    with pytest.raises(LLMTimeout):
        await _gemini(slow).chat_with_tools("m", [], [])
