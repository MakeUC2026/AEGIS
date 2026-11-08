"""xAI Grok client: OpenAI-compatible chat completions with tool calling (PRD §3.2, D-15).

Tool-call arguments that are not valid JSON are passed through as the raw string, so the
AFF canonicalizer (M2) can deny them instead of this client silently "fixing" them.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

import httpx

from app.llm.base import ChatMessage, ChatResult, LLMError, LLMTimeout, ToolCall

XAI_BASE_URL = "https://api.x.ai/v1"
DEFAULT_CHAT_TIMEOUT_S = 30.0


class Budget(Protocol):
    async def spend(self, provider: str) -> None: ...


def _wire_message(msg: ChatMessage) -> dict[str, Any]:
    out: dict[str, Any] = {"role": msg.role, "content": msg.content}
    if msg.tool_calls:
        out["tool_calls"] = [
            {
                "id": call.id,
                "type": "function",
                "function": {
                    "name": call.name,
                    "arguments": call.arguments
                    if isinstance(call.arguments, str)
                    else json.dumps(call.arguments),
                },
            }
            for call in msg.tool_calls
        ]
    if msg.tool_call_id is not None:
        out = {"role": "tool", "tool_call_id": msg.tool_call_id, "content": msg.content}
    return out


def _parse_tool_call(raw: dict[str, Any]) -> ToolCall:
    fn = raw.get("function", {})
    args_text = fn.get("arguments", "")
    try:
        args: dict[str, Any] | str = json.loads(args_text) if args_text else {}
        if not isinstance(args, dict):
            args = args_text
    except json.JSONDecodeError:
        args = args_text
    return ToolCall(id=str(raw.get("id", "")), name=str(fn.get("name", "")), arguments=args)


class XaiClient:
    def __init__(
        self,
        api_key: str,
        budget: Budget,
        transport: httpx.AsyncBaseTransport | None = None,
        base_url: str = XAI_BASE_URL,
    ) -> None:
        if not api_key:
            raise ValueError("XAI_API_KEY is not set")
        self._budget = budget
        self._http = httpx.AsyncClient(
            base_url=base_url, headers={"authorization": f"Bearer {api_key}"}, transport=transport
        )

    async def chat_with_tools(
        self,
        model: str,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]],
        timeout_s: float = DEFAULT_CHAT_TIMEOUT_S,
    ) -> ChatResult:
        body: dict[str, Any] = {"model": model, "messages": [_wire_message(m) for m in messages]}
        if tools:
            body["tools"] = [{"type": "function", "function": t} for t in tools]
            body["tool_choice"] = "auto"
        await self._budget.spend("xai")
        try:
            resp = await self._http.post("/chat/completions", json=body, timeout=timeout_s)
        except httpx.TimeoutException as exc:
            raise LLMTimeout(f"xai chat timed out after {timeout_s}s") from exc
        except httpx.HTTPError as exc:
            raise LLMError("xai transport error") from exc
        if resp.status_code != httpx.codes.OK:
            raise LLMError(f"xai returned HTTP {resp.status_code}")
        try:
            message = resp.json()["choices"][0]["message"]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise LLMError("xai returned no message") from exc
        calls = [_parse_tool_call(c) for c in message.get("tool_calls") or []]
        return ChatResult(content=message.get("content"), tool_calls=calls)

    async def aclose(self) -> None:
        await self._http.aclose()
