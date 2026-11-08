"""ScriptedLLM: deterministic stand-in for Grok and Gemini in tests (PRD §16.1, I-6).

Replays scripted answers in order, records every call for assertions, and raises
`UnexpectedLLMCall` when a test makes a call it did not script.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any

from app.llm.base import ChatMessage, ChatResult


class UnexpectedLLMCall(AssertionError):
    """A model call happened that the test did not script."""


@dataclass(frozen=True)
class JsonCall:
    model: str
    prompt: str
    schema: dict[str, Any]


@dataclass(frozen=True)
class ChatCall:
    model: str
    messages: tuple[ChatMessage, ...]
    tools: tuple[dict[str, Any], ...]


class ScriptedLLM:
    def __init__(
        self,
        json_answers: list[dict[str, Any] | Exception] | None = None,
        chat_answers: list[ChatResult | Exception] | None = None,
        embeddings: list[list[float] | Exception] | None = None,
    ) -> None:
        self._json: deque[dict[str, Any] | Exception] = deque(json_answers or [])
        self._chat: deque[ChatResult | Exception] = deque(chat_answers or [])
        self._embed: deque[list[float] | Exception] = deque(embeddings or [])
        self.json_calls: list[JsonCall] = []
        self.chat_calls: list[ChatCall] = []
        self.embed_calls: list[str] = []

    @staticmethod
    def _pop(queue: deque[Any], kind: str) -> Any:
        if not queue:
            raise UnexpectedLLMCall(f"unscripted {kind} call")
        answer = queue.popleft()
        if isinstance(answer, Exception):
            raise answer
        return answer

    async def generate_json(
        self, model: str, prompt: str, schema: dict[str, Any], timeout_s: float = 30.0
    ) -> dict[str, Any]:
        self.json_calls.append(JsonCall(model=model, prompt=prompt, schema=schema))
        return dict(self._pop(self._json, "generate_json"))

    async def chat_with_tools(
        self,
        model: str,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]],
        timeout_s: float = 30.0,
    ) -> ChatResult:
        self.chat_calls.append(ChatCall(model=model, messages=tuple(messages), tools=tuple(tools)))
        return self._pop(self._chat, "chat_with_tools")

    async def embed(self, text: str, timeout_s: float = 2.0) -> list[float]:
        self.embed_calls.append(text)
        return list(self._pop(self._embed, "embed"))
