"""Model-client interfaces shared by M2 (bot runner, decoys), M3 (judge, forensics,
embeddings) and M4 (quiz). Real clients: `gemini.py`, `xai.py`. Test stub: `scripted.py`.
"""

from __future__ import annotations

from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

EMBEDDING_DIMENSIONS = 768  # PRD §18.2 default


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ToolCall(_Frozen):
    id: str
    name: str
    arguments: dict[str, Any] | str  # str when the model sent JSON we could not parse


class ChatMessage(_Frozen):
    role: Literal["system", "user", "assistant", "tool"]
    content: str | None = None
    tool_calls: list[ToolCall] = Field(default_factory=list)
    tool_call_id: str | None = None


class ChatResult(_Frozen):
    content: str | None
    tool_calls: list[ToolCall] = Field(default_factory=list)


class LLMError(Exception):
    """A model API call failed or returned something unusable."""


class LLMTimeout(LLMError, TimeoutError):
    """A model API call exceeded its timeout."""


class BudgetExhausted(LLMError):
    """The global daily model budget is used up (PRD §15.1 Cost)."""


@runtime_checkable
class JsonModel(Protocol):
    async def generate_json(
        self, model: str, prompt: str, schema: dict[str, Any], timeout_s: float = 30.0
    ) -> dict[str, Any]: ...


@runtime_checkable
class ChatModel(Protocol):
    async def chat_with_tools(
        self,
        model: str,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]],
        timeout_s: float = 30.0,
    ) -> ChatResult: ...


@runtime_checkable
class Embedder(Protocol):
    async def embed(self, text: str, timeout_s: float = 2.0) -> list[float]: ...
