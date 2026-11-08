"""Bot runner (M2 B-06; PRD §7.6, D-15; spec AEGIS-DOM-110).

Runs one student turn against the bot model through M1's `ChatModel.chat_with_tools`
(Gemini in production, `ScriptedLLM` in tests):

- the model sees the system prompt plus the last 20 messages, and the window always starts
  at a student message, so no tool result is left without its call (M2-X10, M2-DD-27);
- up to 5 tool-call rounds; after the 5th, one final call with tools disabled, and any tool
  calls in it are ignored (M2-X09);
- every proposed tool call goes to `on_tool_call` first (the pipeline's tool-call check);
  it returns the result to feed back, stops the turn (deny, divert, error), or holds it for
  review: the turn then ends with `held` set and the calls after the held one in the same
  model message kept unchecked in `remaining_calls` (C-01);
- tool results go back wrapped as untrusted data (delimited and labelled, M2-DD-28);
- each `ToolCall` (with Gemini's `thoughtSignature`) is sent back unchanged on the next call;
- a model error or timeout raises `BotUnavailable`, so the caller releases the claim and the
  arena can retry with the same message ID.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from app.contracts.firewall import BotUnavailable, ToolDef
from app.firewall.limits import BOT_HISTORY_MESSAGES, tool_rounds_exhausted
from app.llm.base import ChatMessage, ChatModel, ChatResult, LLMError, ToolCall

BOT_CALL_TIMEOUT_S = 15.0  # per model call; the arena gives the whole turn 30 s


@dataclass(frozen=True)
class ToolStep:
    kind: Literal["result", "stop", "hold"]
    content: str = ""

    @classmethod
    def result(cls, content: str) -> ToolStep:
        return cls("result", content)

    @classmethod
    def stop(cls) -> ToolStep:
        return cls("stop")

    @classmethod
    def hold(cls) -> ToolStep:
        return cls("hold")


@dataclass(frozen=True)
class BotTurn:
    reply: str | None  # None when a tool call stopped the turn
    stopped: bool
    rounds: int  # tool-call rounds used
    new_messages: tuple[ChatMessage, ...]  # assistant and tool messages added this turn
    held: bool = False  # stopped by a tool call parked for review
    remaining_calls: tuple[ToolCall, ...] = ()  # proposed after the held call, not checked


ToolHook = Callable[[ToolCall, int], Awaitable[ToolStep]]


def tool_declarations(tools: Sequence[ToolDef]) -> list[dict[str, Any]]:
    return [
        {
            "name": t.name,
            "description": str(t.json_schema.get("description", "")),
            "parameters": t.json_schema,
        }
        for t in tools
    ]


def wrap_untrusted(tool: str, content: str) -> str:
    return f'<tool_result tool="{tool}" trust="untrusted">\n{content}\n</tool_result>'


def history_window(messages: Sequence[ChatMessage]) -> tuple[ChatMessage, ...]:
    """The last BOT_HISTORY_MESSAGES, trimmed forward to the first student message."""
    tail = list(messages[-BOT_HISTORY_MESSAGES:])
    start = next((i for i, m in enumerate(tail) if m.role == "user"), len(tail))
    return tuple(tail[start:])


async def _chat(
    llm: ChatModel,
    model: str,
    messages: Sequence[ChatMessage],
    tools: list[dict[str, Any]],
    timeout_s: float,
) -> ChatResult:
    try:
        return await llm.chat_with_tools(model, list(messages), tools, timeout_s=timeout_s)
    except (LLMError, TimeoutError) as exc:
        raise BotUnavailable(f"bot model failed: {type(exc).__name__}") from exc


async def run_turn(
    llm: ChatModel,
    model: str,
    system_prompt: str,
    history: Sequence[ChatMessage],
    user_text: str,
    tools: Sequence[ToolDef],
    on_tool_call: ToolHook,
    timeout_s: float = BOT_CALL_TIMEOUT_S,
) -> BotTurn:
    window = history_window([*history, ChatMessage(role="user", content=user_text)])
    messages: tuple[ChatMessage, ...] = (ChatMessage(role="system", content=system_prompt), *window)
    added: tuple[ChatMessage, ...] = ()
    declarations = tool_declarations(tools)
    round_index = 0
    while True:
        tools_on = not tool_rounds_exhausted(round_index)
        result = await _chat(llm, model, messages, declarations if tools_on else [], timeout_s)
        if not tools_on or not result.tool_calls:
            reply = ChatMessage(role="assistant", content=result.content or "")
            return BotTurn(result.content or "", False, round_index, (*added, reply))
        assistant = ChatMessage(
            role="assistant", content=result.content, tool_calls=list(result.tool_calls)
        )
        messages, added = (*messages, assistant), (*added, assistant)
        for i, call in enumerate(result.tool_calls):
            step = await on_tool_call(call, round_index)
            if step.kind == "hold":
                rest = tuple(result.tool_calls[i + 1 :])
                return BotTurn(None, True, round_index, added, held=True, remaining_calls=rest)
            if step.kind == "stop":
                return BotTurn(None, True, round_index, added)
            tool_msg = ChatMessage(
                role="tool", content=wrap_untrusted(call.name, step.content), tool_call_id=call.id
            )
            messages, added = (*messages, tool_msg), (*added, tool_msg)
        round_index += 1
