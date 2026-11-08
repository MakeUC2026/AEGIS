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
# Said to the model on the last request only, when tools are off. Without it a real model keeps
# asking for a tool and answers with no text (Gemini `UNEXPECTED_TOOL_CALL`). Never stored.
TOOL_LIMIT_NOTICE = (
    "The tool limit for this turn is reached and no more tools can be called. "
    "Reply to the student now, in plain text, with what you have."
)


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


def _tool_message(call: ToolCall, step: ToolStep) -> ChatMessage:
    return ChatMessage(
        role="tool", content=wrap_untrusted(call.name, step.content), tool_call_id=call.id
    )


Messages = tuple[ChatMessage, ...]


async def _run_calls(
    calls: Sequence[ToolCall],
    round_index: int,
    on_tool_call: ToolHook,
    messages: Messages,
    added: Messages,
    first_step: ToolStep | None = None,
) -> tuple[Messages, Messages, BotTurn | None]:
    """Feed each call through the hook; a BotTurn back means the turn ended here."""
    for i, call in enumerate(calls):
        step = first_step if i == 0 and first_step is not None else None
        step = step or await on_tool_call(call, round_index)
        if step.kind == "hold":
            rest = tuple(calls[i + 1 :])
            return messages, added, BotTurn(None, True, round_index, added, True, rest)
        if step.kind == "stop":
            return messages, added, BotTurn(None, True, round_index, added)
        tool_msg = _tool_message(call, step)
        messages, added = (*messages, tool_msg), (*added, tool_msg)
    return messages, added, None


async def _loop(
    llm: ChatModel,
    model: str,
    messages: Messages,
    added: Messages,
    declarations: list[dict[str, Any]],
    round_index: int,
    on_tool_call: ToolHook,
    timeout_s: float,
) -> BotTurn:
    while True:
        tools_on = not tool_rounds_exhausted(round_index)
        asked = (
            messages
            if tools_on
            else (*messages, ChatMessage(role="user", content=TOOL_LIMIT_NOTICE))
        )
        result = await _chat(llm, model, asked, declarations if tools_on else [], timeout_s)
        if not tools_on or not result.tool_calls:
            reply = ChatMessage(role="assistant", content=result.content or "")
            return BotTurn(result.content or "", False, round_index, (*added, reply))
        assistant = ChatMessage(
            role="assistant", content=result.content, tool_calls=list(result.tool_calls)
        )
        messages, added = (*messages, assistant), (*added, assistant)
        messages, added, ended = await _run_calls(
            result.tool_calls, round_index, on_tool_call, messages, added
        )
        if ended is not None:
            return ended
        round_index += 1


def _opening(system_prompt: str, history: Sequence[ChatMessage], user_text: str) -> Messages:
    window = history_window([*history, ChatMessage(role="user", content=user_text)])
    return (ChatMessage(role="system", content=system_prompt), *window)


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
    messages = _opening(system_prompt, history, user_text)
    declarations = tool_declarations(tools)
    return await _loop(llm, model, messages, (), declarations, 0, on_tool_call, timeout_s)


async def resume_turn(
    llm: ChatModel,
    model: str,
    system_prompt: str,
    history: Sequence[ChatMessage],
    user_text: str,
    tools: Sequence[ToolDef],
    on_tool_call: ToolHook,
    prior: Sequence[ChatMessage],
    round_index: int,
    calls: Sequence[ToolCall],
    held_step: ToolStep,
    timeout_s: float = BOT_CALL_TIMEOUT_S,
) -> BotTurn:
    """Continue a turn parked on a tool call (C-02): `prior` is the bot's messages so far,
    `calls` the held call (already run, its outcome `held_step`) then the calls queued after
    it, which go through the hook like any new call."""
    messages = (*_opening(system_prompt, history, user_text), *prior)
    messages, added, ended = await _run_calls(
        calls, round_index, on_tool_call, messages, tuple(prior), first_step=held_step
    )
    if ended is not None:
        return ended
    declarations = tool_declarations(tools)
    return await _loop(
        llm, model, messages, added, declarations, round_index + 1, on_tool_call, timeout_s
    )
