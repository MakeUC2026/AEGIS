"""M2 B-06 bot runner (spec AEGIS-DOM-110; PRD §7.6). Driven by M1's ScriptedLLM.

Cases: M2-X09 (a 6th tool round never runs; final reply with tools disabled), M2-X10 (the
model sees the last 20 messages), BotUnavailable on model failure, thoughtSignature echo,
untrusted wrapping of tool results.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.arena.scenario_data import SYSTEM_PROMPT, TOOLS
from app.contracts.firewall import BotUnavailable, ToolDef
from app.firewall.bot_runner import (
    ToolStep,
    history_window,
    run_turn,
    tool_declarations,
)
from app.llm.base import ChatMessage, ChatResult, LLMError, LLMTimeout, ToolCall
from app.llm.scripted import ScriptedLLM

DEFS = [
    ToolDef(name=t["name"], json_schema=t["json_schema"], high_risk=t["high_risk"]) for t in TOOLS
]
MODEL = "gemini-bot-test"


def _call(n: int, name: str = "search_docs", **args: Any) -> ToolCall:
    return ToolCall(
        id=f"call-{n}", name=name, arguments=args or {"query": "q3"}, signature=f"sig-{n}"
    )


class Recorder:
    def __init__(self, stop_at: int | None = None) -> None:
        self.seen: list[tuple[str, int]] = []
        self.stop_at = stop_at

    async def __call__(self, call: ToolCall, round_index: int) -> ToolStep:
        self.seen.append((call.id, round_index))
        if self.stop_at is not None and len(self.seen) >= self.stop_at:
            return ToolStep.stop()
        return ToolStep.result(f"result for {call.id}")


async def _turn(llm: ScriptedLLM, hook: Recorder, history: list[ChatMessage] | None = None) -> Any:
    return await run_turn(
        llm, MODEL, SYSTEM_PROMPT, history or [], "Summarise the Q3 notes", DEFS, hook
    )


# --- Declarations ---


def test_tool_declarations_use_the_contract_schemas() -> None:
    decls = tool_declarations(DEFS)
    assert [d["name"] for d in decls] == [t.name for t in DEFS]
    assert all(d["parameters"] == t.json_schema for d, t in zip(decls, DEFS, strict=True))
    assert all(isinstance(d["description"], str) for d in decls)


# --- Plain reply and one tool round --------------------------------------------------------------


async def test_plain_reply_is_one_call_with_the_system_prompt_first() -> None:
    llm = ScriptedLLM(chat_answers=[ChatResult(content="Hello!")])
    turn = await _turn(llm, Recorder())
    assert (turn.reply, turn.stopped, turn.rounds) == ("Hello!", False, 0)
    sent = llm.chat_calls[0]
    assert sent.model == MODEL
    assert sent.messages[0].role == "system" and sent.messages[0].content == SYSTEM_PROMPT
    assert sent.messages[-1] == ChatMessage(role="user", content="Summarise the Q3 notes")
    assert len(sent.tools) == len(DEFS)


async def test_tool_round_feeds_back_wrapped_results_and_echoes_the_signature() -> None:
    llm = ScriptedLLM(
        chat_answers=[ChatResult(content=None, tool_calls=[_call(1)]), ChatResult(content="Done.")]
    )
    hook = Recorder()
    turn = await _turn(llm, hook)
    assert (turn.reply, turn.rounds, hook.seen) == ("Done.", 1, [("call-1", 0)])
    second = llm.chat_calls[1].messages
    assistant = next(m for m in second if m.role == "assistant" and m.tool_calls)
    assert assistant.tool_calls[0].signature == "sig-1"  # Gemini thoughtSignature round trip
    tool_msg = next(m for m in second if m.role == "tool")
    assert tool_msg.tool_call_id == "call-1"
    assert tool_msg.content is not None
    assert 'trust="untrusted"' in tool_msg.content and "result for call-1" in tool_msg.content
    assert [m.role for m in turn.new_messages] == ["assistant", "tool", "assistant"]


async def test_a_stopped_tool_call_ends_the_turn_without_more_model_calls() -> None:
    llm = ScriptedLLM(chat_answers=[ChatResult(content=None, tool_calls=[_call(1), _call(2)])])
    turn = await _turn(llm, Recorder(stop_at=1))
    assert (turn.stopped, turn.reply, len(llm.chat_calls)) == (True, None, 1)


async def test_unparseable_arguments_reach_the_hook_for_the_canonicalizer() -> None:
    bad = ToolCall(id="call-x", name="send_email", arguments="{not json", signature=None)
    llm = ScriptedLLM(
        chat_answers=[ChatResult(content=None, tool_calls=[bad]), ChatResult(content="ok")]
    )
    hook = Recorder()
    await _turn(llm, hook)
    assert hook.seen == [("call-x", 0)]


# --- M2-X09: at most 5 rounds, then a final reply with tools disabled --------------------------


async def test_m2x09_sixth_round_never_runs() -> None:
    looping = [ChatResult(content=None, tool_calls=[_call(i)]) for i in range(5)]
    final = ChatResult(content="Final answer.", tool_calls=[_call(99)])  # ignored: tools are off
    llm = ScriptedLLM(chat_answers=[*looping, final])
    hook = Recorder()
    turn = await _turn(llm, hook)
    assert [r for _, r in hook.seen] == [0, 1, 2, 3, 4]
    assert len(llm.chat_calls) == 6
    assert llm.chat_calls[-1].tools == ()  # the final request has tools disabled
    assert (turn.reply, turn.rounds) == ("Final answer.", 5)


# --- M2-X10: history window ----------------------------------------------------------------------


def test_m2x10_window_keeps_the_last_twenty_and_starts_at_a_student_message() -> None:
    history: list[ChatMessage] = []
    for i in range(10):
        history += [
            ChatMessage(role="user", content=f"u{i}"),
            ChatMessage(role="assistant", content=None, tool_calls=[_call(i)]),
            ChatMessage(role="tool", content=f"t{i}", tool_call_id=f"call-{i}"),
        ]  # 30 messages
    window = history_window(history)
    assert len(window) <= 20
    assert window[0].role == "user"  # never an orphan tool result at the start
    assert window[-1] == history[-1]


async def test_model_receives_the_window_not_the_whole_history() -> None:
    history = [
        ChatMessage(role="user" if i % 2 == 0 else "assistant", content=f"m{i}") for i in range(25)
    ]
    llm = ScriptedLLM(chat_answers=[ChatResult(content="ok")])
    await _turn(llm, Recorder(), history)
    sent = llm.chat_calls[0].messages
    assert sent[0].role == "system"
    assert len(sent) - 1 <= 20  # system prompt plus at most 20 messages
    assert sent[-1].content == "Summarise the Q3 notes"


# --- Model failure ---


@pytest.mark.parametrize("error", [LLMError("boom"), LLMTimeout("slow")])
async def test_model_failure_is_bot_unavailable(error: Exception) -> None:
    llm = ScriptedLLM(chat_answers=[error])
    with pytest.raises(BotUnavailable):
        await _turn(llm, Recorder())
