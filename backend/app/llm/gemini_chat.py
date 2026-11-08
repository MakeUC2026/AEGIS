"""Translate our provider-neutral chat messages to Gemini `generateContent` and back.

Gemini is the attacked arena bot (PRD D-15 as revised: Gemini replaces Grok). Function
calling uses `functionDeclarations` with the full JSON schema (`parametersJsonSchema`).
Gemini 3 returns a `thoughtSignature` on function-call parts that must be echoed back on
the next turn, so it rides along on `ToolCall.signature`.
"""

from __future__ import annotations

import itertools
from typing import Any

from app.llm.base import ChatMessage, ChatResult, LLMError, ToolCall

_generated_ids = itertools.count(1)


def _function_call_part(call: ToolCall) -> dict[str, Any]:
    args = call.arguments if isinstance(call.arguments, dict) else {"_raw": call.arguments}
    part: dict[str, Any] = {"functionCall": {"id": call.id, "name": call.name, "args": args}}
    if call.signature:
        part["thoughtSignature"] = call.signature
    return part


def build_request(messages: list[ChatMessage], tools: list[dict[str, Any]]) -> dict[str, Any]:
    system_text: list[str] = []
    contents: list[dict[str, Any]] = []
    names_by_call_id: dict[str, str] = {}

    for msg in messages:
        if msg.role == "system":
            system_text.append(msg.content or "")
        elif msg.role == "user":
            contents.append({"role": "user", "parts": [{"text": msg.content or ""}]})
        elif msg.role == "assistant":
            parts: list[dict[str, Any]] = [{"text": msg.content}] if msg.content else []
            for call in msg.tool_calls:
                names_by_call_id[call.id] = call.name
                parts.append(_function_call_part(call))
            contents.append({"role": "model", "parts": parts})
        else:  # tool result
            call_id = msg.tool_call_id or ""
            if call_id not in names_by_call_id:
                raise LLMError(f"tool result for unknown call id {call_id!r}")
            response = {
                "id": call_id,
                "name": names_by_call_id[call_id],
                "response": {"result": msg.content or ""},
            }
            contents.append({"role": "user", "parts": [{"functionResponse": response}]})

    body: dict[str, Any] = {"contents": contents}
    if system_text:
        body["systemInstruction"] = {"parts": [{"text": "\n\n".join(system_text)}]}
    if tools:
        declarations = [
            {
                "name": t["name"],
                "description": t.get("description", ""),
                "parametersJsonSchema": t.get("parameters", {"type": "object"}),
            }
            for t in tools
        ]
        body["tools"] = [{"functionDeclarations": declarations}]
        body["toolConfig"] = {"functionCallingConfig": {"mode": "AUTO"}}
    return body


def parse_response(data: dict[str, Any]) -> ChatResult:
    try:
        parts = data["candidates"][0]["content"].get("parts") or []
    except (KeyError, IndexError, TypeError, AttributeError) as exc:
        raise LLMError("gemini returned no candidate") from exc
    texts: list[str] = []
    calls: list[ToolCall] = []
    for part in parts:
        if "functionCall" in part:
            fc = part["functionCall"]
            args = fc.get("args", {})
            calls.append(
                ToolCall(
                    id=str(fc.get("id") or f"gen-call-{next(_generated_ids)}"),
                    name=str(fc.get("name", "")),
                    arguments=args if isinstance(args, dict) else str(args),
                    signature=part.get("thoughtSignature"),
                )
            )
        elif isinstance(part.get("text"), str) and not part.get("thought"):
            texts.append(part["text"])
    return ChatResult(content="".join(texts) or None, tool_calls=calls)
