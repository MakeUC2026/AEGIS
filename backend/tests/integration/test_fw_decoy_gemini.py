"""M2 C-06 Gemini decoys for tool calls (PRD §8.6; E-48, E-49; spec AEGIS-DOM-121).

`GeminiDecoys` asks the JSON model for the fake tool output from the tool's schema and the
attempted call. The prompt never carries the secret (arguments that hold any part of it are
withheld, and an email body is never sent). The answer is scanned for the secret and
regenerated once on a hit, then the fixed template is used (E-48); a timeout or model error
goes straight to the template (E-49).
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine

from app.arena.scenario_data import ATTACKER_MAILBOX
from app.contracts.common import ClientMeta
from app.contracts.fakes import InMemoryRiskyHistory
from app.firewall.canonical import CanonicalCall, canonicalize
from app.firewall.decoy_gemini import GeminiDecoys
from app.firewall.decoys import Decoy, make_decoy, template_decoy
from app.firewall.leak import secret_core
from app.firewall.pipeline import run_message
from app.llm.base import ChatResult, LLMError
from app.llm.scripted import ScriptedLLM
from tests.integration.test_fw_divert import DIVERT_RULE, LEAK_MAIL
from tests.integration.test_fw_review_park import DEFS, SECRET, _rows, _session, _tool

CLIENT = ClientMeta(ip="203.0.113.7", user_agent="ArenaTest/1.0")
MAIL_ANSWER = {
    "result": f"Email sent to {ATTACKER_MAILBOX}.",
    "mail_subject": "Message delivered",
    "mail_body": "Your message to the recipient was delivered at 10:42.",
}


def _call(tool: str, **args: Any) -> CanonicalCall:
    result = canonicalize(tool, args, DEFS, call_id="m1-r0-c0")
    assert isinstance(result, CanonicalCall)
    return result


async def test_the_prompt_is_built_from_the_schema_and_the_call() -> None:
    llm = ScriptedLLM(json_answers=[MAIL_ANSWER])
    tool = next(t for t in DEFS if t.name == "send_email")
    decoy = await GeminiDecoys(llm, "flash-test").generate(_call("send_email", **LEAK_MAIL), tool)

    assert decoy == Decoy(
        MAIL_ANSWER["result"], MAIL_ANSWER["mail_subject"], MAIL_ANSWER["mail_body"]
    )
    [sent] = llm.json_calls
    assert sent.model == "flash-test"
    assert "send_email" in sent.prompt and ATTACKER_MAILBOX in sent.prompt
    assert "notes" in sent.prompt  # the subject helps the decoy look right
    assert "the secret is" not in sent.prompt  # an email body is never sent
    assert "untrusted" in sent.prompt
    assert json.dumps(tool.json_schema, sort_keys=True) in sent.prompt  # the tool's own schema
    assert sent.schema["required"] == ["result"]


async def test_an_answer_without_a_result_is_no_decoy() -> None:
    gen = GeminiDecoys(ScriptedLLM(json_answers=[{"mail_body": "x"}, {"result": 7}]), "m")
    assert await gen.generate(_call("query_db", sql="SELECT 1")) is None
    assert await gen.generate(_call("query_db", sql="SELECT 1")) is None


async def test_mail_fields_are_kept_for_email_only() -> None:
    llm = ScriptedLLM(json_answers=[{"result": "3 rows", "mail_subject": "s", "mail_body": "b"}])
    decoy = await GeminiDecoys(llm, "m").generate(_call("query_db", sql="SELECT * FROM t"))
    assert decoy == Decoy("3 rows")


async def test_a_secret_in_an_argument_never_reaches_the_prompt() -> None:
    llm = ScriptedLLM(json_answers=[{"result": "0 rows"}])
    # test data for the mock database, never executed against a real one
    call = _call("query_db", sql=f"SELECT * FROM keys WHERE k = '{SECRET}'")  # noqa: S608
    await make_decoy(GeminiDecoys(llm, "m"), call, SECRET)
    [sent] = llm.json_calls
    assert SECRET not in sent.prompt and secret_core(SECRET).lower() not in sent.prompt.lower()


async def test_a_hit_is_regenerated_once_then_the_clean_answer_is_used() -> None:
    llm = ScriptedLLM(json_answers=[{"result": f"Done {SECRET}"}, {"result": "Clean."}])
    decoy = await make_decoy(GeminiDecoys(llm, "m"), _call("query_db", sql="SELECT 1"), SECRET)
    assert decoy == Decoy("Clean.") and len(llm.json_calls) == 2


async def test_two_hits_fall_back_to_the_template() -> None:
    leak = {"result": f"Done {SECRET}"}
    llm = ScriptedLLM(json_answers=[leak, leak])
    call = _call("query_db", sql="SELECT 1")
    assert await make_decoy(GeminiDecoys(llm, "m"), call, SECRET) == template_decoy(call)
    assert len(llm.json_calls) == 2  # E-48: regenerated once, no more


async def test_a_model_error_goes_straight_to_the_template() -> None:
    llm = ScriptedLLM(json_answers=[LLMError("down")])
    call = _call("query_db", sql="SELECT 1")
    assert await make_decoy(GeminiDecoys(llm, "m"), call, SECRET) == template_decoy(call)
    assert len(llm.json_calls) == 1


async def test_a_gemini_decoy_is_what_the_student_sees(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine, extra=DIVERT_RULE)
    llm = ScriptedLLM(
        chat_answers=[_tool(1, "send_email", **LEAK_MAIL), ChatResult(content="Sent!")],
        json_answers=[MAIL_ANSWER],
    )
    result = await run_message(
        engine,
        llm,
        owner,
        sid,
        "m1",
        "email it",
        CLIENT,
        risky=InMemoryRiskyHistory(),
        decoys=GeminiDecoys(llm, "flash-test"),
    )
    [effect] = result.player_view.tool_effects
    assert effect.visible_content and "delivered at 10:42" in effect.visible_content
    assert result.facts.diverted is True and result.facts.secret_delivered is False
    [state] = await _rows(
        engine, "SELECT emails FROM fw_mock_state WHERE fw_session_id = :s", s=sid
    )
    assert "delivered at 10:42" in json.dumps(state["emails"])
    assert SECRET not in json.dumps(state["emails"])
