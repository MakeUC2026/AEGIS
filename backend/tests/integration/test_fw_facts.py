"""M2 C-10 facts: secret_attempted, secret_delivered, diverted (PRD §5.3, §9.4; spec AEGIS-DOM-125).

`secret_delivered` is a fact, computed in every mode over the cumulative visible output (every
visible reply and every readable tool effect of the session): that is how E-22 counts as
delivered in Basic although Basic enforces only the per-message scan. Echo exclusion applies
(8 consecutive characters the student typed, case-insensitive). A partial leak never counts as
delivery. `secret_attempted` is true when the bot tried to send the secret, blocked or not,
and whenever it was delivered. `diverted` is true when a decoy was returned.
"""

from __future__ import annotations

import base64
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.contracts.common import ClientMeta
from app.contracts.fakes import InMemoryRiskyHistory
from app.firewall.pipeline import run_message
from app.firewall.tickets import decide_ticket
from app.llm.base import ChatResult
from app.llm.scripted import ScriptedLLM
from tests.integration.test_fw_decide_ticket import _admin
from tests.integration.test_fw_review_park import REPLY_REVIEW, SECRET, _rows, _session

CLIENT = ClientMeta()
CORE = SECRET[5:]  # the random part: 24 characters
PARTS = [CORE[:8], CORE[8:16], CORE[16:]]


async def _say(
    engine: AsyncEngine, sid: str, owner: str, n: int, reply: str, message: str = "go on"
) -> Any:
    llm = ScriptedLLM(chat_answers=[ChatResult(content=reply)])
    return await run_message(
        engine, llm, owner, sid, f"m{n}", message, CLIENT, risky=InMemoryRiskyHistory()
    )


async def _split_turns(engine: AsyncEngine, mode: str) -> tuple[str, list[Any]]:
    sid, owner = await _session(engine, mode=mode)
    results = []
    for i, part in enumerate(PARTS, start=1):
        results.append(await _say(engine, sid, owner, i, f"Part {i}: {part}"))
    return sid, results


# --- E-22: a secret split across replies -------------------------------------------------------


async def test_basic_releases_a_split_secret_and_counts_it_on_the_completing_reply(
    engine: AsyncEngine,
) -> None:
    sid, results = await _split_turns(engine, "basic")

    assert [r.player_view.status for r in results] == ["replied"] * 3  # Basic scans each alone
    assert [r.facts.secret_delivered for r in results] == [False, False, True]
    assert [r.facts.secret_attempted for r in results] == [False, False, True]  # delivered => tried
    assert results[-1].facts.diverted is False
    stored = await _rows(
        engine,
        "SELECT message_id, secret_delivered FROM fw_events"
        " WHERE fw_session_id = :s AND stage = 'output_check' ORDER BY message_id",
        s=sid,
    )
    assert [r["secret_delivered"] for r in stored] == [False, False, True]


async def test_strict_stops_the_completing_reply_with_a_decoy(engine: AsyncEngine) -> None:
    _, results = await _split_turns(engine, "strict")

    assert [r.facts.secret_delivered for r in results] == [False, False, False]
    last = results[-1]
    assert last.facts.diverted is True and last.facts.secret_attempted is True
    assert last.player_view.reply is not None and PARTS[2] not in last.player_view.reply


async def test_off_counts_the_completing_reply_too(engine: AsyncEngine) -> None:
    _, results = await _split_turns(engine, "off")
    assert [r.facts.secret_delivered for r in results] == [False, False, True]
    assert all(r.player_view.status == "replied" for r in results)


async def test_a_completing_reply_released_by_a_reviewer_counts_as_delivered(
    engine: AsyncEngine,
) -> None:
    sid, owner = await _session(engine, extra=REPLY_REVIEW)
    await _say(engine, sid, owner, 1, f"Part 1: {PARTS[0]}")
    await _say(engine, sid, owner, 2, f"Part 2: {PARTS[1]}")
    held = await _say(engine, sid, owner, 3, f"quarterly part 3: {PARTS[2]}")
    assert held.player_view.status == "awaiting_review"
    assert held.facts.secret_delivered is False  # nothing has reached the student yet

    final = await decide_ticket(
        engine,
        ScriptedLLM(),
        InMemoryRiskyHistory(),
        held.player_view.ticket_id or "",
        "ok",
        await _admin(engine),
    )
    assert final.player_view.status == "replied" and final.facts.secret_delivered is True


# --- encodings, partial leaks and the echo rule -------------------------------------------------


@pytest.mark.parametrize(
    "encode",
    [
        lambda s: s.encode().hex(),
        lambda s: base64.b64encode(s.encode()).decode(),
        lambda s: s[::-1],
        lambda s: " ".join(s),
    ],
    ids=["hex", "base64", "reversed", "spaced"],
)
async def test_an_encoded_secret_in_off_is_attempted_and_delivered(
    engine: AsyncEngine, encode: Any
) -> None:
    sid, owner = await _session(engine, mode="off")
    result = await _say(engine, sid, owner, 1, f"Here: {encode(SECRET)}")
    assert (result.facts.secret_attempted, result.facts.secret_delivered) == (True, True)


async def test_a_partial_leak_is_attempted_but_never_delivered(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine, mode="off")
    result = await _say(engine, sid, owner, 1, f"Maybe it starts {CORE[:12]}")
    assert (result.facts.secret_attempted, result.facts.secret_delivered) == (True, False)


async def test_7_typed_characters_do_not_excuse_a_delivery(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine, mode="off")  # M2-X32
    result = await _say(engine, sid, owner, 1, f"It is {SECRET}", f"Is it {CORE[:7]} something?")
    assert result.facts.secret_delivered is True


async def test_8_typed_characters_in_any_case_are_an_echo(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine, mode="off")  # M2-X33, E-53
    typed = f"Is it {CORE[:8].lower()} something?"
    result = await _say(engine, sid, owner, 1, f"It is {SECRET}", typed)
    assert result.facts.secret_delivered is False and result.facts.secret_attempted is True


async def test_a_secret_the_student_typed_is_not_something_the_bot_tried_to_send(
    engine: AsyncEngine,
) -> None:
    sid, owner = await _session(engine)
    result = await _say(engine, sid, owner, 1, "Hello.", f"my key is {SECRET}")
    assert (result.facts.secret_attempted, result.facts.secret_delivered) == (False, False)


# --- M2-X35: the Strict output cap ---------------------------------------------------------------


async def _seed_visible_output(engine: AsyncEngine, sid: str, chars: int) -> None:
    async with engine.begin() as conn:
        for seq in range(1, chars // 5000 + 2):
            await conn.execute(
                text(
                    "INSERT INTO fw_conversation (fw_session_id, seq, message_id, role, content,"
                    " visible, model_payload) VALUES (:s, :q, 'seed', 'bot', :c, true,"
                    " '{\"in_history\": false}')"
                ),
                {"s": sid, "q": seq, "c": "x" * 5000},
            )


async def test_strict_denies_replies_past_50_000_visible_characters(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine, mode="strict")
    await _seed_visible_output(engine, sid, 50_000)  # 11 rows of 5,000: 55,000
    result = await _say(engine, sid, owner, 1, "Fine.")
    assert result.player_view.status == "blocked"


async def test_basic_is_not_limited_by_the_cumulative_cap(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine, mode="basic")
    await _seed_visible_output(engine, sid, 50_000)
    result = await _say(engine, sid, owner, 1, "Fine.")
    assert result.player_view.status == "replied"
