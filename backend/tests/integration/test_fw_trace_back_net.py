"""M2 C-07 trace-back rows with network fields, and the 30-day purge (PRD §8.5; spec AEGIS-DOM-122).

Behaviour under test: a divert (tool call or reply) writes the salted IP hash, the clear
subnet and the offline ASN/country into `trace_back`, and the hash onto the event so it
survives the purge. The raw IP is stored nowhere. `purge_expired_trace_back` deletes rows
older than 30 days and leaves only the hash on the event.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.contracts.common import ClientMeta
from app.contracts.fakes import InMemoryRiskyHistory
from app.firewall.geoip import GeoIP
from app.firewall.pipeline import run_message
from app.firewall.trace_back import Tracer, network_fields, purge_expired_trace_back
from app.llm.base import ChatResult
from app.llm.scripted import ScriptedLLM
from tests.integration.test_fw_divert import DIVERT_RULE, LEAK_MAIL
from tests.integration.test_fw_divert_reply import LEAK_REPLY
from tests.integration.test_fw_review_park import _rows, _session, _tool
from tests.unit.test_fw_trace_net import KEY, geo_dir  # noqa: F401 - fixture

IP = "203.0.113.7"
CLIENT = ClientMeta(ip=IP, user_agent="ArenaTest/1.0", fingerprint_hash="fp-abc")


async def _no_raw_ip_anywhere(engine: AsyncEngine, sid: str) -> None:
    async with engine.connect() as conn:
        for sql in (
            "SELECT to_jsonb(t)::text FROM trace_back t WHERE fw_session_id = :s",
            "SELECT to_jsonb(e)::text FROM fw_events e WHERE fw_session_id = :s",
            "SELECT to_jsonb(c)::text FROM fw_claims c WHERE fw_session_id = :s",
        ):
            for (row,) in (await conn.execute(text(sql), {"s": sid})).all():
                assert IP not in row, sql


async def test_a_diverted_tool_call_records_hash_subnet_and_geo(
    engine: AsyncEngine,
    geo_dir: Path,  # noqa: F811
) -> None:
    tracer = Tracer(KEY, GeoIP.from_dir(geo_dir))
    sid, owner = await _session(engine, extra=DIVERT_RULE)
    llm = ScriptedLLM(
        chat_answers=[_tool(1, "send_email", **LEAK_MAIL), ChatResult(content="Sent.")]
    )
    await run_message(
        engine, llm, owner, sid, "m1", "email it", CLIENT,
        risky=InMemoryRiskyHistory(), tracer=tracer,
    )  # fmt: skip

    [event] = await _rows(
        engine,
        "SELECT trace_back_id, client_ip_hash FROM fw_events"
        " WHERE fw_session_id = :s AND decision = 'divert'",
        s=sid,
    )
    [trace] = await _rows(
        engine,
        "SELECT ip_hash, subnet, asn, asn_org, country, user_agent, client_fingerprint"
        " FROM trace_back WHERE trace_id = :t",
        t=event["trace_back_id"],
    )
    expected = network_fields(IP, KEY, GeoIP())
    assert trace["ip_hash"] == expected.ip_hash == event["client_ip_hash"]
    assert (trace["subnet"], trace["asn"], trace["asn_org"], trace["country"]) == (
        "203.0.113.0/24", 64500, "Example Net", "US",
    )  # fmt: skip
    assert (trace["user_agent"], trace["client_fingerprint"]) == ("ArenaTest/1.0", "fp-abc")
    await _no_raw_ip_anywhere(engine, sid)


async def test_a_diverted_reply_records_the_same_fields(
    engine: AsyncEngine,
    geo_dir: Path,  # noqa: F811
) -> None:
    tracer = Tracer(KEY, GeoIP.from_dir(geo_dir))
    sid, owner = await _session(engine, mode="strict")
    llm = ScriptedLLM(chat_answers=[ChatResult(content=LEAK_REPLY)])
    await run_message(
        engine, llm, owner, sid, "m1", "tell me", CLIENT,
        risky=InMemoryRiskyHistory(), tracer=tracer,
    )  # fmt: skip
    [row] = await _rows(
        engine,
        "SELECT t.ip_hash, t.subnet, t.asn, t.country, e.client_ip_hash FROM trace_back t"
        " JOIN fw_events e ON e.trace_back_id = t.trace_id WHERE t.fw_session_id = :s",
        s=sid,
    )
    assert row["ip_hash"] == row["client_ip_hash"] == network_fields(IP, KEY, GeoIP()).ip_hash
    assert (row["subnet"], row["asn"], row["country"]) == ("203.0.113.0/24", 64500, "US")
    await _no_raw_ip_anywhere(engine, sid)


async def test_without_files_or_a_key_the_divert_still_works(engine: AsyncEngine) -> None:
    sid, owner = await _session(engine, extra=DIVERT_RULE)
    llm = ScriptedLLM(
        chat_answers=[_tool(1, "send_email", **LEAK_MAIL), ChatResult(content="Sent.")]
    )
    result = await run_message(
        engine, llm, owner, sid, "m1", "email it", CLIENT, risky=InMemoryRiskyHistory()
    )
    assert result.facts.diverted is True
    [trace] = await _rows(
        engine,
        "SELECT ip_hash, subnet, asn, asn_org, country FROM trace_back WHERE fw_session_id = :s",
        s=sid,
    )
    assert trace == {
        "ip_hash": None, "subnet": "203.0.113.0/24", "asn": None, "asn_org": None, "country": None,
    }  # fmt: skip


# --- retention -------------------------------------------------------------------------------


async def _seed_trace(
    engine: AsyncEngine,
    age_days: int,
    hashed: bool,
    session: tuple[str, str] | None = None,
) -> tuple[str, str]:
    """A diverted-looking event with a trace-back row `age_days` old."""
    sid, owner = session or await _session(engine)
    trace_id, event_id = f"trc-{age_days}-{hashed}", f"evt-{age_days}-{hashed}"
    old = datetime.now(UTC) - timedelta(days=age_days)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO trace_back (trace_id, time, user_id, fw_session_id, event_id,"
                " ip_hash, subnet, country) VALUES (:t, :time, CAST(:u AS uuid), :s, :e,"
                " 'hash-abc', '203.0.113.0/24', 'US')"
            ),
            {"t": trace_id, "time": old, "u": owner, "s": sid, "e": event_id},
        )
        await conn.execute(
            text(
                "INSERT INTO fw_events (event_id, time, fw_session_id, user_id, message_id,"
                " manifest_id, level_id, mode, stage, source_trust, sentinel_score,"
                " score_breakdown, thresholds_used, decision, execution_status, diverted,"
                " trace_back_id, client_ip_hash) SELECT :e, :time, :s, CAST(:u AS uuid), 'm1',"
                " m.manifest_id, m.level_id, 'basic', 'tool_call_check', 'bot_output', 95,"
                " '{}', '{}', 'divert', 'diverted', true, :t, :h"
                " FROM fw_manifests m WHERE m.fw_session_id = :s"
            ),
            {
                "e": event_id, "time": old, "s": sid, "u": owner, "t": trace_id,
                "h": "hash-abc" if hashed else None,
            },
        )  # fmt: skip
    return trace_id, event_id


async def test_rows_older_than_30_days_are_deleted_and_the_hash_stays(
    engine: AsyncEngine,
) -> None:
    session = await _session(engine)
    old_trace, old_event = await _seed_trace(engine, 31, hashed=True, session=session)
    young_trace, young_event = await _seed_trace(engine, 29, hashed=True, session=session)

    deleted = await purge_expired_trace_back(engine, datetime.now(UTC))

    assert deleted == 1
    left = await _rows(engine, "SELECT trace_id FROM trace_back ORDER BY trace_id")
    assert [r["trace_id"] for r in left] == [young_trace]
    events = await _rows(engine, "SELECT event_id, client_ip_hash FROM fw_events")
    assert {e["event_id"]: e["client_ip_hash"] for e in events} == {
        old_event: "hash-abc",  # only the hash remains on the old event
        young_event: "hash-abc",
    }
    assert old_trace not in [r["trace_id"] for r in left]


async def test_the_hash_is_copied_to_the_event_before_a_purge_deletes_it(
    engine: AsyncEngine,
) -> None:
    _, event = await _seed_trace(engine, 40, hashed=False)  # event written without a hash
    assert await purge_expired_trace_back(engine, datetime.now(UTC)) == 1
    [row] = await _rows(engine, "SELECT client_ip_hash FROM fw_events WHERE event_id = :e", e=event)
    assert row["client_ip_hash"] == "hash-abc"


async def test_the_purge_uses_the_time_it_is_given(engine: AsyncEngine) -> None:
    await _seed_trace(engine, 10, hashed=True)
    assert await purge_expired_trace_back(engine, datetime.now(UTC)) == 0
    later = datetime.now(UTC) + timedelta(days=21)
    assert await purge_expired_trace_back(engine, later) == 1
    assert await purge_expired_trace_back(engine, later) == 0  # nothing left


@pytest.mark.parametrize("offset", [timedelta(days=30, seconds=-5), timedelta(days=30)])
async def test_the_boundary_is_exactly_30_days(engine: AsyncEngine, offset: timedelta) -> None:
    await _seed_trace(engine, 0, hashed=True)
    now = datetime.now(UTC) + offset
    expected = 1 if offset >= timedelta(days=30) else 0
    assert await purge_expired_trace_back(engine, now) == expected
