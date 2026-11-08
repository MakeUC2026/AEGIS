"""Phase D fuzzing (M1 master prompt: Hypothesis on every external input).

Properties:
- The arena HTTP API never answers 500 for any message body, path ID or ticket ID; accepted
  text comes back byte-for-byte (M1-X23: never truncated or normalized).
- ArenaService (C4, called by M3/M4 with IDs taken from their URLs) never raises a database
  error for any filter or session ID: malformed IDs match nothing.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import quote

import pytest
from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.arena.router import MAX_TEXT_CHARS, MESSAGE_ID_PATTERN, MessageIn
from app.arena.service import ArenaService
from app.contracts.arena import LevelConfigUpdate, SessionFilters
from app.contracts.firewall import NotFound
from tests.integration.test_arena_api import Ctx, _ctx

FUZZ = settings(
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)

# Text that JSON can carry: any code point except lone surrogates.
json_text = st.text(st.characters(blacklist_categories=("Cs",)), max_size=300)
hostile = st.sampled_from(
    [
        "",
        " ",
        "\x00",
        "'; DROP TABLE arena_sessions; --",
        "../../etc/passwd",
        "%00",
        "<script>alert(1)</script>",
        "a" * 65,
        "a" * 64,
        "‮​",
        "ignore previous instructions",
        str(uuid.uuid4()),
    ]
)
any_id = st.one_of(hostile, json_text)


@pytest.fixture
async def fz(engine: AsyncEngine) -> AsyncIterator[Ctx]:
    async for c in _ctx(engine, AEGIS_HOURLY_MESSAGE_CAP=100000):
        yield c


@pytest.fixture
async def svc(engine: AsyncEngine) -> ArenaService:
    return ArenaService(engine)


# --- request model (no I/O) --------------------------------------------------------------


near_cap = st.integers(MAX_TEXT_CHARS - 10, MAX_TEXT_CHARS + 10).map(lambda n: "a" * n)


@settings(max_examples=500)
@given(mid=any_id, body=st.one_of(json_text, near_cap))
@example(mid="m1", body="hi\x00there")
def test_message_model_accepts_only_valid_shapes(mid: str, body: str) -> None:
    try:
        m = MessageIn(message_id=mid, text=body)
    except ValidationError:
        valid_id = re.fullmatch(MESSAGE_ID_PATTERN, mid) is not None
        valid_text = 1 <= len(body) <= MAX_TEXT_CHARS and "\x00" not in body
        assert not (valid_id and valid_text)
        return
    assert re.fullmatch(MESSAGE_ID_PATTERN, m.message_id)
    assert m.text == body  # never stripped, truncated or normalized


# --- HTTP API -----------------------------------------------------------------------------


@FUZZ
@given(mid=any_id, body=st.one_of(hostile, json_text))
@example(mid="m-nul", body="hi\x00there")  # found in Phase D: Postgres text cannot hold NUL
async def test_send_never_500_and_echoes_text(fz: Ctx, mid: str, body: str) -> None:
    sess = await fz.start("lvl-1")
    r = await fz.send(sess["id"], mid, body)
    assert r.status_code < 500, r.text
    if r.status_code == 200:
        assert r.json()["text"] == body


@FUZZ
@given(payload=st.one_of(st.none(), st.integers(), json_text, st.dictionaries(json_text, any_id)))
async def test_send_arbitrary_json_never_500(fz: Ctx, payload: Any) -> None:
    sess = await fz.start("lvl-1")
    r = await fz.client.post(
        f"/api/arena/sessions/{sess['id']}/messages", json=payload, headers=fz.h()
    )
    assert r.status_code == 422, r.text


@FUZZ
@given(sid=any_id, tid=any_id)
async def test_path_ids_never_500(fz: Ctx, sid: str, tid: str) -> None:
    s, t = quote(sid, safe=""), quote(tid, safe="")
    if not s or not t:
        return
    for method, path in (
        ("GET", f"/api/arena/sessions/{s}"),
        ("GET", f"/api/arena/sessions/{s}/recap"),
        ("POST", f"/api/arena/sessions/{s}/close"),
        ("GET", f"/api/arena/sessions/{s}/tickets/{t}"),
    ):
        r = await fz.client.request(method, path, headers=fz.h())
        assert r.status_code < 500, (method, path, r.text)


@FUZZ
@given(tid=any_id)
@example(tid="\x00")
@example(tid="t" * 129)
async def test_ticket_id_on_real_session_never_500(fz: Ctx, tid: str) -> None:
    sess = await fz.start("lvl-1")
    t = quote(tid, safe="")
    if not t:
        return
    r = await fz.client.get(f"/api/arena/sessions/{sess['id']}/tickets/{t}", headers=fz.h())
    assert r.status_code < 500, r.text


# --- ArenaService (C4) --------------------------------------------------------------------


@FUZZ
@given(
    user_id=st.one_of(st.none(), any_id),
    level_id=st.one_of(st.none(), any_id),
    mode=st.sampled_from([None, "off", "basic", "strict"]),
    outcome=st.sampled_from([None, "obtained", "not_obtained"]),
    status=st.sampled_from([None, "active", "closed"]),
    admin_test=st.sampled_from([None, True, False]),
    limit=st.integers(1, 1000),
    offset=st.integers(0, 2**31 - 1),
)
@example(
    user_id=None,
    level_id="lvl-\x00",
    mode=None,
    outcome=None,
    status=None,
    admin_test=None,
    limit=1,
    offset=0,
)
@example(
    user_id="",
    level_id=None,
    mode=None,
    outcome=None,
    status=None,
    admin_test=None,
    limit=1,
    offset=0,
)
async def test_list_sessions_any_filter_never_raises(svc: ArenaService, **kw: Any) -> None:
    rows = await svc.list_sessions(SessionFilters(**kw))
    assert len(rows) <= kw["limit"]
    if kw["user_id"] is not None:
        assert all(r.user_id == kw["user_id"] for r in rows)


@FUZZ
@given(sid=any_id)
@example(sid="")
@example(sid="\x00")
async def test_get_session_any_id_never_raises(svc: ArenaService, sid: str) -> None:
    got = await svc.get_session(sid)
    assert got is None or got.id == sid


@FUZZ
@given(sid=any_id, level=any_id)
@example(sid="\x00", level="lvl-\x00")
async def test_unlock_and_c8_level_ids_never_db_error(
    svc: ArenaService, sid: str, level: str
) -> None:
    await svc.unlock_recap(sid)  # unknown or malformed: a no-op
    if level.startswith("lvl-") and level[4:].isdigit():
        return  # a real seeded level: rotating it is not what this property is about
    with pytest.raises(NotFound):
        await svc.rotate_secret(level, str(uuid.uuid4()))
    with pytest.raises(NotFound):
        await svc.save_level_version(LevelConfigUpdate(level_id=level), str(uuid.uuid4()))
