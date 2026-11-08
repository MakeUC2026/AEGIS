"""M2 B-03 event writer (spec AEGIS-DOM-107; PRD §10.1, §10.2).

Cases: M2-X46 (shadow only in Off, nulls kept), M2-X47 (Basic allow: no forensics, no
NOTIFY), M2-X48 (Off allow that delivered the secret: pending plus NOTIFY), and atomicity
with the turn (PRD §15.1).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from types import MappingProxyType
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.firewall.events import EventRow, forensic_status_for, insert_event, row_from_decision
from app.firewall.gatekeeper import GateInput, decide
from app.firewall.leak import LeakMatch
from app.firewall.rules import Evaluation, RuleHit
from app.firewall.sentinel_l1 import Layer1Result

STRICT = MappingProxyType({"review": 30, "deny": 60, "divert": 95, "alert": 99})


async def _user(engine: AsyncEngine) -> str:
    async with engine.begin() as conn:
        row = await conn.execute(
            text("INSERT INTO users (auth0_sub, role) VALUES ('auth0|ev', 'student') RETURNING id")
        )
        return str(row.scalar_one())


def _row(user_id: str, **over: Any) -> EventRow:
    base: dict[str, Any] = {
        "fw_session_id": "fws-1",
        "user_id": user_id,
        "message_id": "m1",
        "manifest_id": "man-1",
        "level_id": "lvl-2",
        "mode": "basic",
        "stage": "tool_call_check",
        "source_trust": "bot_output",
        "decision": "deny",
        "execution_status": "not_executed",
        "sentinel_score": 75,
        "score_breakdown": {"R-003": 0, "high_risk_tool": 15, "judge": None},
        "thresholds_used": dict(STRICT),
        "rule_ids": ("R-003",),
        "tool": "send_email",
        "call_id": "c1",
        "args_hash": "sha256:" + "0" * 64,
    }
    return EventRow(**{**base, **over})


async def _fetch(engine: AsyncEngine, event_id: str) -> dict[str, Any] | None:
    async with engine.connect() as conn:
        row = (
            await conn.execute(text("SELECT * FROM fw_events WHERE event_id = :e"), {"e": event_id})
        ).first()
    return dict(row._mapping) if row else None


async def _listening(engine: AsyncEngine, action: Callable[[], Awaitable[None]]) -> list[str]:
    received: list[str] = []

    def on_notify(*args: Any) -> None:
        received.append(args[-1])

    async with engine.connect() as conn:
        raw = (await conn.get_raw_connection()).driver_connection
        await raw.add_listener("fw_events_forensic", on_notify)
        try:
            await action()
            for _ in range(10):
                await asyncio.sleep(0.05)
        finally:
            await raw.remove_listener("fw_events_forensic", on_notify)
    return received


# --- Forensic selection (PRD §10.2) -----------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "decision", "shadow", "delivered", "expected"),
    [
        ("basic", "allow", None, False, None),  # M2-X47
        ("basic", "review", None, False, None),
        ("basic", "deny", None, False, "pending"),
        ("strict", "divert", None, False, "pending"),
        ("strict", "human_deny", None, False, "pending"),
        ("off", "allow", "deny", False, "pending"),  # shadow deny counts
        ("off", "allow", "allow", True, "pending"),  # M2-X48: Off leak
        ("off", "allow", "allow", False, None),
        ("off", "allow", "review", False, None),
    ],
)
def test_forensic_selection(
    mode: str, decision: str, shadow: str | None, delivered: bool, expected: str | None
) -> None:
    row = _row(
        "u",
        mode=mode,
        decision=decision,
        shadow_decision=shadow,
        secret_delivered=delivered,
    )
    assert forensic_status_for(row) == expected


def test_shadow_decision_outside_off_is_refused() -> None:
    with pytest.raises(ValueError, match="Off"):
        _row("u", mode="basic", shadow_decision="deny")


def test_event_ids_are_unique_and_prefixed() -> None:
    a, b = _row("u"), _row("u")
    assert a.event_id != b.event_id and a.event_id.startswith("evt-")


# --- Writing ------------------------------------------------------------------------------------


async def test_a_deny_row_is_stored_with_nulls_kept(engine: AsyncEngine) -> None:
    uid = await _user(engine)
    row = _row(uid)
    async with engine.begin() as conn:
        assert await insert_event(conn, row) == row.event_id
    stored = await _fetch(engine, row.event_id)
    assert stored is not None
    assert (stored["decision"], stored["forensic_status"], stored["shadow_decision"]) == (
        "deny", "pending", None,
    )  # fmt: skip
    breakdown = stored["score_breakdown"]
    breakdown = json.loads(breakdown) if isinstance(breakdown, str) else breakdown
    assert breakdown == {"R-003": 0, "high_risk_tool": 15, "judge": None}  # null, never 0
    assert stored["rule_ids_fired"] == ["R-003"]
    assert stored["judge_risk"] is None


async def test_notify_only_for_forensic_rows_and_only_on_commit(engine: AsyncEngine) -> None:
    uid = await _user(engine)
    allow, deny = _row(uid, decision="allow", sentinel_score=5), _row(uid)

    async def write_both() -> None:
        async with engine.begin() as conn:
            await insert_event(conn, allow)
            await insert_event(conn, deny)

    assert await _listening(engine, write_both) == [deny.event_id]


async def test_event_rolls_back_with_the_turn(engine: AsyncEngine) -> None:
    uid = await _user(engine)
    row = _row(uid)

    async def failed_turn() -> None:
        with pytest.raises(RuntimeError):
            async with engine.begin() as conn:
                await insert_event(conn, row)
                raise RuntimeError("tool effect failed")

    assert await _listening(engine, failed_turn) == []
    assert await _fetch(engine, row.event_id) is None


# --- From a Gatekeeper decision (PRD §6.5 step 1) ---------------------------------------------


async def test_row_from_the_off_demo_decision(engine: AsyncEngine) -> None:
    uid = await _user(engine)
    gate = decide(
        GateInput(
            mode="off",
            thresholds=STRICT,
            divert_enabled=False,
            layer1=Layer1Result(score=25, breakdown=MappingProxyType({"high_risk_tool": 15})),
            rules=Evaluation((RuleHit("R-003", 1, "deny", None, None),), (), 0.0),
            leak=LeakMatch("exact"),
        )
    )
    row = row_from_decision(
        gate,
        thresholds=STRICT,
        fw_session_id="fws-1",
        user_id=uid,
        message_id="m1",
        manifest_id="man-1",
        level_id="lvl-1",
        mode="off",
        stage="tool_call_check",
        source_trust="bot_output",
        execution_status="executed",
        secret_attempted=True,
        secret_delivered=True,
    )
    assert (row.decision, row.shadow_decision, row.rule_ids) == ("allow", "deny", ("R-003", "B-01"))
    async with engine.begin() as conn:
        await insert_event(conn, row)
    stored = await _fetch(engine, row.event_id)
    assert stored is not None
    assert (stored["decision"], stored["shadow_decision"], stored["forensic_status"]) == (
        "allow", "deny", "pending",
    )  # fmt: skip
