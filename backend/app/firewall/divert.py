"""The divert transaction (M2 C-05; PRD §8.4; E-45; M2-X41 to X43; spec AEGIS-DOM-120).

The decoy is made before this runs (`decoys.make_decoy`). Then, on the caller's transaction,
in order: the trace-back row, the divert event (`decision: divert`, `execution_status:
diverted`, linked to the trace-back row), the risky-behaviour record (C7
`record_behavior(action="divert")`), the call record (`state: diverted`, `is_decoy`, the decoy
as its result) and, for `send_email`, the decoy mail in mock state (`is_decoy: true`). Any
failure rolls all of it back; the caller then blocks the turn. The real tool is never run.

A retry of a message whose divert already committed finds the call record (same tool and
arguments) and replays the stored decoy: no new rows. A recorded call that is not a divert,
or a different one, is not replayed here: the caller fails closed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from app.contracts.common import ClientMeta
from app.contracts.sentinel import RiskyBehaviorRecord, RiskyHistoryPort
from app.firewall.canonical import CanonicalCall
from app.firewall.decoys import Decoy
from app.firewall.events import EventRow, insert_event
from app.firewall.mock_tools import ASSISTANT_ADDRESS
from app.firewall.tool_exec import derived_call_id
from app.firewall.trace_back import insert_trace_back, new_trace_id

_RECORDED = (
    "SELECT args_hash, state, result FROM fw_tool_calls"
    " WHERE fw_session_id = :sid AND call_id = :cid"
)
_RECORD = (
    "INSERT INTO fw_tool_calls (fw_session_id, call_id, message_id, tool, args_hash,"
    " canonical_args, state, result, is_decoy) VALUES (:sid, :cid, :mid, :tool, :args_hash,"
    " CAST(:args AS jsonb), 'diverted', :result, true)"
)
_ADD_MAIL = (
    "UPDATE fw_mock_state SET emails = emails || CAST(:mail AS jsonb), updated_at = now()"
    " WHERE fw_session_id = :sid RETURNING attacker_mailbox"
)
_MAILBOX = "SELECT attacker_mailbox, emails FROM fw_mock_state WHERE fw_session_id = :sid"


class DivertRefused(Exception):
    """The call cannot be diverted here (a different record exists); the caller blocks."""


@dataclass(frozen=True)
class Diverted:
    call_id: str
    result: str
    visible_content: str | None  # the decoy mail, when it went to the attacker mailbox
    replayed: bool
    event_id: str | None  # None when replayed


def _json(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


def _visible(mail: dict[str, Any], attacker_mailbox: str) -> str | None:
    recipients = tuple(str(r).lower() for r in mail["to"])
    if attacker_mailbox.lower() not in recipients:
        return None
    return f"To: {', '.join(mail['to'])}\nSubject: {mail['subject']}\n\n{mail['body']}"


def _decoy_mail(call: CanonicalCall, call_id: str, decoy: Decoy) -> dict[str, Any] | None:
    if call.tool != "send_email":
        return None
    return {
        "sender": ASSISTANT_ADDRESS,
        "to": list(call.recipients),
        "subject": decoy.mail_subject or "Delivery confirmation",
        "body": decoy.mail_body or "Your message was accepted for delivery.",
        "is_decoy": True,
        "call_id": call_id,
    }


async def _replay(conn: AsyncConnection, sid: str, call_id: str, result: str) -> Diverted:
    row = (await conn.execute(text(_MAILBOX), {"sid": sid})).mappings().first()
    visible = None
    if row is not None:
        for mail in _json(row["emails"]):
            if mail.get("is_decoy") and mail.get("call_id") == call_id:
                visible = _visible(mail, row["attacker_mailbox"])
    return Diverted(call_id, result, visible, True, None)


async def divert_call(
    conn: AsyncConnection,
    *,
    event: EventRow,
    call: CanonicalCall,
    decoy: Decoy,
    client: ClientMeta,
    student_message: str,
    risky: RiskyHistoryPort | None,
    now: datetime,
) -> Diverted:
    sid, call_id = event.fw_session_id, call.call_id
    recorded = (
        (await conn.execute(text(_RECORDED), {"sid": sid, "cid": call_id})).mappings().first()
    )
    if recorded is not None and recorded["args_hash"] != call.args_hash:
        call = replace(call, call_id=derived_call_id(call))  # a retry that proposed another call
        call_id = call.call_id
        recorded = (
            (await conn.execute(text(_RECORDED), {"sid": sid, "cid": call_id})).mappings().first()
        )
    if recorded is not None:
        if recorded["state"] != "diverted":
            raise DivertRefused("the call was already recorded as " + str(recorded["state"]))
        return await _replay(conn, sid, call_id, recorded["result"] or "")

    trace_id = new_trace_id()
    event = replace(event, call_id=call_id, trace_back_id=trace_id)
    await insert_trace_back(
        conn,
        trace_id=trace_id,
        user_id=event.user_id,
        fw_session_id=sid,
        event_id=event.event_id,
        client=client,
        tool=call.tool,
    )
    await insert_event(conn, event)
    if risky is not None:
        await risky.record_behavior(
            RiskyBehaviorRecord(
                time=now,
                user_id=event.user_id,
                fw_session_id=sid,
                event_id=event.event_id,
                stage=event.stage,
                tool=call.tool,
                args_hash=call.args_hash,
                action="divert",
                sentinel_score=event.sentinel_score,
                rule_ids=list(event.rule_ids),
                input_text=student_message,
                trace_id=trace_id,
                shadow=False,
            ),
            conn,
        )
    await conn.execute(
        text(_RECORD),
        {
            "sid": sid,
            "cid": call_id,
            "mid": event.message_id,
            "tool": call.tool,
            "args_hash": call.args_hash,
            "args": json.dumps(dict(call.args)),
            "result": decoy.result,
        },
    )
    mail = _decoy_mail(call, call_id, decoy)
    visible = None
    if mail is not None:
        mailbox = (
            await conn.execute(text(_ADD_MAIL), {"sid": sid, "mail": json.dumps(mail)})
        ).scalar_one()
        visible = _visible(mail, mailbox)
    return Diverted(call_id, decoy.result, visible, False, event.event_id)
