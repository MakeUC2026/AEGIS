"""Mock tool execution on the database (M2 B-05; PRD §7.6, §15.1; spec AEGIS-DOM-109).

`execute_tool` runs on the caller's transaction:
1. lock the session's mock state row (calls on one session queue up);
2. a closed session runs nothing (`SessionClosed`; the session row is share-locked, so a
   concurrent close waits for this transaction or wins before it starts);
3. if the `call_id` is already recorded for the same tool and arguments, replay its stored
   result: it never executes twice. A recorded call with different content (a retry where
   the model proposed something else) is not replayed: the new call runs under an ID
   derived from its own content (M2-DD-36);
4. otherwise run the pure tool, save any changed state, and record the call.
A failure later in the turn rolls back the state change, the record and the event together.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from app.contracts.firewall import SessionClosed
from app.firewall.canonical import CanonicalCall
from app.firewall.mock_tools import MockState, run_tool, visible_mail

_LOCK_STATE = (
    "SELECT documents, emails, db_rows, filesystem, attacker_mailbox, allowlist_domains"
    " FROM fw_mock_state WHERE fw_session_id = :sid FOR UPDATE"
)
_READ_STATE = (
    "SELECT documents, emails, db_rows, filesystem, attacker_mailbox, allowlist_domains"
    " FROM fw_mock_state WHERE fw_session_id = :sid"
)
_SESSION_STATUS = "SELECT status FROM fw_sessions WHERE fw_session_id = :sid FOR SHARE"
_RECORDED = (
    "SELECT tool, args_hash, result, canonical_args FROM fw_tool_calls"
    " WHERE fw_session_id = :sid AND call_id = :cid"
)
_SAVE_STATE = (
    "UPDATE fw_mock_state SET documents = CAST(:documents AS jsonb),"
    " emails = CAST(:emails AS jsonb), filesystem = CAST(:filesystem AS jsonb),"
    " updated_at = now() WHERE fw_session_id = :sid"
)
_RECORD = (
    "INSERT INTO fw_tool_calls (fw_session_id, call_id, message_id, tool, args_hash,"
    " canonical_args, state, result) VALUES (:sid, :cid, :mid, :tool, :args_hash,"
    " CAST(:args AS jsonb), 'executed', :result)"
)


@dataclass(frozen=True)
class Executed:
    result: str
    visible_content: str | None
    replayed: bool
    call_id: str = ""  # the ID the call ran (or replayed) under


def _json(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


async def load_state(conn: AsyncConnection, fw_session_id: str, lock: bool = False) -> MockState:
    row = (
        await conn.execute(text(_LOCK_STATE if lock else _READ_STATE), {"sid": fw_session_id})
    ).first()
    if row is None:
        raise LookupError(f"no mock state for session {fw_session_id}")
    m = row._mapping
    return MockState.from_parts(
        documents=_json(m["documents"]),
        emails=_json(m["emails"]),
        db_rows=_json(m["db_rows"]),
        filesystem=_json(m["filesystem"]),
        attacker_mailbox=m["attacker_mailbox"],
        allowlist_domains=list(m["allowlist_domains"]),
    )


def _replayed_visibility(state: MockState, tool: str, args: dict[str, Any]) -> str | None:
    if tool != "send_email":
        return None
    recipients = tuple(a for a in str(args.get("to", "")).split(", ") if a)
    return visible_mail(state, recipients, str(args.get("subject", "")), str(args.get("body", "")))


def derived_call_id(call: CanonicalCall) -> str:
    return f"{call.call_id}-{call.args_hash[-12:]}"


async def _recorded(conn: AsyncConnection, fw_session_id: str, call_id: str) -> Any:
    row = (await conn.execute(text(_RECORDED), {"sid": fw_session_id, "cid": call_id})).first()
    return None if row is None else row._mapping


async def execute_tool(
    conn: AsyncConnection, fw_session_id: str, message_id: str, call: CanonicalCall
) -> Executed:
    status = (
        await conn.execute(text(_SESSION_STATUS), {"sid": fw_session_id})
    ).scalar_one_or_none()
    if status is None:
        raise LookupError(f"no session {fw_session_id}")
    if status == "closed":
        raise SessionClosed("session is closed; no tool runs")
    state = await load_state(conn, fw_session_id, lock=True)
    recorded = await _recorded(conn, fw_session_id, call.call_id)
    if recorded is not None and recorded["args_hash"] != call.args_hash:
        call = replace(call, call_id=derived_call_id(call))
        recorded = await _recorded(conn, fw_session_id, call.call_id)
    if recorded is not None:
        args = _json(recorded["canonical_args"]) or {}
        visible = _replayed_visibility(state, recorded["tool"], args)
        return Executed(recorded["result"] or "", visible, True, call.call_id)
    outcome = run_tool(state, call)
    if outcome.changed:
        new = outcome.state
        await conn.execute(
            text(_SAVE_STATE),
            {
                "sid": fw_session_id,
                "documents": json.dumps([dict(d) for d in new.documents]),
                "emails": json.dumps([dict(e) for e in new.emails]),
                "filesystem": json.dumps(dict(new.filesystem)),
            },
        )
    await conn.execute(
        text(_RECORD),
        {
            "sid": fw_session_id,
            "cid": call.call_id,
            "mid": message_id,
            "tool": call.tool,
            "args_hash": call.args_hash,
            "args": json.dumps(dict(call.args)),
            "result": outcome.result,
        },
    )
    return Executed(outcome.result, outcome.visible_content, False, call.call_id)
