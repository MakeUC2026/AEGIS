"""Mock tool execution on the database (M2 B-05; PRD §7.6, §15.1; spec AEGIS-DOM-109).

`execute_tool` runs on the caller's transaction:
1. lock the session's mock state row (calls on one session queue up);
2. if the `call_id` is already recorded, replay its stored result: it never executes twice;
3. otherwise run the pure tool, save any changed state, and record the call.
A failure later in the turn rolls back the state change, the record and the event together.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

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
_RECORDED = (
    "SELECT tool, result, canonical_args FROM fw_tool_calls"
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


async def execute_tool(
    conn: AsyncConnection, fw_session_id: str, message_id: str, call: CanonicalCall
) -> Executed:
    state = await load_state(conn, fw_session_id, lock=True)
    recorded = (
        await conn.execute(text(_RECORDED), {"sid": fw_session_id, "cid": call.call_id})
    ).first()
    if recorded is not None:
        r = recorded._mapping
        args = _json(r["canonical_args"]) or {}
        return Executed(r["result"] or "", _replayed_visibility(state, r["tool"], args), True)
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
    return Executed(outcome.result, outcome.visible_content, False)
