"""Draft and risky-pattern decisions for the admin console (M3 C-06, C-07; PRD §7.5, §10.3).

Never automatic: every change here is an admin action. Each one runs in one transaction with its
`record_audit` row (M3-X40). Validation re-runs on every edit and again at approval, never trusting
a stored `pending` (M3-X31). Every pattern approval and retirement takes the next version from
the `risky_pattern_versions` ledger, whose primary key issues each version once; a race is a
unique violation and becomes `Conflict` (409, M3-X33).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.contracts.firewall_admin import FirewallAdminPort, RuleForm
from app.contracts.fixtures import FixtureToolCall
from app.db.audit import record_audit
from app.firewall.risky_history import VERSION_SQL
from app.firewall.risky_patterns import PatternSpec, validate_for_approval
from app.workers.drafts import Benign, validate_draft

DRAFT_STATUSES = frozenset({"pending", "failed_validation", "approved", "rejected"})
PATTERN_STATUSES = frozenset({"candidate", "approved", "rejected", "retired"})
LIST_LIMIT = 500
_JSON_FIELDS = frozenset({"body", "validation"})
# Column names `_set_draft` may write; never caller input (the SQL is built from these keys).
_DRAFT_FIELDS = frozenset({"body", "validation", "status", "result_ref", "cluster_id"})


class DecisionError(Exception):
    pass


class Missing(DecisionError):
    """Unknown draft or pattern (404)."""


class Conflict(DecisionError):
    """Not in a state that allows this action, or a concurrent decision won (409)."""


class Invalid(DecisionError):
    """Validation or the approval checks failed (422)."""

    def __init__(self, reasons: list[str]) -> None:
        super().__init__("; ".join(reasons))
        self.reasons = reasons


_DRAFT_COLS = (
    "draft_id::text AS draft_id, source_event_id, kind, body, status, validation,"
    " cluster_id::text AS cluster_id, result_ref, source, created_at, updated_at, decided_at,"
    " decided_by::text AS decided_by"
)
_PATTERN_COLS = (
    "pattern_id::text AS pattern_id, tool, conditions,"
    " CASE WHEN retired_in_version IS NOT NULL THEN 'retired' ELSE status END AS status,"
    " approved_in_version, retired_in_version, source_event_id, source_args,"
    " source_draft_id::text AS source_draft_id, created_at, decided_at,"
    " decided_by::text AS decided_by"
)
_DRAFT_SQL = f"SELECT {_DRAFT_COLS} FROM drafts WHERE draft_id = CAST(:id AS uuid)"  # noqa: S608
_PATTERN_SQL = (
    f"SELECT {_PATTERN_COLS} FROM risky_tool_patterns"  # noqa: S608 - constant column list
    " WHERE pattern_id = CAST(:id AS uuid)"
)
_LOCK = " FOR UPDATE"


def _uuid_or_missing(value: str) -> str:
    """Path IDs are untrusted: a malformed UUID is simply not found (never a 500)."""
    try:
        return str(uuid.UUID(value))
    except ValueError as exc:
        raise Missing(value) from exc


async def _one(conn: AsyncConnection, sql: str, value: str) -> dict[str, Any]:
    row = (await conn.execute(text(sql), {"id": _uuid_or_missing(value)})).mappings().first()
    if row is None:
        raise Missing(value)
    return dict(row)


def _view(row: dict[str, Any], *keys: str) -> dict[str, Any]:
    return {k: row[k] for k in keys}


async def _issue_version(
    conn: AsyncConnection, pattern_id: str, change: str, admin_id: str | None
) -> int:
    """Next version through the ledger; a concurrent issue of the same number fails the PK."""
    version = int((await conn.execute(VERSION_SQL)).scalar_one()) + 1
    await conn.execute(
        text(
            "INSERT INTO risky_pattern_versions (version, pattern_id, change, created_by)"
            " VALUES (:v, CAST(:p AS uuid), :c, CAST(:a AS uuid))"
        ),
        {"v": version, "p": pattern_id, "c": change, "a": admin_id},
    )
    return version


def _is_race(exc: DBAPIError) -> bool:
    return isinstance(exc, IntegrityError) or "deadlock" in str(exc.orig).lower()


# --- drafts (C-06) ----------------------------------------------------------------------------


async def list_drafts(engine: AsyncEngine, status: str = "pending") -> list[dict[str, Any]]:
    """Pending drafts: one per cluster (the oldest) with the cluster size. Others: every row."""
    if status not in DRAFT_STATUSES:
        raise Invalid([f"unknown status {status!r}"])
    if status == "pending":
        sql = (
            f"SELECT DISTINCT ON (cluster_id) {_DRAFT_COLS},"  # noqa: S608 - constant columns
            " count(*) OVER (PARTITION BY cluster_id) AS cluster_size FROM drafts"
            " WHERE status = 'pending' ORDER BY cluster_id, created_at, draft_id"
            f" LIMIT {LIST_LIMIT}"
        )
    else:
        sql = (
            f"SELECT {_DRAFT_COLS}, 1 AS cluster_size FROM drafts"  # noqa: S608
            f" WHERE status = :s ORDER BY created_at DESC LIMIT {LIST_LIMIT}"
        )
    query = text(sql)  # nosemgrep: avoid-sqlalchemy-text (constant SQL, bound values)
    async with engine.connect() as conn:
        rows = [dict(r) for r in (await conn.execute(query, {"s": status})).mappings()]
    rows = [{**r, "needs_reconcile": _unlinked_rule(r)} for r in rows]
    return sorted(rows, key=lambda r: (-r["cluster_size"], r["created_at"]))


async def get_draft(engine: AsyncEngine, draft_id: str) -> dict[str, Any]:
    async with engine.connect() as conn:
        return await _one(conn, _DRAFT_SQL, draft_id)


async def _set_draft(
    conn: AsyncConnection, draft_id: str, admin_id: str | None, decided: bool, **fields: Any
) -> dict[str, Any]:
    unknown = set(fields) - _DRAFT_FIELDS
    if unknown:
        raise ValueError(f"not a writable draft field: {sorted(unknown)}")
    sets = ", ".join(
        f"{k} = CAST(:{k} AS jsonb)" if k in _JSON_FIELDS else f"{k} = :{k}" for k in fields
    )
    decided_sql = ", decided_at = now(), decided_by = CAST(:admin AS uuid)" if decided else ""
    params = {k: json.dumps(v) if k in _JSON_FIELDS else v for k, v in fields.items()}
    await conn.execute(
        text(  # nosemgrep: avoid-sqlalchemy-text (allowlisted columns, bound values)
            f"UPDATE drafts SET {sets}, updated_at = now(){decided_sql}"  # noqa: S608 - our keys
            " WHERE draft_id = CAST(:id AS uuid)"
        ),
        {**params, "id": draft_id, "admin": admin_id},
    )
    return await _one(conn, _DRAFT_SQL, draft_id)


async def edit_draft(
    engine: AsyncEngine, draft_id: str, body: dict[str, Any], admin_id: str, benign: Benign
) -> dict[str, Any]:
    async with engine.begin() as conn:
        draft = await _one(conn, _DRAFT_SQL + _LOCK, draft_id)
        if draft["status"] not in {"pending", "failed_validation"}:
            raise Conflict(f"draft is {draft['status']}")
        reasons = validate_draft(draft["kind"], body, draft["source"] or {}, benign)
        after = await _set_draft(
            conn,
            draft_id,
            admin_id,
            False,
            body=body,
            validation={"ok": not reasons, "reasons": reasons},
            status="failed_validation" if reasons else "pending",
        )
        if body != draft["body"]:
            # The old embedding and cluster describe the old body (Codex round 7): stand alone
            # under a fresh cluster ID until a recompute; the rest of the old cluster stays.
            await conn.execute(
                text(
                    "UPDATE drafts SET embedding = NULL, cluster_id = gen_random_uuid()"
                    " WHERE draft_id = CAST(:id AS uuid)"
                ),
                {"id": draft_id},
            )
            after = await _one(conn, _DRAFT_SQL, draft_id)
        await record_audit(
            conn,
            actor_id=admin_id,
            entity="draft",
            entity_id=draft_id,
            action="edit",
            before=_view(draft, "status", "body"),
            after=_view(after, "status", "body"),
        )
        return after


async def _approve_pattern_draft(
    conn: AsyncConnection, draft: dict[str, Any], admin_id: str
) -> str:
    source = draft["source"] or {}
    row = await conn.execute(
        text(
            "INSERT INTO risky_tool_patterns (tool, conditions, status, source_event_id,"
            " source_args, source_draft_id) VALUES (:tool, CAST(:c AS jsonb), 'candidate', :e,"
            " CAST(:a AS jsonb), CAST(:d AS uuid)) RETURNING pattern_id::text"
        ),
        {
            "tool": draft["body"]["tool"],
            "c": json.dumps(draft["body"]["conditions"]),
            "e": draft["source_event_id"],
            "a": json.dumps(source.get("canonical_args")),
            "d": draft["draft_id"],
        },
    )
    pattern_id = str(row.scalar_one())
    version = await _issue_version(conn, pattern_id, "approve", admin_id)
    await conn.execute(
        text(
            "UPDATE risky_tool_patterns SET status = 'approved', approved_in_version = :v,"
            " decided_at = now(), decided_by = CAST(:a AS uuid)"
            " WHERE pattern_id = CAST(:p AS uuid)"
        ),
        {"v": version, "a": admin_id, "p": pattern_id},
    )
    await record_audit(
        conn,
        actor_id=admin_id,
        entity="risky_pattern",
        entity_id=pattern_id,
        action="approve",
        before=None,
        after={"status": "approved", "approved_in_version": version, "draft": draft["draft_id"]},
    )
    return pattern_id


async def approve_draft(
    engine: AsyncEngine,
    draft_id: str,
    admin_id: str,
    benign: Benign,
    admin: FirewallAdminPort,
) -> dict[str, Any]:
    """Re-validate (never trusting a stored `pending`, M3-X31), then approve. The draft row lock
    serializes two admins (M3-X33).

    A pattern draft becomes an approved pattern at the next version, all in one transaction.
    A rule draft goes through C6 `create_rule`, which cannot join this transaction, so it is
    two-phase: first the draft is committed as approved (with its audit row), then C6 is called.
    If C6 fails the draft goes back to pending; if anything fails after C6 the draft stays
    approved with no `result_ref` (visible to the admin), so a retry is a 409 and can never
    create a second rule (Codex rounds 1 and 2; an idempotent C6 would close it fully, §10).
    """
    async with engine.begin() as conn:  # recovery of an approval that stopped around C6
        draft = await _one(conn, _DRAFT_SQL + _LOCK, draft_id)
        if _unlinked_rule(draft):
            if datetime.now(UTC) - draft["decided_at"] < RECONCILE_AFTER:
                raise Conflict("approval in progress; retry shortly")
            after, refused = await _reconcile(
                conn, draft, admin_id, admin, benign, action="reconcile"
            )
    if _unlinked_rule(draft):
        if refused:
            raise Invalid(refused)
        return after
    failed: list[str] = []
    try:
        async with engine.begin() as conn:
            draft = await _one(conn, _DRAFT_SQL + _LOCK, draft_id)
            if draft["status"] != "pending":
                raise Conflict(f"draft is {draft['status']}")
            failed = validate_draft(draft["kind"], draft["body"], draft["source"] or {}, benign)
            if failed:
                after = await _set_draft(
                    conn,
                    draft_id,
                    admin_id,
                    False,
                    validation={"ok": False, "reasons": failed},
                    status="failed_validation",
                )
                action = "revalidation_failed"
            else:
                ref = None
                if draft["kind"] == "pattern":
                    ref = await _approve_pattern_draft(conn, draft, admin_id)
                after = await _set_draft(
                    conn, draft_id, admin_id, True, status="approved", result_ref=ref
                )
                action = "approve"
            await record_audit(
                conn,
                actor_id=admin_id,
                entity="draft",
                entity_id=draft_id,
                action=action,
                before=_view(draft, "status"),
                after={**_view(after, "status", "result_ref"), "kind": draft["kind"]},
            )
    except DBAPIError as exc:
        if _is_race(exc):
            raise Conflict("a concurrent decision won; reload and retry") from exc
        raise
    if failed:
        raise Invalid(failed)
    if draft["kind"] != "rule":
        return after
    # Phase two under the row lock again: whoever holds it first creates and links the rule.
    c6_error: Exception | None = None
    refused: list[str] = []
    async with engine.begin() as conn:
        current = await _one(conn, _DRAFT_SQL + _LOCK, draft_id)
        if not _unlinked_rule(current):
            return current
        try:
            after, refused = await _reconcile(conn, current, admin_id, admin, benign, action="link")
        except _C6Failed as exc:  # C6 refused or failed: back to pending, audited
            c6_error = exc.cause
            await _revert_approval(conn, draft_id, admin_id)
    if c6_error is not None:
        raise c6_error
    if refused:
        raise Invalid(refused)
    return after


class _C6Failed(Exception):
    def __init__(self, cause: Exception) -> None:
        super().__init__(str(cause))
        self.cause = cause


RECONCILE_SKEW = timedelta(minutes=1)  # C6 clock vs DB clock
# An unlinked approval younger than this may still be running its C6 call (409 meanwhile).
RECONCILE_AFTER = timedelta(minutes=2)


def _unlinked_rule(draft: dict[str, Any]) -> bool:
    return draft["kind"] == "rule" and draft["status"] == "approved" and not draft["result_ref"]


async def _reconcile(
    conn: AsyncConnection,
    draft: dict[str, Any],
    admin_id: str,
    admin: FirewallAdminPort,
    benign: Benign,
    *,
    action: str,
) -> tuple[dict[str, Any], list[str]]:
    """Approved but unlinked (a crash before or after C6): link the rule C6 already created,
    found by its exact form after the approval time, or create it now. The draft row lock is
    held throughout, so two admins never both create it (Codex round 3)."""
    form = RuleForm.model_validate(draft["body"])
    since = draft["decided_at"] - RECONCILE_SKEW
    made = [
        r
        for r in await admin.list_rules()
        if r.form is not None and r.form == form and r.created_at >= since and not r.deprecated
    ]
    if made:
        rule = max(made, key=lambda r: r.created_at)
    elif reasons := validate_draft("rule", draft["body"], draft["source"] or {}, benign):
        # Fixtures may have changed since phase one: never create a rule that fails now.
        after = await _set_draft(
            conn,
            draft["draft_id"],
            admin_id,
            False,
            validation={"ok": False, "reasons": reasons},
            status="failed_validation",
        )
        await record_audit(
            conn,
            actor_id=admin_id,
            entity="draft",
            entity_id=draft["draft_id"],
            action="revalidation_failed",
            before=_view(draft, "status", "result_ref"),
            after=_view(after, "status", "result_ref"),
        )
        return after, reasons
    else:
        try:
            rule = await admin.create_rule(form, admin_id)
        except Exception as exc:
            raise _C6Failed(exc) from exc
    after = await _link_rule(conn, draft["draft_id"], rule.rule_id)
    await record_audit(
        conn,
        actor_id=admin_id,
        entity="draft",
        entity_id=draft["draft_id"],
        action=action,
        before=_view(draft, "status", "result_ref"),
        after={**_view(after, "status", "result_ref"), "found_existing": bool(made)},
    )
    return after, []


async def _revert_approval(conn: AsyncConnection, draft_id: str, admin_id: str) -> None:
    """C6 refused or failed: the draft goes back to pending, with an audit row."""
    await conn.execute(
        text(
            "UPDATE drafts SET status = 'pending', decided_at = NULL, decided_by = NULL,"
            " updated_at = now() WHERE draft_id = CAST(:id AS uuid) AND status = 'approved'"
            " AND result_ref IS NULL"
        ),
        {"id": draft_id},
    )
    await record_audit(
        conn,
        actor_id=admin_id,
        entity="draft",
        entity_id=draft_id,
        action="approve_reverted",
        before={"status": "approved"},
        after={"status": "pending"},
    )


async def _link_rule(conn: AsyncConnection, draft_id: str, rule_id: str) -> dict[str, Any]:
    await conn.execute(
        text(
            "UPDATE drafts SET result_ref = :r, updated_at = now()"
            " WHERE draft_id = CAST(:id AS uuid)"
        ),
        {"r": rule_id, "id": draft_id},
    )
    return await _one(conn, _DRAFT_SQL, draft_id)


async def reject_draft(engine: AsyncEngine, draft_id: str, admin_id: str) -> dict[str, Any]:
    async with engine.begin() as conn:
        draft = await _one(conn, _DRAFT_SQL + _LOCK, draft_id)
        if draft["status"] not in {"pending", "failed_validation"}:
            raise Conflict(f"draft is {draft['status']}")
        after = await _set_draft(conn, draft_id, admin_id, True, status="rejected")
        await record_audit(
            conn,
            actor_id=admin_id,
            entity="draft",
            entity_id=draft_id,
            action="reject",
            before=_view(draft, "status"),
            after=_view(after, "status"),
        )
        return after


# --- risky patterns (C-07) --------------------------------------------------------------------


async def list_patterns(engine: AsyncEngine, status: str | None = None) -> list[dict[str, Any]]:
    if status is not None and status not in PATTERN_STATUSES:
        raise Invalid([f"unknown status {status!r}"])
    sql = (
        f"SELECT * FROM (SELECT {_PATTERN_COLS} FROM risky_tool_patterns) p"  # noqa: S608
        " WHERE CAST(:s AS text) IS NULL OR status = CAST(:s AS text)"
        f" ORDER BY created_at DESC LIMIT {LIST_LIMIT}"
    )
    query = text(sql)  # nosemgrep: avoid-sqlalchemy-text (constant SQL, bound values)
    async with engine.connect() as conn:
        return [dict(r) for r in (await conn.execute(query, {"s": status})).mappings()]


def _pattern_reasons(pattern: dict[str, Any], benign: Benign) -> list[str]:
    spec = PatternSpec.model_validate(
        {"tool": pattern["tool"], "conditions": pattern["conditions"]}
    )
    if pattern["source_args"] is None:
        return ["pattern has no original call to check against"]
    original = FixtureToolCall(tool=pattern["tool"], arguments=pattern["source_args"])
    return validate_for_approval(spec, original, benign.calls)


async def check_pattern(engine: AsyncEngine, pattern_id: str, benign: Benign) -> list[str]:
    """The three approval checks (PRD §7.5) plus RE2, for the editor to show pass or fail."""
    async with engine.connect() as conn:
        return _pattern_reasons(await _one(conn, _PATTERN_SQL, pattern_id), benign)


async def edit_pattern(
    engine: AsyncEngine, pattern_id: str, conditions: list[dict[str, Any]], admin_id: str
) -> dict[str, Any]:
    async with engine.begin() as conn:
        before = await _one(conn, _PATTERN_SQL + _LOCK, pattern_id)
        if before["status"] != "candidate":
            raise Conflict(f"pattern is {before['status']}; only candidates are edited")
        await conn.execute(
            text(
                "UPDATE risky_tool_patterns SET conditions = CAST(:c AS jsonb)"
                " WHERE pattern_id = CAST(:p AS uuid)"
            ),
            {"c": json.dumps(conditions), "p": pattern_id},
        )
        after = await _one(conn, _PATTERN_SQL, pattern_id)
        await record_audit(
            conn,
            actor_id=admin_id,
            entity="risky_pattern",
            entity_id=pattern_id,
            action="edit",
            before=_view(before, "status", "conditions"),
            after=_view(after, "status", "conditions"),
        )
        return after


_PATTERN_SETS = {
    "approve": "status = 'approved', approved_in_version = :v",
    "retire": "retired_in_version = :v",
    "reject": "status = 'rejected'",
}
_VERSIONS = ("status", "approved_in_version", "retired_in_version")


async def _decide_pattern(
    engine: AsyncEngine,
    pattern_id: str,
    admin_id: str | None,
    *,
    action: str,
    allowed_from: str,
    benign: Benign | None = None,
) -> dict[str, Any]:
    try:
        async with engine.begin() as conn:
            before = await _one(conn, _PATTERN_SQL + _LOCK, pattern_id)
            if before["status"] != allowed_from:
                raise Conflict(f"pattern is {before['status']}")
            if benign is not None and (reasons := _pattern_reasons(before, benign)):
                raise Invalid(reasons)
            params: dict[str, Any] = {"a": admin_id, "p": pattern_id}
            if action in {"approve", "retire"}:
                params["v"] = await _issue_version(conn, pattern_id, action, admin_id)
            await conn.execute(
                text(  # nosemgrep: avoid-sqlalchemy-text (constant SET clause)
                    f"UPDATE risky_tool_patterns SET {_PATTERN_SETS[action]},"  # noqa: S608
                    " decided_at = now(), decided_by = CAST(:a AS uuid)"
                    " WHERE pattern_id = CAST(:p AS uuid)"
                ),
                params,
            )
            after = await _one(conn, _PATTERN_SQL, pattern_id)
            await record_audit(
                conn,
                actor_id=admin_id,
                entity="risky_pattern",
                entity_id=pattern_id,
                action=action,
                before=_view(before, *_VERSIONS),
                after=_view(after, *_VERSIONS),
            )
            return after
    except DBAPIError as exc:
        if _is_race(exc):
            raise Conflict("a concurrent decision took this version; reload and retry") from exc
        raise


async def approve_pattern(
    engine: AsyncEngine, pattern_id: str, admin_id: str | None, benign: Benign
) -> dict[str, Any]:
    return await _decide_pattern(
        engine, pattern_id, admin_id, action="approve", allowed_from="candidate", benign=benign
    )


async def reject_pattern(
    engine: AsyncEngine, pattern_id: str, admin_id: str | None
) -> dict[str, Any]:
    return await _decide_pattern(
        engine, pattern_id, admin_id, action="reject", allowed_from="candidate"
    )


async def retire_pattern(
    engine: AsyncEngine, pattern_id: str, admin_id: str | None
) -> dict[str, Any]:
    return await _decide_pattern(
        engine, pattern_id, admin_id, action="retire", allowed_from="approved"
    )
