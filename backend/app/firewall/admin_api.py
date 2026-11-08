"""C6: the AFF admin API for the firewall console (M2 C-12; PRD §8.3, §9.1, §11, §12.4;
spec AEGIS-DOM-127).

`AdminApi` implements `FirewallAdminPort`. M3's admin router calls it after its own role check
(firewall_admin); this layer trusts the `admin_id` it is given and never exposes a student view.

- **Rules** are versioned, never edited or deleted. Each write opens a new rule set and adds one
  row to `rules` (`set_version` = the new set), so a session, which pins its rule set at
  registration, keeps the rules it started with. A new rule takes the next `R-nnn`; update and
  deprecate add a version; the built-in switch (B-01, B-02, B-04) adds a version with `enabled`
  changed. Rule writes are serialized by an advisory lock so set numbers and IDs never clash.
  A form is checked before anything is written (RE2 patterns compile, values fit the operator).
- **Tickets**: the queue (what an admin needs to decide, with the secret redacted) and
  `decide_ticket`, which continues or denies the held item through `tickets.decide_ticket`.
- **Events, diverts and trace-back**: admin-only views. Network fields appear as the stored hash,
  subnet and ASN, never the raw address; the judge's reason is shown, with the secret redacted.
- **Every write calls `record_audit` on its own transaction**: if the audit fails the change
  does not happen (PRD §15.1).
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import re2
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.config import get_settings
from app.contracts.firewall import NotFound
from app.contracts.firewall_admin import (
    ConflictError,
    DivertAdminItem,
    EventFilter,
    EventRow,
    RuleDef,
    RuleForm,
    TicketDecision,
    TicketQueueItem,
    TraceBack,
)
from app.contracts.sentinel import JudgePort, RiskyHistoryPort
from app.db.audit import record_audit
from app.db.engine import make_engine
from app.firewall.context import rule_from_row, rules_at
from app.firewall.decoys import DecoyGenerator
from app.firewall.interface import build_decoys, build_llm
from app.firewall.read_api import FirewallRead
from app.firewall.redact import redact_secret
from app.firewall.tickets import decide_ticket, expire_due
from app.firewall.trace_back import purge_expired_trace_back
from app.llm.base import ChatModel

RULE_LOCK_KEY = 7_311_001  # serializes rule writes (set numbers and R-nnn IDs)
MAX_REGEX_CHARS = 1000
MAX_LIST_ITEMS = 200
MAX_ITEM_CHARS = 300
MAX_NOTE_CHARS = 500
MAX_RULE_NUMBER = 999  # the rules table allows R-000 to R-999
SWITCHABLE_BUILTINS = ("B-01", "B-02", "B-04")  # B-03 is part of the canonical call form

_LIST_OPERATORS = frozenset({"in_list", "domain_in", "domain_not_in"})
_NUMERIC_OPERATORS = frozenset({"greater_than", "less_than"})
_NO_VALUE_OPERATORS = frozenset({"inside_workspace", "outside_workspace"})
_COUNT_CHECKS = frozenset({"turn_count", "earlier_denies"})

_LOCK = "SELECT pg_advisory_xact_lock(:key)"
_LATEST_SET = "SELECT coalesce(max(version), 0) FROM rule_sets"
_OPEN_SET = "INSERT INTO rule_sets (version, note) VALUES (:version, :note)"
_NEXT_NUMBER = (
    "SELECT coalesce(max(CAST(substring(rule_id FROM 3) AS int)), 0) + 1"
    " FROM rules WHERE rule_id LIKE 'R-%'"
)
_CURRENT = (
    "SELECT rule_id, version, set_version, builtin, enabled, deprecated, form, created_at,"
    " created_by FROM rules WHERE rule_id = :rule_id ORDER BY version DESC LIMIT 1"
)
_INSERT_RULE = (
    "INSERT INTO rules (rule_id, version, set_version, builtin, enabled, deprecated, form,"
    " created_by) VALUES (:rule_id, :version, :set_version, :builtin, :enabled, :deprecated,"
    " CAST(:form AS jsonb), CAST(:admin AS uuid))"
    " RETURNING rule_id, version, builtin, enabled, deprecated, form, created_at, created_by"
)
_QUEUE = (
    "SELECT t.ticket_id, t.fw_session_id, CAST(s.owner_ref AS text) AS user_id, t.stage,"
    " t.student_command, t.held_tool, t.held_args, t.held_reply, t.sentinel_score,"
    " t.score_breakdown, t.rule_ids, t.expires_at, t.priority_alert, s.secret"
    " FROM fw_tickets t JOIN fw_sessions s ON s.fw_session_id = t.fw_session_id"
    " WHERE t.status = 'pending' AND t.expires_at > now()"
    " ORDER BY t.priority_alert DESC, t.expires_at ASC, t.ticket_id"
)
_EVENTS = (
    "SELECT e.event_id, e.time, e.fw_session_id, CAST(e.user_id AS text) AS user_id, e.mode,"
    " e.stage, e.decision, e.shadow_decision, e.sentinel_score, e.rule_ids_fired AS rule_ids,"
    " e.judge_risk, e.judge_reason, e.forensic_status, s.secret"
    " FROM fw_events e JOIN fw_sessions s ON s.fw_session_id = e.fw_session_id"
    " WHERE (CAST(:sid AS text) IS NULL OR e.fw_session_id = CAST(:sid AS text))"
    " AND (CAST(:mode AS text) IS NULL OR e.mode = CAST(:mode AS text))"
    " AND (CAST(:decision AS text) IS NULL OR e.decision = CAST(:decision AS text))"
    " AND (CAST(:stage AS text) IS NULL OR e.stage = CAST(:stage AS text))"
    " AND (CAST(:since AS timestamptz) IS NULL OR e.time >= CAST(:since AS timestamptz))"
    " ORDER BY e.time DESC, e.event_id LIMIT :limit"
)
_DIVERT_EVENTS = (
    "SELECT e.event_id, e.fw_session_id, CAST(e.user_id AS text) AS user_id, e.trace_back_id"
    " FROM fw_events e WHERE e.execution_status = 'diverted'"
    " AND (CAST(:sid AS text) IS NULL OR e.fw_session_id = CAST(:sid AS text))"
    " AND (CAST(:mode AS text) IS NULL OR e.mode = CAST(:mode AS text))"
    " AND (CAST(:decision AS text) IS NULL OR e.decision = CAST(:decision AS text))"
    " AND (CAST(:stage AS text) IS NULL OR e.stage = CAST(:stage AS text))"
    " AND (CAST(:since AS timestamptz) IS NULL OR e.time >= CAST(:since AS timestamptz))"
    " ORDER BY e.time DESC, e.event_id LIMIT :limit"
)
_TRACE_BACKS = (
    "SELECT trace_id, time, CAST(user_id AS text) AS user_id, fw_session_id, ip_hash, subnet,"
    " asn, asn_org, country, user_agent, client_fingerprint, methods_used, tools_called"
    " FROM trace_back WHERE trace_id = ANY(CAST(:ids AS text[]))"
)


class InvalidRule(ValueError):
    """A rule form that cannot be saved (the console shows the message, HTTP 422)."""


def _json(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


# --- rule forms -------------------------------------------------------------------------------


def _text_value(form: RuleForm) -> str:
    if not isinstance(form.value, str) or not form.value.strip():
        raise InvalidRule("this operator needs a non-empty text value")
    if len(form.value) > MAX_REGEX_CHARS:
        raise InvalidRule(f"the value is longer than {MAX_REGEX_CHARS} characters")
    return form.value


def check_form(form: RuleForm) -> None:
    """Refuse a form the engine could not run correctly (nothing is written for it)."""
    if not form.note.strip() or len(form.note) > MAX_NOTE_CHARS:
        raise InvalidRule(f"the note must say why the rule exists (1-{MAX_NOTE_CHARS} characters)")
    op = form.operator
    if op in _NO_VALUE_OPERATORS:
        return
    if op in _LIST_OPERATORS:
        items = form.value
        if not isinstance(items, list) or not items or len(items) > MAX_LIST_ITEMS:
            raise InvalidRule(f"this operator needs a list of 1 to {MAX_LIST_ITEMS} items")
        if any(not isinstance(i, str) or not i.strip() or len(i) > MAX_ITEM_CHARS for i in items):
            raise InvalidRule("every list item must be non-empty text")
        return
    if op in _NUMERIC_OPERATORS or (op == "equals" and form.checks in _COUNT_CHECKS):
        if isinstance(form.value, bool) or not isinstance(form.value, int) or form.value < 0:
            raise InvalidRule("this operator needs a whole number, 0 or more")
        return
    pattern = _text_value(form)
    if op == "regex":
        try:
            re2.compile(pattern)
        except re2.error as exc:
            raise InvalidRule(f"not a valid RE2 pattern: {exc}") from exc


def _snapshot(rule: RuleDef, set_version: int) -> dict[str, Any]:
    return {
        "version": rule.version,
        "set_version": set_version,
        "enabled": rule.enabled,
        "deprecated": rule.deprecated,
        "form": rule.form.model_dump(mode="json") if rule.form else None,
    }


class AdminApi:
    def __init__(
        self,
        engine: AsyncEngine,
        llm: ChatModel,
        risky: RiskyHistoryPort,
        judge: JudgePort,
        decoys: DecoyGenerator | None = None,
    ) -> None:
        self._engine = engine
        self._llm = llm
        self._risky = risky
        self._judge = judge
        self._decoys = decoys
        self._read = FirewallRead(engine)

    # --- rules ---------------------------------------------------------------------------------

    async def list_rules(self) -> list[RuleDef]:
        async with self._engine.connect() as conn:
            latest = (await conn.execute(text(_LATEST_SET))).scalar_one()
            rules = await rules_at(conn, int(latest))
        return sorted(rules, key=lambda r: (r.builtin, r.rule_id))

    @staticmethod
    async def _current(conn: AsyncConnection, rule_id: str) -> tuple[RuleDef, int]:
        row = (await conn.execute(text(_CURRENT), {"rule_id": rule_id})).mappings().first()
        if row is None:
            raise NotFound(f"rule {rule_id} not found")
        return rule_from_row(row), int(row["set_version"])

    @staticmethod
    async def _add_version(
        conn: AsyncConnection,
        *,
        current: tuple[RuleDef, int] | None,
        rule_id: str,
        admin_id: str,
        note: str,
        action: str,
        form: RuleForm | None = None,
        enabled: bool | None = None,
        deprecated: bool | None = None,
    ) -> RuleDef:
        """Open a new rule set, add the rule's next version to it, and audit the change."""
        before = current[0] if current else None
        latest = int((await conn.execute(text(_LATEST_SET))).scalar_one())
        await conn.execute(text(_OPEN_SET), {"version": latest + 1, "note": note})
        new_form = form if form is not None else (before.form if before else None)
        enabled_now = enabled if enabled is not None else (before.enabled if before else True)
        deprecated_now = (
            deprecated if deprecated is not None else (before.deprecated if before else False)
        )
        row = (
            (
                await conn.execute(
                    text(_INSERT_RULE),
                    {
                        "rule_id": rule_id,
                        "version": before.version + 1 if before else 1,
                        "set_version": latest + 1,
                        "builtin": before.builtin if before else False,
                        "enabled": enabled_now,
                        "deprecated": deprecated_now,
                        "form": json.dumps(new_form.model_dump(mode="json")) if new_form else None,
                        "admin": admin_id,
                    },
                )
            )
            .mappings()
            .one()
        )
        rule = rule_from_row(row)
        await record_audit(
            conn,
            actor_id=admin_id,
            entity="fw_rule",
            entity_id=rule_id,
            action=action,
            before=_snapshot(before, current[1]) if before and current else None,
            after=_snapshot(rule, latest + 1),
        )
        return rule

    async def create_rule(self, form: RuleForm, admin_id: str) -> RuleDef:
        check_form(form)
        async with self._engine.begin() as conn:
            await conn.execute(text(_LOCK), {"key": RULE_LOCK_KEY})
            number = int((await conn.execute(text(_NEXT_NUMBER))).scalar_one())
            if number > MAX_RULE_NUMBER:
                raise ConflictError("there is no free rule number left")
            rule_id = f"R-{number:03d}"
            return await self._add_version(
                conn,
                current=None,
                rule_id=rule_id,
                admin_id=admin_id,
                note=f"create {rule_id}",
                action="create",
                form=form,
            )

    async def update_rule(self, rule_id: str, form: RuleForm, admin_id: str) -> RuleDef:
        check_form(form)
        async with self._engine.begin() as conn:
            await conn.execute(text(_LOCK), {"key": RULE_LOCK_KEY})
            current = await self._current(conn, rule_id)
            if current[0].builtin:
                raise ConflictError("built-in rules are code and cannot be edited")
            if current[0].deprecated:
                raise ConflictError("a deprecated rule cannot be edited")
            return await self._add_version(
                conn,
                current=current,
                rule_id=rule_id,
                admin_id=admin_id,
                note=f"update {rule_id}",
                action="update",
                form=form,
            )

    async def deprecate_rule(self, rule_id: str, admin_id: str) -> RuleDef:
        async with self._engine.begin() as conn:
            await conn.execute(text(_LOCK), {"key": RULE_LOCK_KEY})
            current = await self._current(conn, rule_id)
            if current[0].builtin:
                raise ConflictError("built-in rules cannot be deprecated; switch them off instead")
            if current[0].deprecated:
                raise ConflictError("the rule is already deprecated")
            return await self._add_version(
                conn,
                current=current,
                rule_id=rule_id,
                admin_id=admin_id,
                note=f"deprecate {rule_id}",
                action="deprecate",
                deprecated=True,
            )

    async def set_builtin_enabled(self, rule_id: str, enabled: bool, admin_id: str) -> RuleDef:
        async with self._engine.begin() as conn:
            await conn.execute(text(_LOCK), {"key": RULE_LOCK_KEY})
            current = await self._current(conn, rule_id)
            if not current[0].builtin:
                raise ConflictError("only built-in checks can be switched; edit a form rule")
            if rule_id not in SWITCHABLE_BUILTINS:
                raise ConflictError(f"{rule_id} is part of the canonical call form: always on")
            if current[0].enabled == enabled:
                return current[0]  # nothing to change, nothing to record
            return await self._add_version(
                conn,
                current=current,
                rule_id=rule_id,
                admin_id=admin_id,
                note=f"{'enable' if enabled else 'disable'} {rule_id}",
                action="builtin_switch",
                enabled=enabled,
            )

    async def set_rule_enabled(self, rule_id: str, enabled: bool, admin_id: str) -> RuleDef:
        """Switch any rule on or off for new sessions. Built-ins keep their limits (B-03 is always
        on); a form rule is switched like a built-in, and a deprecated one must be restored
        first. A switch that changes nothing writes nothing."""
        async with self._engine.begin() as conn:
            await conn.execute(text(_LOCK), {"key": RULE_LOCK_KEY})
            current = await self._current(conn, rule_id)
            rule = current[0]
            if rule.builtin and rule_id not in SWITCHABLE_BUILTINS:
                raise ConflictError(f"{rule_id} is part of the canonical call form: always on")
            if rule.deprecated:
                raise ConflictError("a deprecated rule cannot be switched; restore it first")
            if rule.enabled == enabled:
                return rule
            return await self._add_version(
                conn,
                current=current,
                rule_id=rule_id,
                admin_id=admin_id,
                note=f"{'enable' if enabled else 'disable'} {rule_id}",
                action="builtin_switch" if rule.builtin else "rule_switch",
                enabled=enabled,
            )

    async def restore_rule(self, rule_id: str, admin_id: str) -> RuleDef:
        """Undo a deprecation: a new version, same form, for new sessions. History is kept."""
        async with self._engine.begin() as conn:
            await conn.execute(text(_LOCK), {"key": RULE_LOCK_KEY})
            current = await self._current(conn, rule_id)
            if current[0].builtin:
                raise ConflictError("built-in rules are never deprecated")
            if not current[0].deprecated:
                raise ConflictError("the rule is not deprecated")
            return await self._add_version(
                conn,
                current=current,
                rule_id=rule_id,
                admin_id=admin_id,
                note=f"restore {rule_id}",
                action="restore",
                deprecated=False,
            )

    # --- tickets -------------------------------------------------------------------------------

    async def list_pending_tickets(self) -> list[TicketQueueItem]:
        await expire_due(self._engine)  # a due ticket leaves the queue as an expiry
        async with self._engine.connect() as conn:
            rows = (await conn.execute(text(_QUEUE))).mappings().all()
        return [self._queue_item(r) for r in rows]

    @staticmethod
    def _queue_item(r: Any) -> TicketQueueItem:
        secret = r["secret"]
        args = _json(r["held_args"])
        shown = (
            {k: redact_secret(v, secret) if isinstance(v, str) else v for k, v in args.items()}
            if args is not None
            else None
        )
        return TicketQueueItem(
            ticket_id=r["ticket_id"],
            fw_session_id=r["fw_session_id"],
            user_id=r["user_id"],
            stage=r["stage"],
            student_command=redact_secret(r["student_command"] or "", secret),
            held_tool=r["held_tool"],
            held_args=shown,
            held_reply=redact_secret(r["held_reply"], secret) if r["held_reply"] else None,
            sentinel_score=r["sentinel_score"] or 0,
            score_breakdown=_json(r["score_breakdown"]) or {},
            rule_ids=list(r["rule_ids"] or []),
            expires_at=r["expires_at"],
            priority_alert=r["priority_alert"],
        )

    async def decide_ticket(self, ticket_id: str, decision: TicketDecision, admin_id: str) -> None:
        await decide_ticket(
            self._engine,
            self._llm,
            self._risky,
            ticket_id,
            decision,
            admin_id,
            decoys=self._decoys,
            judge=self._judge,
        )

    # --- events, diverts, trace-back ----------------------------------------------------------

    @staticmethod
    def _filter_params(filters: EventFilter) -> dict[str, Any]:
        return {
            "sid": filters.fw_session_id,
            "mode": filters.mode,
            "decision": filters.decision,
            "stage": filters.stage,
            "since": filters.since,
            "limit": filters.limit,
        }

    async def list_events(self, filters: EventFilter) -> list[EventRow]:
        async with self._engine.connect() as conn:
            rows = list(
                (await conn.execute(text(_EVENTS), self._filter_params(filters))).mappings()
            )
        return [
            EventRow.model_validate(
                {
                    **{k: v for k, v in r.items() if k != "secret"},
                    "rule_ids": list(r["rule_ids"] or []),
                    "judge_reason": (
                        redact_secret(r["judge_reason"], r["secret"]) if r["judge_reason"] else None
                    ),
                }
            )
            for r in rows
        ]

    async def _trace_backs(self, trace_ids: list[str]) -> dict[str, TraceBack]:
        if not trace_ids:
            return {}
        async with self._engine.connect() as conn:
            rows = (await conn.execute(text(_TRACE_BACKS), {"ids": trace_ids})).mappings()
            return {r["trace_id"]: TraceBack.model_validate(dict(r)) for r in rows}

    async def list_diverts_admin(self, filters: EventFilter) -> list[DivertAdminItem]:
        async with self._engine.connect() as conn:
            params = self._filter_params(filters)
            events = list((await conn.execute(text(_DIVERT_EVENTS), params)).mappings())
        sessions = list(dict.fromkeys(e["fw_session_id"] for e in events))
        items = await self._read.divert_items(sessions)
        traces = await self._trace_backs([e["trace_back_id"] for e in events if e["trace_back_id"]])
        found = []
        for e in events:  # newest first, like the events
            divert = next(
                (d for d in items.get(e["fw_session_id"], []) if d.event_id == e["event_id"]), None
            )
            if divert is not None:
                found.append(
                    DivertAdminItem(
                        divert=divert,
                        fw_session_id=e["fw_session_id"],
                        user_id=e["user_id"],
                        trace_back=traces.get(e["trace_back_id"]),
                    )
                )
        return found

    async def get_trace_back(self, trace_id: str) -> TraceBack:
        found = await self._trace_backs([trace_id])
        if trace_id not in found:
            raise NotFound("trace-back not found (it may have been purged after 30 days)")
        return found[trace_id]

    async def purge_expired_trace_back(self, now: datetime) -> int:
        return await purge_expired_trace_back(self._engine, now)


def create() -> AdminApi:
    """The factory M1's `ports.py` calls when `admin` is not faked. Approving a held item
    continues its turn, so this builds the same bot model, history, judge and decoys as C2."""
    from app.firewall import ports  # imported here: ports imports this module lazily

    settings = get_settings()
    engine = make_engine(settings.database_url)
    llm = build_llm(settings, engine)
    return AdminApi(
        engine, llm, ports.get_risky_history(), ports.get_judge(), build_decoys(settings, llm)
    )
