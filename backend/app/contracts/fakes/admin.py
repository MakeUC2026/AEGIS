"""In-memory C6 fake. When linked to a FakeFirewall, `decide_ticket` resolves its tickets."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime

from app.contracts.fakes.firewall import STARTING_RULES, FakeFirewall
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


class FakeFirewallAdmin:
    def __init__(self, firewall: FakeFirewall | None = None) -> None:
        self._firewall = firewall
        self._ids = itertools.count(7)
        now = datetime.now(UTC)
        self.rules: dict[str, RuleDef] = {
            r.rule_id: RuleDef(
                rule_id=r.rule_id,
                version=1,
                builtin=r.rule_id.startswith("B-"),
                enabled=True,
                deprecated=False,
                form=None,
                created_at=now,
                created_by=None,
            )
            for r in STARTING_RULES
        }
        self.decided: list[tuple[str, TicketDecision, str]] = []
        self.queue: list[TicketQueueItem] = []
        self.trace_backs: dict[str, TraceBack] = {}

    async def list_pending_tickets(self) -> list[TicketQueueItem]:
        return list(self.queue)

    async def decide_ticket(self, ticket_id: str, decision: TicketDecision, admin_id: str) -> None:
        if any(t == ticket_id for t, _, _ in self.decided):
            raise ConflictError(ticket_id)
        if self._firewall is not None:
            if ticket_id not in self._firewall.pending_ticket_ids():
                raise ConflictError(ticket_id)
            outcome = "approved" if decision == "ok" else "human_denied"
            await self._firewall.resolve_ticket(ticket_id, outcome)
        self.decided.append((ticket_id, decision, admin_id))

    async def list_rules(self) -> list[RuleDef]:
        return list(self.rules.values())

    def _put(self, rule_id: str, form: RuleForm | None, admin_id: str, **flags: bool) -> RuleDef:
        prior = self.rules.get(rule_id)
        rule = RuleDef(
            rule_id=rule_id,
            version=(prior.version + 1) if prior else 1,
            builtin=prior.builtin if prior else False,
            enabled=flags.get("enabled", prior.enabled if prior else True),
            deprecated=flags.get("deprecated", prior.deprecated if prior else False),
            form=form if form is not None else (prior.form if prior else None),
            created_at=datetime.now(UTC),
            created_by=admin_id,
        )
        self.rules = {**self.rules, rule_id: rule}
        return rule

    async def create_rule(self, form: RuleForm, admin_id: str) -> RuleDef:
        return self._put(f"R-{next(self._ids):03d}", form, admin_id)

    async def update_rule(self, rule_id: str, form: RuleForm, admin_id: str) -> RuleDef:
        if rule_id not in self.rules:
            raise NotFound(rule_id)
        return self._put(rule_id, form, admin_id)

    async def deprecate_rule(self, rule_id: str, admin_id: str) -> RuleDef:
        if rule_id not in self.rules:
            raise NotFound(rule_id)
        return self._put(rule_id, None, admin_id, deprecated=True)

    async def set_builtin_enabled(self, rule_id: str, enabled: bool, admin_id: str) -> RuleDef:
        if rule_id not in self.rules or not self.rules[rule_id].builtin:
            raise NotFound(rule_id)
        return self._put(rule_id, None, admin_id, enabled=enabled)

    async def set_rule_enabled(self, rule_id: str, enabled: bool, admin_id: str) -> RuleDef:
        if rule_id not in self.rules:
            raise NotFound(rule_id)
        return self._put(rule_id, None, admin_id, enabled=enabled)

    async def restore_rule(self, rule_id: str, admin_id: str) -> RuleDef:
        if rule_id not in self.rules:
            raise NotFound(rule_id)
        return self._put(rule_id, None, admin_id, deprecated=False)

    async def list_events(self, filters: EventFilter) -> list[EventRow]:
        return []

    async def list_diverts_admin(self, filters: EventFilter) -> list[DivertAdminItem]:
        return []

    async def get_trace_back(self, trace_id: str) -> TraceBack:
        if trace_id not in self.trace_backs:
            raise NotFound(trace_id)
        return self.trace_backs[trace_id]

    async def purge_expired_trace_back(self, now: datetime) -> int:
        return 0
