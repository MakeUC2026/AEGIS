"""C6: AFF admin operations (new seam, M1 §3.1). Provider M2, consumer M3's admin router.

Rule form fields follow PRD §9.1 exactly. Every write is audited by the provider.
"""

from __future__ import annotations

from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import Field, model_validator

from app.contracts.common import Contract, Decision, Mode, Stage, UtcDatetime
from app.contracts.firewall_read import DivertItem

RuleAppliesOn = Literal[
    "player_message", "tool_result", "bot_tool_call", "bot_reply", "session_history"
]
RuleChecks = Literal["text", "tool_name", "named_argument", "turn_count", "earlier_denies"]
RuleOperator = Literal[
    "contains",
    "equals",
    "regex",
    "in_list",
    "domain_in",
    "domain_not_in",
    "inside_workspace",
    "outside_workspace",
    "greater_than",
    "less_than",
]
RuleAction = Literal["score_only", "allow", "review", "deny", "divert"]
AtlasTag = Literal["AML.T0051.000", "AML.T0051.001", "AML.T0053", "AML.T0086"]
TicketDecision = Literal["ok", "not_ok"]

RULE_WEIGHT_MIN = 5
RULE_WEIGHT_MAX = 60

# PRD §9.1: "Only operators valid for the field type".
TEXT_OPERATORS: frozenset[str] = frozenset({"contains", "equals", "regex", "in_list"})
OPERATORS_BY_CHECK: dict[str, frozenset[str]] = {
    "text": TEXT_OPERATORS,
    "tool_name": frozenset({"equals", "in_list"}),
    "named_argument": TEXT_OPERATORS
    | frozenset({"domain_in", "domain_not_in", "inside_workspace", "outside_workspace"}),
    "turn_count": frozenset({"equals", "greater_than", "less_than"}),
    "earlier_denies": frozenset({"equals", "greater_than", "less_than"}),
}


class RuleForm(Contract):
    applies_on: RuleAppliesOn
    checks: RuleChecks
    argument_name: str | None = None  # required when checks == named_argument
    operator: RuleOperator
    value: str | int | list[str]
    action: RuleAction
    weight: int | None = Field(default=None, ge=RULE_WEIGHT_MIN, le=RULE_WEIGHT_MAX)
    atlas_tag: AtlasTag | None = None
    note: str

    @model_validator(mode="after")
    def _operator_fits_field(self) -> RuleForm:
        if self.operator not in OPERATORS_BY_CHECK[self.checks]:
            raise ValueError(f"operator {self.operator!r} is not valid for {self.checks!r}")
        if self.checks == "named_argument" and not self.argument_name:
            raise ValueError("argument_name is required when checks is named_argument")
        if self.action == "score_only" and self.weight is None:
            raise ValueError("a score_only rule needs a weight")
        return self


class RuleDef(Contract):
    rule_id: str
    version: int
    builtin: bool
    enabled: bool
    deprecated: bool
    form: RuleForm | None  # None for built-ins B-01..B-04, which are code, not form rules
    created_at: UtcDatetime
    created_by: str | None


class TicketQueueItem(Contract):
    ticket_id: str
    fw_session_id: str
    user_id: str
    stage: Stage
    student_command: str
    held_tool: str | None
    held_args: dict[str, Any] | None
    held_reply: str | None
    sentinel_score: int
    score_breakdown: dict[str, int | None]
    rule_ids: list[str]
    expires_at: UtcDatetime
    priority_alert: bool


class EventFilter(Contract):
    fw_session_id: str | None = None
    mode: Mode | None = None
    decision: Decision | None = None
    stage: Stage | None = None
    since: UtcDatetime | None = None
    limit: int = Field(default=100, ge=1, le=1000)


class EventRow(Contract):
    event_id: str
    time: UtcDatetime
    fw_session_id: str
    user_id: str
    mode: Mode
    stage: Stage
    decision: Decision
    shadow_decision: Decision | None
    sentinel_score: int
    rule_ids: list[str]
    judge_risk: int | None
    judge_reason: str | None  # admin-only
    forensic_status: str | None


class TraceBack(Contract):
    trace_id: str
    time: UtcDatetime
    user_id: str
    fw_session_id: str
    ip_hash: str | None
    subnet: str | None
    asn: int | None
    asn_org: str | None
    country: str | None
    user_agent: str | None
    client_fingerprint: str | None
    methods_used: list[str]
    tools_called: list[str]


class DivertAdminItem(Contract):
    divert: DivertItem
    fw_session_id: str
    user_id: str
    trace_back: TraceBack | None  # None once purged after 30 days


class ConflictError(Exception):
    """Ticket no longer pending, already expired, or decided concurrently (409)."""


@runtime_checkable
class FirewallAdminPort(Protocol):
    async def list_pending_tickets(self) -> list[TicketQueueItem]: ...

    async def decide_ticket(
        self, ticket_id: str, decision: TicketDecision, admin_id: str
    ) -> None: ...

    async def list_rules(self) -> list[RuleDef]: ...

    async def create_rule(self, form: RuleForm, admin_id: str) -> RuleDef: ...

    async def update_rule(self, rule_id: str, form: RuleForm, admin_id: str) -> RuleDef: ...

    async def deprecate_rule(self, rule_id: str, admin_id: str) -> RuleDef: ...

    async def set_builtin_enabled(self, rule_id: str, enabled: bool, admin_id: str) -> RuleDef: ...

    async def list_events(self, filters: EventFilter) -> list[EventRow]: ...

    async def list_diverts_admin(self, filters: EventFilter) -> list[DivertAdminItem]: ...

    async def get_trace_back(self, trace_id: str) -> TraceBack: ...

    async def purge_expired_trace_back(self, now: UtcDatetime) -> int: ...
