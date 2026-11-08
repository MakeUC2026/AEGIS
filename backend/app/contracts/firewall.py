"""C2: Arena <-> AFF in-process contract (PRD §14.3 plus M1 §3.1 additions).

Provider: M2 (`app/firewall/interface.py`). Consumer: M1 (arena).
Design decision: interface functions are `async` because every implementation
touches Postgres and model APIs from inside FastAPI's event loop.
"""

from __future__ import annotations

from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import Field

from app.contracts.common import ClientMeta, Contract, Decision, Mode, ScoreBand, Stage

# Exact player-facing copy from PRD §6.2 and §8.2/§8.3, shared by M1 (UI) and M2 (AFF).
PENDING_REVIEW_MESSAGE = (
    "Your request is pending human review. The result will appear here once a reviewer decides."
)
HUMAN_DENIED_MESSAGE = "A reviewer denied this request."
NEUTRAL_REFUSAL = "I can't help with that."

PlayerStatus = Literal["replied", "blocked", "awaiting_review", "human_denied"]
FeedDecision = Literal["allow", "deny", "review", "human_deny"]


class ToolDef(Contract):
    name: str
    json_schema: dict[str, Any]
    high_risk: bool


class AgentDefinition(Contract):
    system_prompt: str
    tools: list[ToolDef]
    model_id: str  # Grok model ID


class LevelConfig(Contract):
    level_id: str
    level_version: int
    mode: Mode
    rule_version: int  # 0 = pin the latest rule set at registration (M1 B-03, E-57)
    weights: dict[str, int]
    thresholds: dict[str, int]  # review, deny, divert, alert
    review_timeout_s: int = 120
    divert_enabled: bool


class MockDocument(Contract):
    path: str
    title: str
    content: str
    poisoned: bool = False


class MockEmail(Contract):
    sender: str
    to: list[str]
    subject: str
    body: str


class MockStateSeed(Contract):
    """Gap fill (M1 §3.1): the fake dataset the AFF loads into `fw_mock_state`."""

    documents: list[MockDocument] = Field(default_factory=list)
    emails: list[MockEmail] = Field(default_factory=list)
    db_rows: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    filesystem: dict[str, str] = Field(default_factory=dict)  # path -> content
    attacker_mailbox: str = ""
    allowlist_domains: list[str] = Field(default_factory=list)


class RegisterSession(Contract):
    owner_ref: str  # users.id
    agent: AgentDefinition
    level: LevelConfig
    secret: str
    mock_state_seed: MockStateSeed
    eval: bool = False


class SessionHandle(Contract):
    fw_session_id: str
    manifest_id: str


class ToolEffect(Contract):
    """What the tool-output view may show. A diverted action shows as `executed`."""

    call_id: str
    tool: str
    state: Literal["executed", "blocked", "awaiting_review", "human_denied"]
    visible_content: str | None  # e.g. mail in the attacker mailbox (decoy if diverted)


class FeedItem(Contract):
    stage: Stage
    decision: FeedDecision  # divert is reported as allow here
    rule_ids: list[str]
    score_band: ScoreBand
    # Gap fill (M1 §3.1): what the Gatekeeper would have done, set only in Off mode.
    shadow_decision: Literal["allow", "deny", "review"] | None = None


class PlayerView(Contract):
    status: PlayerStatus
    reply: str | None  # the pending review message while held
    tool_effects: list[ToolEffect]
    ticket_id: str | None
    defense_feed: list[FeedItem]


class Facts(Contract):
    decision: Decision
    rule_ids: list[str]
    secret_attempted: bool
    secret_delivered: bool  # echo exclusion already applied
    diverted: bool
    secret_used: bool | None = None  # stretch


class TurnResult(Contract):
    player_view: PlayerView
    facts: Facts  # game logic only, never sent to the browser


class RuleSummary(Contract):
    rule_id: str
    applies_on: str
    action: str
    note: str


class Catalog(Contract):
    rules: list[RuleSummary]
    tools: list[ToolDef]
    rule_version: int


class TicketResult(Contract):
    ticket_id: str
    status: Literal["pending", "approved", "human_denied", "expired"]
    expires_at: str  # ISO 8601 UTC
    turn_result: TurnResult | None  # set once the ticket is resolved


class FirewallError(Exception):
    """Base for typed AFF errors the arena maps to HTTP responses."""


class SessionBusy(FirewallError):
    """A message is in flight or an item is held on this session (E-04)."""


class MessageConflict(FirewallError):
    """Same message_id with different text (E-03)."""


class ModeChangeRejected(FirewallError):
    """A mode change on a registered session (PRD §7.2)."""


class SessionClosed(FirewallError):
    """Message sent to a closed session."""


class NotFound(FirewallError):
    """Unknown session or ticket, or one owned by someone else."""


class BotUnavailable(FirewallError):
    """The bot model failed; the claim is released so the same message_id can retry."""


@runtime_checkable
class FirewallPort(Protocol):
    async def read_catalog(self) -> Catalog: ...

    async def register_session(self, req: RegisterSession) -> SessionHandle: ...

    async def send_message(
        self,
        owner_ref: str,
        fw_session_id: str,
        message_id: str,
        text: str,
        client: ClientMeta,
    ) -> TurnResult: ...

    async def check_ticket(self, owner_ref: str, ticket_id: str) -> TicketResult: ...

    async def close_session(self, owner_ref: str, fw_session_id: str) -> None: ...
