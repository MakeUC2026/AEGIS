"""Fakes for every seam (M1 A-02). Providers may improve their own fake in their own PR."""

from app.contracts.fakes.admin import FakeFirewallAdmin
from app.contracts.fakes.arena import FakeArenaService
from app.contracts.fakes.firewall import FakeDelay, FakeFirewall, SessionContext
from app.contracts.fakes.read import FakeFirewallRead
from app.contracts.fakes.sentinel import ZERO_SIGNALS, InMemoryRiskyHistory, StubJudge
from app.contracts.fakes.turns import fake_turn, with_ticket

__all__ = [
    "ZERO_SIGNALS",
    "FakeArenaService",
    "FakeDelay",
    "FakeFirewall",
    "FakeFirewallAdmin",
    "FakeFirewallRead",
    "InMemoryRiskyHistory",
    "SessionContext",
    "StubJudge",
    "fake_turn",
    "with_ticket",
]
