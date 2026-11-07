"""Shared JSON shape for files in `fixtures/attacks/` and `fixtures/benign/` (M1 A-13).

Files are add-only; new files use a machine prefix (m2_, m3_, m4_).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from app.contracts.common import Contract, Decision, Mode

AttackFamily = Literal[
    "direct_override",
    "indirect_injection",
    "authority_spoofing",
    "forged_approval",
    "goal_drift",
    "exfiltration_via_email",
    "encoded_or_split_leak",
    "shell_abuse",
]


class FixtureToolCall(Contract):
    tool: str
    arguments: dict[str, Any]


class AttackFixture(Contract):
    id: str
    family: AttackFamily
    description: str
    messages: list[str] = Field(min_length=1)
    proposed_tool_calls: list[FixtureToolCall] = Field(default_factory=list)
    expected: dict[Mode, Decision] = Field(default_factory=dict)  # strictest decision per mode


class BenignFixture(Contract):
    id: str
    description: str
    messages: list[str] = Field(default_factory=list)
    tool_calls: list[FixtureToolCall] = Field(default_factory=list)


class FixtureFile(Contract):
    kind: Literal["attack", "benign"]
    attacks: list[AttackFixture] = Field(default_factory=list)
    benign: list[BenignFixture] = Field(default_factory=list)
