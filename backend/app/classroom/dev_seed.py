"""Builders that fill `FakeArenaService` and `FakeFirewallRead` with classroom data.

Used by tests and (B7) by the dev seed so the dashboard has something to show while M1/M2/M3
are still on fakes. Everything here is synthetic; the only secret-like string is the
`DEMO_TOKEN_42` style placeholder (PRD 15.2).
"""

from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta

from app.contracts.arena import ArenaSession, LevelSummary
from app.contracts.common import Decision, Mode
from app.contracts.fakes import FakeArenaService, FakeFirewallRead
from app.contracts.firewall_read import (
    DecisionItem,
    DivertItem,
    ForensicItem,
    ManifestSummary,
    TicketItem,
    TranscriptItem,
)

_ids = itertools.count(1)
_THRESHOLDS = {"review": 40, "deny": 60, "divert": 80, "alert": 90}


def _uuid_like(n: int) -> str:
    return f"00000000-0000-4000-8000-{n:012d}"


def now() -> datetime:
    return datetime.now(UTC)


def add_level(
    arena: FakeArenaService, level_id: str, number: int, name: str, mode: Mode
) -> LevelSummary:
    level = LevelSummary(
        level_id=level_id,
        level_version=1,
        number=number,
        name=name,
        mode=mode,
        secret_tier="demo",  # noqa: S106 - tier label, not a credential
        rule_version=1,
        weights={},
        thresholds=dict(_THRESHOLDS),
        review_timeout_s=120,
        divert_enabled=mode == "strict",
        created_at=now(),
    )
    arena.levels = {**arena.levels, level_id: level}
    return level


def add_session(
    arena: FakeArenaService,
    read: FakeFirewallRead,
    *,
    user_id: str,
    level_id: str,
    mode: Mode,
    obtained: bool = False,
    closed: bool = False,
    admin_test: bool = False,
    started_at: datetime | None = None,
    session_id: str | None = None,
    messages: list[tuple[str, str]] | None = None,
    scores: list[tuple[str, int]] | None = None,
    diverts: list[tuple[str, str]] | None = None,
) -> ArenaSession:
    """Create one session plus its firewall-side data. `messages` are (student, bot) pairs,
    `scores` are (decision, sentinel_score), `diverts` are (attempted, decoy_shown)."""
    n = next(_ids)
    sid = session_id or _uuid_like(n)
    fw_id = f"fw-{n}"
    started = started_at or now() - timedelta(minutes=30)
    session = ArenaSession(
        id=sid,
        user_id=user_id,
        level_id=level_id,
        level_version=1,
        mode=mode,
        fw_session_id=fw_id,
        manifest_id=f"man-{n}",
        secret_version=1,
        status="closed" if (closed or obtained) else "active",
        secret_obtained_at=started + timedelta(minutes=10) if obtained else None,
        started_at=started,
        closed_at=started + timedelta(minutes=12) if (closed or obtained) else None,
        admin_test=admin_test,
        recap_unlocked_at=None,
    )
    arena.sessions = {**arena.sessions, sid: session}
    for i, (student, bot) in enumerate(messages or []):
        mid = f"m{i + 1}"
        t = started + timedelta(minutes=i)
        read.transcripts[fw_id].append(
            TranscriptItem(message_id=mid, time=t, speaker="student", text=student)
        )
        read.transcripts[fw_id].append(
            TranscriptItem(
                message_id=mid,
                time=t,
                speaker="bot",
                text=bot,
                status="replied",
                is_decoy=any(bot == shown for _, shown in diverts or []),
            )
        )
    for i, (decision, score) in enumerate(scores or []):
        read.decisions[fw_id].append(
            DecisionItem(
                event_id=f"evt-{n}-{i}",
                time=started + timedelta(minutes=i),
                message_id=f"m{i + 1}",
                stage="input_check",
                decision=_decision(decision),
                shadow_decision=None,
                execution_status="diverted" if decision == "divert" else "not_executed",
                sentinel_score=score,
                score_breakdown={"rules": score, "judge": None},
                thresholds_used=dict(_THRESHOLDS),
                rule_ids=["R-demo-1"] if score >= 40 else [],
                risky_pattern_ids=["P-demo-1"] if score >= 60 else [],
            )
        )
    for i, (attempted, shown) in enumerate(diverts or []):
        read.diverts[fw_id].append(
            DivertItem(
                event_id=f"evt-{n}-d{i}",
                time=started + timedelta(minutes=i),
                stage="tool_call_check",
                tool="read_file",
                attempted_summary=attempted,
                decoy_shown=shown,
            )
        )
    read.manifests[fw_id] = ManifestSummary(
        manifest_id=f"man-{n}",
        level_id=level_id,
        level_version=1,
        mode=mode,
        rule_version=1,
        pattern_version=1,
        thresholds=dict(_THRESHOLDS),
        weights={"rules": 50, "judge": 50},
        bot_model_id="demo-bot",
        judge_model_id="demo-judge" if mode == "strict" else None,
        judge_policy_hash=None,
    )
    return session


def _decision(value: str) -> Decision:
    allowed: tuple[Decision, ...] = ("allow", "deny", "review", "human_deny", "divert")
    for item in allowed:
        if item == value:
            return item
    raise ValueError(f"unknown decision {value!r}")


def add_forensic(read: FakeFirewallRead, session: ArenaSession, family: str) -> None:
    read.forensics[session.fw_session_id].append(
        ForensicItem(
            event_id=f"evt-f-{session.id[-4:]}",
            attack_family=family,
            atlas_techniques=["AML.T0051"],
            summary="Synthetic forensic summary.",
            missed_signals=["demo signal"],
            would_have_blocked_in=["strict"],
        )
    )


def add_ticket(read: FakeFirewallRead, session: ArenaSession, status: str, by: str | None) -> None:
    allowed = {"pending", "approved", "human_denied", "expired"}
    if status not in allowed:
        raise ValueError(status)
    read.tickets[session.fw_session_id].append(
        TicketItem(
            ticket_id=f"t-{session.id[-4:]}",
            stage="tool_call_check",
            status=status,  # type: ignore[arg-type]
            created_at=session.started_at,
            decided_at=session.started_at + timedelta(minutes=1) if by else None,
            decided_by=by,
        )
    )
