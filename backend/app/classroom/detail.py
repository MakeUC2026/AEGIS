"""Session detail (PRD 12.2). Everything comes through C3/C4; no network data exists in any
model used here (M4-X06)."""

from __future__ import annotations

import asyncio

from sqlalchemy.ext.asyncio import AsyncEngine

from app.classroom.access import can_view_session, is_staff
from app.classroom.quiz_status import NOT_TAKEN, summaries_for
from app.classroom.schemas import (
    ConfigBlock,
    DecisionRow,
    DivertRow,
    ForensicRow,
    HeldRow,
    OutcomeBlock,
    SessionDetail,
    TranscriptRow,
)
from app.classroom.sessions import build_row
from app.classroom.users_repo import names_for
from app.contracts.arena import ArenaServicePort, ArenaSession
from app.contracts.firewall import NotFound
from app.contracts.firewall_read import FirewallReadPort, ManifestSummary
from app.contracts.users import CurrentUser


class SessionNotFound(Exception):
    pass


class SessionForbidden(Exception):
    pass


async def _manifest(read: FirewallReadPort, fw_id: str) -> ManifestSummary | None:
    try:
        return await read.get_manifest_summary(fw_id)
    except NotFound:
        return None


def _outcome(s: ArenaSession, echo_excluded: bool) -> OutcomeBlock:
    at = s.secret_obtained_at
    return OutcomeBlock(
        obtained=at is not None,
        obtained_at=at,
        duration_s=int((at - s.started_at).total_seconds()) if at else None,
        echo_excluded=echo_excluded,
    )


async def session_detail_view(
    user: CurrentUser,
    session_id: str,
    *,
    engine: AsyncEngine,
    arena: ArenaServicePort,
    read: FirewallReadPort,
) -> SessionDetail:
    s = await arena.get_session(session_id)
    if s is None:
        raise SessionNotFound(session_id)
    if not can_view_session(user, s.user_id):
        raise SessionForbidden(session_id)
    staff = is_staff(user)
    fw = s.fw_session_id
    (
        transcript,
        decisions,
        tickets,
        diverts,
        forensics,
        manifest,
        summaries,
        levels,
    ) = await asyncio.gather(
        read.get_transcript(fw),
        read.get_decisions(fw) if staff else _none(),
        read.get_tickets(fw) if staff else _none(),
        read.get_diverts(fw) if staff else _none(),
        read.get_forensics(fw) if staff else _none(),
        _manifest(read, fw) if staff else _none(),
        read.get_session_summaries([fw]),
        arena.list_levels(),
    )
    summary = summaries[0] if summaries else None
    quizzes = await summaries_for(engine, [s.id])
    deciders = {t.decided_by for t in tickets or [] if t.decided_by}
    names = await names_for(engine, {s.user_id, *deciders})
    row = build_row(
        s,
        names=names,
        levels={lv.level_id: lv.name for lv in levels},
        summary=summary,
        quiz=quizzes.get((s.id, s.user_id), NOT_TAKEN),
    )
    return SessionDetail(
        view="staff" if staff else "student",
        session=row,
        outcome=_outcome(s, bool(summary and summary.echo_excluded)),
        transcript=[
            TranscriptRow(
                message_id=t.message_id,
                time=t.time,
                speaker=t.speaker,
                text=t.text,
                status=t.status,
                is_decoy=t.is_decoy and staff,
            )
            for t in transcript
        ],
        decisions=None if decisions is None else [DecisionRow(**d.model_dump()) for d in decisions],
        config=None
        if manifest is None
        else ConfigBlock(**manifest.model_dump(exclude={"manifest_id", "judge_policy_hash"})),
        held_items=None
        if tickets is None
        else [
            HeldRow(
                ticket_id=t.ticket_id,
                stage=t.stage,
                status=t.status,
                created_at=t.created_at,
                decided_at=t.decided_at,
                decided_by_name=names.get(t.decided_by) if t.decided_by else None,
            )
            for t in tickets
        ],
        diverts=None if diverts is None else [DivertRow(**d.model_dump()) for d in diverts],
        forensics=None if forensics is None else [ForensicRow(**f.model_dump()) for f in forensics],
    )


async def _none() -> None:
    return None
