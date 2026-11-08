"""Secret status and rotation (PRD 12.4). Rotation goes through C8, which writes the audit
row; M4 only passes the caller as the actor. No secret value is ever read or returned."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine

from app.classroom.schemas import SecretList, SecretRow
from app.classroom.users_repo import names_for
from app.contracts.arena import ArenaServicePort, SecretStatus
from app.contracts.firewall import NotFound
from app.contracts.users import CurrentUser


def _row(s: SecretStatus, levels: dict[str, str], names: dict[str, str | None]) -> SecretRow:
    return SecretRow(
        level_id=s.level_id,
        level_name=levels.get(s.level_id),
        secret_version=s.secret_version,
        compromised=s.compromised,
        compromised_by_id=s.compromised_by_user,
        compromised_by_name=names.get(s.compromised_by_user) if s.compromised_by_user else None,
        compromised_by_session=s.compromised_by_session,
        compromised_at=s.compromised_at,
        created_at=s.created_at,
    )


async def secrets_view(*, engine: AsyncEngine, arena: ArenaServicePort) -> SecretList:
    statuses = await arena.get_secret_status()
    levels = await arena.list_levels()
    number = {lv.level_id: lv.number for lv in levels}
    names = await names_for(
        engine, [s.compromised_by_user for s in statuses if s.compromised_by_user]
    )
    ordered = sorted(statuses, key=lambda s: (number.get(s.level_id, 10**6), s.level_id))
    titles = {lv.level_id: lv.name for lv in levels}
    return SecretList(items=[_row(s, titles, names) for s in ordered])


async def rotate_view(
    level_id: str, user: CurrentUser, *, engine: AsyncEngine, arena: ArenaServicePort
) -> SecretRow:
    levels = await arena.list_levels()
    if level_id not in {lv.level_id for lv in levels}:
        raise NotFound(level_id)
    status = await arena.rotate_secret(level_id, user.id)
    return _row(status, {lv.level_id: lv.name for lv in levels}, {})
