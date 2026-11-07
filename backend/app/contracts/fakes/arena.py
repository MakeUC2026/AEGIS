"""In-memory C4/C8 fake for M3 and M4."""

from __future__ import annotations

from datetime import UTC, datetime

from app.contracts.arena import (
    ArenaSession,
    LevelConfigUpdate,
    LevelSummary,
    SecretStatus,
    SessionFilters,
)
from app.contracts.firewall import NotFound


class FakeArenaService:
    def __init__(
        self,
        sessions: list[ArenaSession] | None = None,
        levels: list[LevelSummary] | None = None,
    ) -> None:
        self.sessions: dict[str, ArenaSession] = {s.id: s for s in sessions or []}
        self.levels: dict[str, LevelSummary] = {lv.level_id: lv for lv in levels or []}
        self.secrets: dict[str, SecretStatus] = {}
        self.unlocked: list[str] = []
        self.audit: list[tuple[str, str, str]] = []

    async def list_sessions(self, filters: SessionFilters) -> list[ArenaSession]:
        rows = [
            s
            for s in self.sessions.values()
            if (filters.user_id is None or s.user_id == filters.user_id)
            and (filters.level_id is None or s.level_id == filters.level_id)
            and (filters.mode is None or s.mode == filters.mode)
            and (filters.status is None or s.status == filters.status)
            and (filters.admin_test is None or s.admin_test == filters.admin_test)
        ]
        return rows[filters.offset : filters.offset + filters.limit]

    async def get_session(self, session_id: str) -> ArenaSession | None:
        return self.sessions.get(session_id)

    async def list_levels(self) -> list[LevelSummary]:
        return sorted(self.levels.values(), key=lambda lv: lv.number)

    async def save_level_version(self, update: LevelConfigUpdate, actor: str) -> LevelSummary:
        current = self.levels.get(update.level_id)
        if current is None:
            raise NotFound(update.level_id)
        changes = {
            k: v for k, v in update.model_dump(exclude={"level_id"}).items() if v is not None
        }
        saved = current.model_copy(
            update={
                **changes,
                "level_version": current.level_version + 1,
                "created_at": datetime.now(UTC),
            }
        )
        self.levels = {**self.levels, update.level_id: saved}
        self.audit.append(("level", update.level_id, actor))
        return saved

    async def rotate_secret(self, level_id: str, actor: str) -> SecretStatus:
        prior = self.secrets.get(level_id)
        status = SecretStatus(
            level_id=level_id,
            secret_version=(prior.secret_version + 1) if prior else 1,
            compromised=False,
            compromised_by_user=None,
            compromised_by_session=None,
            compromised_at=None,
            created_at=datetime.now(UTC),
        )
        self.secrets = {**self.secrets, level_id: status}
        self.audit.append(("secret", level_id, actor))
        return status

    async def get_secret_status(self) -> list[SecretStatus]:
        return list(self.secrets.values())

    async def unlock_recap(self, session_id: str) -> None:
        self.unlocked.append(session_id)
