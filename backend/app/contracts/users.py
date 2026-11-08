"""C1: users (PRD §14.2). The token claim is the source of truth for roles."""

from __future__ import annotations

from app.contracts.common import Contract, Role, UtcDatetime


class User(Contract):
    id: str  # UUID every part uses
    auth0_sub: str
    name: str | None
    email: str | None
    role: Role  # display cache only
    created_at: UtcDatetime


class CurrentUser(Contract):
    """The authenticated caller for one request. Roles come from the verified token."""

    id: str
    auth0_sub: str
    name: str | None
    email: str | None
    roles: frozenset[Role]

    def has(self, role: Role) -> bool:
        return role in self.roles
