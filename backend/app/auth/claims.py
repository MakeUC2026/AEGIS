"""Role and profile claims (PRD §3.2, §4.3). The token claim is the source of truth."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.contracts.common import Role

ROLES_CLAIM = "https://aegis/roles"
NAME_CLAIM = "https://aegis/name"
EMAIL_CLAIM = "https://aegis/email"
ASSIGNABLE_ROLES: frozenset[str] = frozenset({"teacher", "firewall_admin"})
MAX_PROFILE_LEN = 200
_PRIORITY: tuple[Role, ...] = ("firewall_admin", "teacher", "student")


def roles_from_claims(claims: Mapping[str, Any]) -> frozenset[Role]:
    """Known roles from the claim; anything else is ignored. No role means student."""
    raw = claims.get(ROLES_CLAIM)
    if not isinstance(raw, list):
        return frozenset({"student"})
    roles = frozenset(r for r in raw if isinstance(r, str) and r in ASSIGNABLE_ROLES)
    return roles or frozenset({"student"})  # type: ignore[return-value]


def primary_role(roles: frozenset[Role]) -> Role:
    """Display cache value for `users.role` (never used for access decisions)."""
    return next(r for r in _PRIORITY if r in roles)


def profile_value(claims: Mapping[str, Any], key: str) -> str | None:
    value = claims.get(key)
    return value[:MAX_PROFILE_LEN] if isinstance(value, str) and value else None
