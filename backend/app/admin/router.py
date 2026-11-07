"""Firewall admin console routes. Gate 0 placeholder created by M1; owned by M3 from here on
(§0.2 rule 4). Every route must use `require_role("firewall_admin")`.
"""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/api/admin", tags=["admin"])
