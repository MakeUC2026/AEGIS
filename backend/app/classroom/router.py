"""Classroom routes. Gate 0 placeholder created by M1; owned by M4 from here on (§0.2 rule 4).
Read other parts only through C3 and C4 (`app.firewall.ports`).
"""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/api/classroom", tags=["classroom"])
