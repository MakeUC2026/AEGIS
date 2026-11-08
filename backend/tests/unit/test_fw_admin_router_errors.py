"""Found by Playwright against the real stack (spec AEGIS-DOM-134): the admin router turned the
contract's `ConflictError` into HTTP 500 on every route but the ticket decision, so the console
showed "internal error" when the real admin API refused something (switching B-03, deprecating
twice, restoring a rule that is not deprecated). A refusal is a 409 with its reason."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.admin.router import _run
from app.contracts.firewall import NotFound
from app.contracts.firewall_admin import ConflictError


async def _raise(exc: Exception) -> None:
    raise exc


async def test_a_refusal_from_the_admin_api_is_a_409_with_its_reason() -> None:
    with pytest.raises(HTTPException) as caught:
        await _run(_raise(ConflictError("B-03 is part of the canonical call form: always on")))
    assert caught.value.status_code == 409
    assert "always on" in str(caught.value.detail)


async def test_not_found_is_still_a_404() -> None:
    with pytest.raises(HTTPException) as caught:
        await _run(_raise(NotFound("R-099")))
    assert caught.value.status_code == 404
