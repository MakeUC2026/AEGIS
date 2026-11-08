"""Demo seed target guard (M1 D-02): never touch production; never reset a shared remote DB
by accident (Tiger Cloud is shared by all four machines)."""

from __future__ import annotations

import pathlib
import re

import pytest

from app.demo import DEMO_USERS, UnsafeTarget, check_target

LOCAL = "postgresql+asyncpg://aegis:pw@127.0.0.1:55432/aegis"
REMOTE = "postgresql+asyncpg://tsdbadmin:s3cretpw@abc123.tsdb.cloud.timescale.com:33333/tsdb"


def test_production_is_always_refused() -> None:
    with pytest.raises(UnsafeTarget):
        check_target("production", LOCAL, confirm_host=None)


@pytest.mark.parametrize("url", [LOCAL, LOCAL.replace("127.0.0.1", "localhost"),
                                 LOCAL.replace("127.0.0.1", "db")])  # fmt: skip
def test_local_targets_need_no_confirmation(url: str) -> None:
    assert check_target("development", url, confirm_host=None)


def test_remote_target_needs_matching_confirmation() -> None:
    with pytest.raises(UnsafeTarget, match="--confirm-host"):
        check_target("development", REMOTE, confirm_host=None)
    with pytest.raises(UnsafeTarget):
        check_target("development", REMOTE, confirm_host="other.example")
    host = "abc123.tsdb.cloud.timescale.com"
    assert check_target("development", REMOTE, confirm_host=host) == host


def test_guard_never_echoes_the_password() -> None:
    with pytest.raises(UnsafeTarget) as exc:
        check_target("development", REMOTE, confirm_host=None)
    assert "s3cretpw" not in str(exc.value)


def test_demo_users_match_frontend_dev_sign_in() -> None:
    src = (pathlib.Path(__file__).resolve().parents[3] / "frontend/lib/dev-auth.ts").read_text()
    frontend_ids = re.findall(r'id: "(dev\|[a-z-]+)"', src)
    assert [u.sub for u in DEMO_USERS] == frontend_ids
