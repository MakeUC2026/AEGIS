"""M4 B-02: role helper. Students are scoped to themselves; staff see everything."""

from __future__ import annotations

import pytest

from app.classroom.access import can_view_session, is_staff, session_scope_user_id
from app.contracts.users import CurrentUser


def _user(*roles: str, uid: str = "u-1") -> CurrentUser:
    return CurrentUser(
        id=uid,
        auth0_sub="auth0|x",
        name=None,
        email=None,
        roles=frozenset(roles),  # type: ignore[arg-type]
    )


@pytest.mark.parametrize("role", ["teacher", "firewall_admin"])
def test_staff_roles_are_staff(role: str) -> None:
    assert is_staff(_user(role))


def test_student_is_not_staff() -> None:
    assert not is_staff(_user("student"))


def test_student_who_is_also_teacher_counts_as_staff() -> None:
    assert is_staff(_user("student", "teacher"))


def test_student_is_forced_to_own_user_id_whatever_was_requested() -> None:
    assert session_scope_user_id(_user("student", uid="me"), requested="someone-else") == "me"
    assert session_scope_user_id(_user("student", uid="me"), requested=None) == "me"


def test_staff_may_filter_by_any_student_or_none() -> None:
    assert session_scope_user_id(_user("teacher"), requested="stu") == "stu"
    assert session_scope_user_id(_user("firewall_admin"), requested=None) is None


def test_only_owner_or_staff_can_view_a_session() -> None:
    assert can_view_session(_user("student", uid="a"), owner_id="a")
    assert not can_view_session(_user("student", uid="a"), owner_id="b")
    assert can_view_session(_user("teacher", uid="t"), owner_id="b")
    assert can_view_session(_user("firewall_admin", uid="f"), owner_id="b")
