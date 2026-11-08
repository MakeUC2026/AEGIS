"""M4 X-6: SQL in app/classroom and app/quiz touches only the quiz tables, the quiz views and a
read-only `users` lookup. Everything else goes through C3, C4 or C8."""

from __future__ import annotations

import ast
import pathlib
import re

APP = pathlib.Path(__file__).resolve().parents[2] / "app"
ALLOWED = {
    "quiz",
    "quiz_questions",
    "quiz_turns",
    "quiz_result",
    "quiz_session_status",
    "quiz_class_items",
    "users",
}
TABLE = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE|DELETE\s+FROM)\s+([a-z_][a-z0-9_]*)", re.I)


def _sql_strings() -> list[tuple[pathlib.Path, str]]:
    """Every argument string of a `text(...)` call, with implicit concatenation joined."""
    found = []
    for folder in ("classroom", "quiz"):
        for path in (APP / folder).rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                is_text = (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "text"
                )
                if is_text and node.args and isinstance(node.args[0], ast.Constant):
                    found.append((path, str(node.args[0].value)))
    return found


def test_there_is_sql_to_check() -> None:
    assert len(_sql_strings()) >= 5


def test_sql_only_touches_allowed_tables() -> None:
    bad = [
        (p.name, name)
        for p, sql in _sql_strings()
        for name in TABLE.findall(sql)
        if name.lower() not in ALLOWED
    ]
    assert bad == []


def test_users_is_only_ever_read() -> None:
    writes = [
        p.name
        for p, sql in _sql_strings()
        if re.search(r"\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+users\b", sql, re.I)
    ]
    assert writes == []


def test_no_classroom_or_quiz_module_selects_the_answer_columns_for_routes() -> None:
    """E-60 groundwork: answer columns are only ever named in the quiz repo (added in phase C)."""
    offenders = [
        p.name
        for p in (APP / "classroom").rglob("*.py")
        if re.search(r"answer_index|answer_key", p.read_text())
    ]
    assert offenders == []
