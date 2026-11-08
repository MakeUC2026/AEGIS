"""Mock tools over the session's mock state (M2 B-05; PRD D-11, §7.6; spec AEGIS-DOM-109).

Nothing a student writes runs on a real host. Every tool works on the canonical call and the
session's `MockState`, and returns a new state rather than changing the old one:

- `search_docs`: documents whose normalized title or content holds every query word;
- `read_file`: workspace files only (B-03 path resolution); anything else is "No such file";
- `send_email`: appended to the mock mailbox. Mail to the attacker mailbox is the
  student-visible tool effect (PRD §6.2);
- `query_db`: SELECT returns mock rows; nothing else is applied; never real SQL;
- `run_shell`: a tiny emulator (`ls`, `cat`, `echo`) over the mock filesystem. Anything else
  is "command not found", and pipes, redirection and chaining are not supported.
"""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any

from app.contracts.firewall import MockStateSeed
from app.firewall.canonical import CanonicalCall, resolve_workspace_path
from app.firewall.textnorm import normalize

ASSISTANT_ADDRESS = "assistant@company.example"
MAX_SEARCH_RESULTS = 10
_SELECT = re.compile(r"^\s*select\b")
_FROM_TABLE = re.compile(r"\bfrom\s+([a-z_][a-z0-9_]*)")
_SHELL_METACHARS = frozenset(";|&`$<>\n\\")


@dataclass(frozen=True)
class MockState:
    documents: tuple[Mapping[str, Any], ...]
    emails: tuple[Mapping[str, Any], ...]
    db_rows: Mapping[str, tuple[Mapping[str, Any], ...]]
    filesystem: Mapping[str, str]
    attacker_mailbox: str
    allowlist_domains: tuple[str, ...]

    @classmethod
    def from_seed(cls, seed: MockStateSeed) -> MockState:
        return cls.from_parts(
            documents=[d.model_dump(mode="json") for d in seed.documents],
            emails=[e.model_dump(mode="json") for e in seed.emails],
            db_rows=seed.db_rows,
            filesystem=seed.filesystem,
            attacker_mailbox=seed.attacker_mailbox,
            allowlist_domains=seed.allowlist_domains,
        )

    @classmethod
    def from_parts(cls, **parts: Any) -> MockState:
        return cls(
            documents=tuple(MappingProxyType(dict(d)) for d in parts["documents"]),
            emails=tuple(MappingProxyType(dict(e)) for e in parts["emails"]),
            db_rows=MappingProxyType(
                {name: tuple(rows) for name, rows in dict(parts["db_rows"]).items()}
            ),
            filesystem=MappingProxyType(dict(parts["filesystem"])),
            attacker_mailbox=str(parts["attacker_mailbox"]),
            allowlist_domains=tuple(parts["allowlist_domains"]),
        )


@dataclass(frozen=True)
class ToolOutcome:
    result: str
    state: MockState
    visible_content: str | None = None
    changed: bool = False


def _search_docs(state: MockState, call: CanonicalCall) -> ToolOutcome:
    words = normalize(str(call.args["query"])).split()
    hits = [
        f"{doc['path']} - {doc['title']}"
        for doc in state.documents
        if words and all(w in normalize(f"{doc['title']} {doc['content']}") for w in words)
    ]
    found = "\n".join(hits[:MAX_SEARCH_RESULTS]) or "No matching documents."
    return ToolOutcome(found, state)


def _read_file(state: MockState, call: CanonicalCall) -> ToolOutcome:
    path = call.paths["path"]
    if path.inside_workspace and path.resolved in state.filesystem:
        return ToolOutcome(state.filesystem[path.resolved], state)
    return ToolOutcome(f"No such file: {path.resolved}", state)


def visible_mail(
    state: MockState, recipients: tuple[str, ...], subject: str, body: str
) -> str | None:
    if state.attacker_mailbox.lower() not in recipients:
        return None
    return f"To: {', '.join(recipients)}\nSubject: {subject}\n\n{body}"


def _send_email(state: MockState, call: CanonicalCall) -> ToolOutcome:
    subject, body = str(call.args["subject"]), str(call.args["body"])
    mail = MappingProxyType(
        {"sender": ASSISTANT_ADDRESS, "to": list(call.recipients), "subject": subject, "body": body}
    )
    return ToolOutcome(
        f"Email sent to {', '.join(call.recipients)}.",
        replace(state, emails=(*state.emails, mail)),
        visible_mail(state, call.recipients, subject, body),
        changed=True,
    )


def _query_db(state: MockState, call: CanonicalCall) -> ToolOutcome:
    sql = normalize(str(call.args["sql"]))
    if not _SELECT.match(sql):
        return ToolOutcome(
            "Query OK, 0 rows affected (mock database: writes are not applied).", state
        )
    table = _FROM_TABLE.search(sql)
    if table is None or table.group(1) not in state.db_rows:
        name = table.group(1) if table else "?"
        return ToolOutcome(f"Error: no such table: {name}", state)
    rows = state.db_rows[table.group(1)]
    return ToolOutcome("\n".join(json.dumps(dict(r), sort_keys=True) for r in rows), state)


def _ls(state: MockState, targets: list[str]) -> str:
    out: list[str] = []
    for target in targets or ["."]:
        path = resolve_workspace_path(target)
        missing = f"ls: cannot access '{target}': No such file or directory"
        if path is None or not path.inside_workspace:
            out.append(missing)
            continue
        if path.resolved in state.filesystem:
            out.append(path.resolved.rsplit("/", 1)[-1])
            continue
        prefix = f"{path.resolved}/" if path.resolved else ""
        names = sorted(
            {f[len(prefix) :].split("/")[0] for f in state.filesystem if f.startswith(prefix)}
        )
        out.append("  ".join(names) or missing)
    return "\n".join(out)


def _cat(state: MockState, targets: list[str]) -> str:
    out: list[str] = []
    for target in targets:
        path = resolve_workspace_path(target)
        if path is not None and path.inside_workspace and path.resolved in state.filesystem:
            out.append(state.filesystem[path.resolved])
        else:
            out.append(f"cat: {target}: No such file or directory")
    return "\n".join(out)


def _run_shell(state: MockState, call: CanonicalCall) -> ToolOutcome:
    command = str(call.args["command"])
    if any(ch in _SHELL_METACHARS for ch in command):
        return ToolOutcome("sh: pipes, redirection and command chaining are not supported", state)
    try:
        argv = shlex.split(command)
    except ValueError:
        return ToolOutcome("sh: syntax error", state)
    if not argv:
        return ToolOutcome("", state)
    name, args = argv[0], [a for a in argv[1:] if not a.startswith("-")]
    if name == "ls":
        return ToolOutcome(_ls(state, args), state)
    if name == "cat":
        return ToolOutcome(_cat(state, args), state)
    if name == "echo":
        return ToolOutcome(" ".join(argv[1:]), state)
    return ToolOutcome(f"{name}: command not found", state)


_TOOLS: Mapping[str, Callable[[MockState, CanonicalCall], ToolOutcome]] = MappingProxyType(
    {
        "search_docs": _search_docs,
        "read_file": _read_file,
        "send_email": _send_email,
        "query_db": _query_db,
        "run_shell": _run_shell,
    }
)


def run_tool(state: MockState, call: CanonicalCall) -> ToolOutcome:
    tool = _TOOLS.get(call.tool)
    if tool is None:
        return ToolOutcome(f"{call.tool}: tool is not available", state)
    return tool(state, call)
