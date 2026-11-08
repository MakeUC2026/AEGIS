"""Risky tool pattern matcher and approval checks (PRD §7.5, M3 A-01, A-03).

Shared by the Strict lookup, draft validation and the admin pattern editor.

A pattern is `{"tool": ..., "conditions": [{"arg": ..., "op": ..., "value": ...}]}`.
It matches a call only when the tool is the same and **every** condition matches.
A condition on a list argument (several recipients) matches when any element matches.
"""

from __future__ import annotations

import json
import os
import pathlib
import posixpath
import unicodedata
from collections.abc import Iterable
from decimal import Decimal, InvalidOperation
from functools import lru_cache
from typing import Any, Literal
from urllib.parse import unquote, urlsplit

import re2
from pydantic import BaseModel, ConfigDict, Field

from app.contracts.fixtures import FixtureFile, FixtureToolCall

PatternOp = Literal[
    "equals",
    "contains",
    "regex",
    "in",
    "domain_in",
    "domain_not_in",
    "inside_workspace",
    "outside_workspace",
    "gt",
    "lt",
]

_RE2_OPTIONS = re2.Options()
_RE2_OPTIONS.case_sensitive = False


class Condition(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    arg: str = Field(min_length=1)
    op: PatternOp
    value: str | int | float | list[str] | None = None


class PatternSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    tool: str = Field(min_length=1)
    conditions: list[Condition] = Field(default_factory=list)


# ponytail: local copy of the PRD §9.1 normalizer; switch to M2's A-03 normalizer once it lands.
_DROP_CATEGORIES = frozenset({"Cc", "Cf"})  # control and format (zero-width) characters


def normalize(text: str) -> str:
    """NFKC, zero-width and control characters removed, case-folded (PRD §9.1).

    Whitespace controls (newline, tab) become a space so `DROP\\nTABLE` keeps its word boundary.
    """
    nfkc = unicodedata.normalize("NFKC", text)
    return "".join(
        " " if ch.isspace() else ch
        for ch in nfkc
        if ch.isspace() or unicodedata.category(ch) not in _DROP_CATEGORIES
    ).casefold()


@lru_cache(maxsize=1024)
def compile_regex(pattern: str) -> Any:
    """Compile with RE2, case-insensitive. Raises `re2.error` on invalid RE2."""
    return re2.compile(pattern, options=_RE2_OPTIONS)


def _domain(value: str) -> str:
    value = value.strip().strip("<>")
    if "://" in value:  # URL first: `https://evil.example/@company.example` is evil.example
        return (urlsplit(value).hostname or "").rstrip(".")
    if "@" in value:
        return value.rsplit("@", 1)[1].rstrip(".")
    return value.rstrip(".")


def _domain_in(value: str, domains: Iterable[str]) -> bool:
    host = _domain(value)
    return any(host == d or host.endswith("." + d) for d in (normalize(x) for x in domains))


# ponytail: simple workspace check on relative mock-filesystem paths; use M2's B-03 resolver
# once it lands. Absolute paths and paths that climb out with ".." are outside.
def _inside_workspace(path: str) -> bool:
    path = unquote(path).replace("\\", "/")
    if path.startswith(("/", "~")) or (len(path) > 1 and path[1] == ":"):  # `c:/...` drive
        return False
    resolved = posixpath.normpath(path)
    return resolved != ".." and not resolved.startswith("../")


def _as_number(value: Any) -> Decimal | None:
    """Every number as an exact decimal, so 0.3, "0.3", 2**53 + 1 and "9007199254740993.0" all
    compare as written. A float goes through its shortest repr (the value the JSON held);
    a string is PRD §9.1-normalized first (full-width digits, zero-width characters).
    NaN compares to nothing.
    """
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        return None
    text = repr(value) if isinstance(value, float) else str(value)
    try:
        number = Decimal(normalize(text).strip())
    except InvalidOperation:
        return None
    return None if number.is_nan() else number


def _condition_matches_one(cond: Condition, raw: Any) -> bool:
    op, want = cond.op, cond.value
    if op in ("gt", "lt"):
        got, limit = _as_number(raw), _as_number(want)
        if got is None or limit is None:
            return False
        return got > limit if op == "gt" else got < limit
    if isinstance(raw, bool) or not isinstance(raw, str | int | float):
        return False
    text = normalize(str(raw))
    match op:
        case "equals":
            return text == normalize(str(want))
        case "contains":
            return normalize(str(want)) in text
        case "regex":
            return compile_regex(str(want)).search(text) is not None
        case "in":
            return isinstance(want, list) and text in {normalize(x) for x in want}
        case "domain_in":
            return isinstance(want, list) and _domain_in(text, want)
        case "domain_not_in":
            return isinstance(want, list) and not _domain_in(text, want)
        case "inside_workspace":
            return _inside_workspace(text)
        case "outside_workspace":
            return not _inside_workspace(text)
    return False


def _condition_matches(cond: Condition, args: dict[str, Any]) -> bool:
    if cond.arg not in args:
        return False
    raw = args[cond.arg]
    values = raw if isinstance(raw, list) else [raw]
    return any(_condition_matches_one(cond, v) for v in values)


def match(pattern: PatternSpec, tool: str | None, canonical_args: dict[str, Any] | None) -> bool:
    """True when the tool is the same and every condition matches. Empty patterns never match."""
    if not pattern.conditions or tool != pattern.tool or canonical_args is None:
        return False
    return all(_condition_matches(c, canonical_args) for c in pattern.conditions)


def structural_errors(pattern: PatternSpec) -> list[str]:
    """Problems with the pattern itself: no conditions, invalid RE2, wrong value types."""
    errors: list[str] = []
    if not pattern.conditions:
        errors.append("pattern has no conditions")
    for i, c in enumerate(pattern.conditions, start=1):
        where = f"condition {i} ({c.arg} {c.op})"
        if c.op == "regex":
            if not isinstance(c.value, str) or not c.value:
                errors.append(f"{where}: regex needs a non-empty string")
                continue
            try:
                compile_regex(c.value)
            except re2.error as exc:
                errors.append(f"{where}: invalid RE2 regex: {exc}")
        elif c.op in ("in", "domain_in", "domain_not_in"):
            if not isinstance(c.value, list) or not c.value:
                errors.append(f"{where}: needs a non-empty list")
        elif c.op in ("gt", "lt"):
            if _as_number(c.value) is None:
                errors.append(f"{where}: needs a number")
        elif c.op in ("equals", "contains") and (
            c.value in (None, "") or isinstance(c.value, list)
        ):
            errors.append(f"{where}: needs a value")
    return errors


def validate_for_approval(
    pattern: PatternSpec,
    source_call: FixtureToolCall,
    benign_calls: Iterable[FixtureToolCall],
) -> list[str]:
    """The three approval checks (PRD §7.5) plus RE2 validity. Returns every failed reason."""
    errors = structural_errors(pattern)
    if errors:
        return errors  # a broken pattern cannot be matched meaningfully
    if not match(pattern, source_call.tool, source_call.arguments):
        errors.append("pattern does not match its original call")
    benign = list(benign_calls)
    if not benign:  # an empty or exhausted corpus proves nothing (fail closed)
        errors.append("no benign fixture calls to check against")
    for call in benign:
        if match(pattern, call.tool, call.arguments):
            errors.append(f"pattern matches a benign call: {call.tool} {call.arguments}")
    return errors


def fixtures_dir() -> pathlib.Path:
    default = pathlib.Path(__file__).resolve().parents[3] / "fixtures"
    return pathlib.Path(os.environ.get("AEGIS_FIXTURES_DIR", default))


def load_benign_calls(root: pathlib.Path | None = None) -> list[FixtureToolCall]:
    """Every tool call in `fixtures/benign/*.json`.

    Raises when there are none: an empty corpus would let the "matches no benign call" check
    pass without checking anything (fail closed, PRD §7.5, §15.3).
    """
    folder = (root or fixtures_dir()) / "benign"
    calls = [
        call
        for path in sorted(folder.glob("*.json"))
        for fixture in FixtureFile.model_validate(json.loads(path.read_text())).benign
        for call in fixture.tool_calls
    ]
    if not calls:
        raise FileNotFoundError(f"no benign fixture tool calls under {folder}")
    return calls
