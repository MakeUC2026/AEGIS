"""M2 A-01 canonical tool calls (spec AEGIS-DOM-102; PRD §7.6, §9.2 B-03).

Cases: M2-X01 (unknown tool), M2-X02 (schema), M2-X03 (recipients), M2-X04 (paths).
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from app.arena.scenario_data import TOOLS
from app.contracts.firewall import ToolDef
from app.firewall.canonical import CanonicalCall, CanonicalError, canonicalize

DEFS = [
    ToolDef(name=t["name"], json_schema=t["json_schema"], high_risk=t["high_risk"]) for t in TOOLS
]
FULLWIDTH_Q3 = "\uff31\uff13"
FULLWIDTH_EMAIL = "\uff41@\uff45\uff56\uff49\uff4c\uff0e\uff43\uff4f\uff4d"  # a@evil.com
FULLWIDTH_DOTS = "\uff0e\uff0e"
TWO_DOT_LEADER = "\u2025"


def _ok(tool: str, args: Any) -> CanonicalCall:
    result = canonicalize(tool, args, DEFS, call_id="c1")
    assert isinstance(result, CanonicalCall), result
    return result


def _err(tool: str, args: Any) -> CanonicalError:
    result = canonicalize(tool, args, DEFS, call_id="c1")
    assert isinstance(result, CanonicalError), result
    return result


def _mail(to: str) -> dict[str, str]:
    return {"to": to, "subject": "s", "body": "b"}


# --- M2-X01: tool name must match exactly --------------------------------------------------


@pytest.mark.parametrize(
    "name", ["delete_everything", "Send_Email", "send_email ", " read_file", ""]
)
def test_unknown_or_inexact_tool_name_is_rejected(name: str) -> None:
    assert _err(name, {"query": "x"}).reason == "unknown_tool"


def test_known_tool_carries_its_risk_flag_and_call_id() -> None:
    call = _ok("send_email", _mail("a@company.example"))
    assert (call.tool, call.high_risk, call.call_id) == ("send_email", True, "c1")
    assert _ok("search_docs", {"query": "q3"}).high_risk is False


# --- M2-X02: JSON schema --------------------------------------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        {"query": 42},  # wrong type
        {},  # missing required
        {"query": "q", "extra": "x"},  # extra field
        ["query"],  # not an object
        None,
        {"query": "x" * 201},  # over the schema's maxLength
    ],
)
def test_schema_violations_are_rejected(args: Any) -> None:
    assert _err("search_docs", args).reason == "schema_invalid"


# --- M2-X03: recipients ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("to", "domains", "addresses"),
    [
        ("a@company.example", ("company.example",), ("a@company.example",)),
        ("X@COMPANY.EXAMPLE", ("company.example",), ("x@company.example",)),
        (
            "a@company.example.evil.com",
            ("company.example.evil.com",),
            ("a@company.example.evil.com",),
        ),
        ('"CEO" <x@evil.com>', ("evil.com",), ("x@evil.com",)),
        (
            "a@company.example, b@evil.com",
            ("company.example", "evil.com"),
            ("a@company.example", "b@evil.com"),
        ),
        (FULLWIDTH_EMAIL, ("evil.com",), ("a@evil.com",)),  # NFKC
    ],
)
def test_recipients_are_parsed_to_bare_lowercase_addresses(
    to: str, domains: tuple[str, ...], addresses: tuple[str, ...]
) -> None:
    call = _ok("send_email", _mail(to))
    assert call.recipient_domains == domains
    assert call.recipients == addresses
    assert call.args["to"] == ", ".join(addresses)  # one canonical form for every check


@pytest.mark.parametrize(
    "to", ["not an email", "a@", "@evil.com", "a@b@c.com", "", "a@exa mple.com"]
)
def test_malformed_recipients_are_rejected(to: str) -> None:
    assert _err("send_email", _mail(to)).reason == "bad_recipient"


def test_display_name_does_not_change_the_hash() -> None:
    plain = _ok("send_email", _mail("x@evil.com"))
    named = _ok("send_email", _mail('"Boss" <X@Evil.com>'))
    assert plain.args_hash == named.args_hash


# --- M2-X04: paths resolved inside the mock filesystem (B-03) ------------------------------


@pytest.mark.parametrize(
    ("raw", "resolved", "inside"),
    [
        ("docs/faq.md", "docs/faq.md", True),
        ("./docs/faq.md", "docs/faq.md", True),
        ("docs/../docs/faq.md", "docs/faq.md", True),
        ("docs\\faq.md", "docs/faq.md", True),
        ("../secrets.txt", "/secrets.txt", False),
        ("/etc/passwd", "/etc/passwd", False),
        ("%2e%2e/%2e%2e/etc/passwd", "/etc/passwd", False),
        ("%252e%252e/etc/passwd", "/etc/passwd", False),  # double-encoded
        (f"{FULLWIDTH_DOTS}/etc/passwd", "/etc/passwd", False),  # NFKC look-alike dots
        (f"docs/{TWO_DOT_LEADER}/{TWO_DOT_LEADER}/x", "/x", False),  # becomes ".."
        ("/workspace/docs/faq.md", "docs/faq.md", True),
    ],
)
def test_paths_resolve_inside_the_workspace(raw: str, resolved: str, inside: bool) -> None:
    call = _ok("read_file", {"path": raw})
    path = call.paths["path"]
    assert (path.resolved, path.inside_workspace) == (resolved, inside)
    assert call.args["path"] == resolved


@pytest.mark.parametrize("raw", ["docs/\x00faq.md", "docs/faq\x07.md", "docs/%00faq.md"])
def test_control_characters_in_paths_are_rejected(raw: str) -> None:
    assert _err("read_file", {"path": raw}).reason == "bad_path"


# --- Canonical form and hash ----------------------------------------------------------------


def test_strings_are_nfkc_normalized_but_not_casefolded() -> None:
    assert _ok("search_docs", {"query": f"{FULLWIDTH_Q3} Planning"}).args["query"] == "Q3 Planning"


def test_hash_is_stable_and_sensitive_to_content() -> None:
    a = _ok("query_db", {"sql": "SELECT 1"})
    b = _ok("query_db", {"sql": "SELECT 1"})
    c = _ok("query_db", {"sql": "SELECT 2"})
    assert a.args_hash == b.args_hash != c.args_hash
    assert a.args_hash.startswith("sha256:") and len(a.args_hash) == len("sha256:") + 64


def test_canonical_args_cannot_be_mutated() -> None:
    call = _ok("search_docs", {"query": "q"})
    with pytest.raises(TypeError):
        call.args["query"] = "other"  # type: ignore[index]


# --- Properties --------------------------------------------------------------------------------

json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=50),
    lambda children: (
        st.lists(children, max_size=3) | st.dictionaries(st.text(max_size=10), children, max_size=3)
    ),
    max_leaves=10,
)


@settings(max_examples=300)
@given(tool=st.sampled_from([t.name for t in DEFS] + ["nope"]), args=json_values)
def test_property_never_raises(tool: str, args: Any) -> None:
    result = canonicalize(tool, args, DEFS, call_id="c1")
    assert isinstance(result, CanonicalCall | CanonicalError)


@settings(max_examples=300)
@given(path=st.text(max_size=80))
def test_property_inside_paths_never_escape(path: str) -> None:
    result = canonicalize("read_file", {"path": path}, DEFS, call_id="c1")
    if isinstance(result, CanonicalCall) and result.paths["path"].inside_workspace:
        resolved = result.paths["path"].resolved
        assert not resolved.startswith("/")
        assert ".." not in resolved.split("/")
