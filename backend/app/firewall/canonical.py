"""Canonical tool calls (M2 A-01; PRD §7.6, §9.2 B-03; spec AEGIS-DOM-102).

Every check, the decoy and the mock tool use the same canonical call:

- the tool name must exactly match a registered tool (no folding, no trimming);
- arguments must validate against the tool's JSON schema, before and after normalization;
- every string is NFKC-normalized (not case-folded, so content keeps its meaning);
- email recipients are parsed to bare, lowercase addresses (display names dropped);
- paths are URL-decoded, NFKC-normalized and resolved inside the mock workspace (B-03);
- the call gets a SHA-256 hash of its canonical JSON form (C7 `args_hash`).

A failure returns a `CanonicalError`; callers deny it in every mode, Off included (M2-X01, X02).
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
import unicodedata
import urllib.parse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from email.utils import getaddresses
from types import MappingProxyType
from typing import Any, Literal

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from app.contracts.firewall import ToolDef

WORKSPACE_ROOT = "/workspace"
RECIPIENT_ARGS: Mapping[str, tuple[str, ...]] = MappingProxyType({"send_email": ("to",)})
PATH_ARGS: Mapping[str, tuple[str, ...]] = MappingProxyType({"read_file": ("path",)})
MAX_URL_DECODE_ROUNDS = 3  # %252e -> %2e -> . (double encoding), with headroom
HASH_PREFIX = "sha256:"
ERROR_DETAIL_MAX = 200

# No % or ! in the local part: legacy mail systems read them as source routes (M2-DD-09).
_LOCAL_PART = re.compile(r"[a-z0-9.#$&'*+/=?^_`{|}~-]+")
_STILL_ENCODED = re.compile(r"%[0-9A-Fa-f]{2}")
_DOMAIN = re.compile(r"[a-z0-9-]+(\.[a-z0-9-]+)+")

ErrorReason = Literal["unknown_tool", "schema_invalid", "bad_recipient", "bad_path"]


@dataclass(frozen=True)
class ResolvedPath:
    raw: str
    resolved: str  # relative to the workspace when inside, absolute when outside
    inside_workspace: bool


@dataclass(frozen=True)
class CanonicalCall:
    call_id: str
    tool: str
    high_risk: bool
    args: Mapping[str, Any]
    args_hash: str
    recipients: tuple[str, ...] = ()
    recipient_domains: tuple[str, ...] = ()
    paths: Mapping[str, ResolvedPath] = field(default_factory=lambda: MappingProxyType({}))


@dataclass(frozen=True)
class CanonicalError:
    reason: ErrorReason
    detail: str


class _Reject(Exception):
    def __init__(self, reason: ErrorReason, detail: str) -> None:
        super().__init__(detail)
        self.reason: ErrorReason = reason
        self.detail = detail


def _nfkc(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFKC", value)
    if isinstance(value, list):
        return [_nfkc(v) for v in value]
    if isinstance(value, dict):
        return {k: _nfkc(v) for k, v in value.items()}
    return value


def _validate(schema: Mapping[str, Any], args: Any) -> None:
    if not isinstance(args, dict):
        raise _Reject("schema_invalid", "arguments must be a JSON object")
    try:
        errors = list(Draft202012Validator(dict(schema)).iter_errors(args))
    except (SchemaError, re.error, TypeError, ValueError, RecursionError) as exc:
        raise _Reject("schema_invalid", f"schema check failed: {type(exc).__name__}") from exc
    if errors:
        raise _Reject("schema_invalid", errors[0].message[:ERROR_DETAIL_MAX])


def _address(addr: str) -> str:
    candidate = addr.strip().lower()
    local, at, domain = candidate.partition("@")
    if not at or not _LOCAL_PART.fullmatch(local) or not _DOMAIN.fullmatch(domain):
        raise _Reject("bad_recipient", "malformed recipient address")
    return candidate


def _recipients(value: str) -> tuple[str, ...]:
    addresses = tuple(_address(addr) for _, addr in getaddresses([value]))
    if not addresses:
        raise _Reject("bad_recipient", "no recipient")
    # The parser silently rewrites some inputs ("a@exa mple.com" -> "a@example.com", comments
    # dropped). Every address must appear verbatim in what the model wrote, or the checks
    # would judge a different recipient than the one written.
    written = value.lower()
    if any(addr not in written for addr in addresses):
        raise _Reject("bad_recipient", "recipient was rewritten by parsing")
    return addresses


def _url_decode(value: str) -> str:
    current = value
    for _ in range(MAX_URL_DECODE_ROUNDS):
        decoded = urllib.parse.unquote(current)
        if decoded == current:
            break
        current = decoded
    return unicodedata.normalize("NFKC", current)


def _resolve_path(raw: str) -> ResolvedPath:
    decoded = _url_decode(raw)
    if _STILL_ENCODED.search(decoded):
        raise _Reject("bad_path", "path is still URL-encoded after decoding")
    if any(unicodedata.category(ch) in ("Cc", "Cf") for ch in decoded):
        raise _Reject("bad_path", "control or format character in path")
    slashed = decoded.replace("\\", "/")
    if slashed.startswith("/"):
        absolute = posixpath.normpath("/" + slashed.lstrip("/"))
    else:
        absolute = posixpath.normpath(posixpath.join(WORKSPACE_ROOT, slashed))
    if absolute == WORKSPACE_ROOT or absolute.startswith(WORKSPACE_ROOT + "/"):
        return ResolvedPath(raw, absolute[len(WORKSPACE_ROOT) + 1 :], inside_workspace=True)
    return ResolvedPath(raw, absolute, inside_workspace=False)


def resolve_workspace_path(raw: str) -> ResolvedPath | None:
    """Public form of the B-03 path resolution, for the mock shell. None means rejected."""
    try:
        return _resolve_path(unicodedata.normalize("NFKC", raw))
    except _Reject:
        return None


def args_hash(tool: str, args: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        {"tool": tool, "args": dict(args)},
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return HASH_PREFIX + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _text_arg(args: Mapping[str, Any], name: str) -> str:
    value = args.get(name)
    if not isinstance(value, str):
        raise _Reject("schema_invalid", f"argument {name!r} must be text")
    return value


def _build(tool: ToolDef, raw_args: Any, call_id: str) -> CanonicalCall:
    _validate(tool.json_schema, raw_args)
    args: dict[str, Any] = _nfkc(raw_args)
    recipients: tuple[str, ...] = ()
    for name in RECIPIENT_ARGS.get(tool.name, ()):
        parsed = _recipients(_text_arg(args, name))
        recipients = (*recipients, *parsed)
        args = {**args, name: ", ".join(parsed)}
    paths: dict[str, ResolvedPath] = {}
    for name in PATH_ARGS.get(tool.name, ()):
        resolved = _resolve_path(_text_arg(args, name))
        paths = {**paths, name: resolved}
        args = {**args, name: resolved.resolved}
    _validate(tool.json_schema, args)  # normalization can lengthen strings
    return CanonicalCall(
        call_id=call_id,
        tool=tool.name,
        high_risk=tool.high_risk,
        args=MappingProxyType(args),
        args_hash=args_hash(tool.name, args),
        recipients=recipients,
        recipient_domains=tuple(addr.partition("@")[2] for addr in recipients),
        paths=MappingProxyType(paths),
    )


def canonicalize(
    tool_name: str, raw_args: Any, tools: Sequence[ToolDef], call_id: str
) -> CanonicalCall | CanonicalError:
    tool = next((t for t in tools if t.name == tool_name), None)
    if tool is None:
        return CanonicalError("unknown_tool", "tool is not registered for this session")
    try:
        return _build(tool, raw_args, call_id)
    except _Reject as rejected:
        return CanonicalError(rejected.reason, rejected.detail)
    except Exception as exc:  # any other surprise fails closed (Deny)
        return CanonicalError("schema_invalid", f"unexpected argument shape: {type(exc).__name__}")
