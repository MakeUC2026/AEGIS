"""Sentinel layer 1: deterministic signals (M2 A-06; PRD §7.3; spec AEGIS-DOM-104).

One score from 0 to 100 per checked item, built from:
- rule weights (score-only and weighted rules; forcing rules show 0 and act in the Gatekeeper),
- keywords (10 per hit, max 30), encoding or obfuscation (+20),
- earlier denies in this session (10 each, max 30), rapid retries (+10 past 5 in 60 s),
- a high-risk tool proposed (+15), untrusted content just read this turn (+10).

Point values come from the level's weights (M1 seed keys, M2-DD-05). It also reports B-02:
an approval attributed to an authority inside a tool result read this turn, followed by a
high-risk call. A bare "already approved" is not enough (M2-DD-14).
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from types import MappingProxyType

from app.firewall.canonical import CanonicalCall
from app.firewall.rules import RuleHit
from app.firewall.textnorm import normalize

MAX_SCORE = 100
RAPID_WINDOW = timedelta(seconds=60)
RAPID_MAX_MESSAGES = 5  # more than this many in the window adds the signal

KEYWORDS: tuple[str, ...] = (
    "system prompt",
    "base64",
    "reveal",
    "exfiltrate",
    "secret",
    "password",
    "credential",
)
_KEYWORD_PATTERNS = tuple(re.compile(rf"\b{re.escape(k)}s?\b") for k in KEYWORDS)

_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_HEX_BLOB = re.compile(r"\b[0-9a-fA-F]{16,}\b")
_SPACED_WORD = re.compile(r"(?<!\S)(?:\w ){4,}\w(?!\S)")  # "s y s t e m"
_FORGED_APPROVAL = re.compile(
    r"\b(approved|authori[sz]ed|signed off|cleared|granted)\s+by\b"  # credited to anyone
    r"|\b(admin|administrator)\s+(has\s+)?(approved|authori[sz]ed)\b"
    r"|\bpre-?approved\b|\bapproval\s+(granted|code|id|number|ref(erence)?)\b"
)

SIGNAL_KEYS: tuple[str, ...] = (
    "keyword",
    "encoding",
    "session_denies",
    "rapid_retries",
    "high_risk_tool",
    "untrusted_context",
)


@dataclass(frozen=True)
class Layer1Input:
    raw_text: str
    now: datetime
    rule_hits: tuple[RuleHit, ...] = ()
    call: CanonicalCall | None = None
    earlier_denies: int = 0
    recent_message_times: tuple[datetime, ...] = ()
    tool_result_read_this_turn: bool = False
    tool_results_this_turn: tuple[str, ...] = ()
    check_forged_approval: bool = True  # B-02 can be switched off by an admin (C-12)


@dataclass(frozen=True)
class Layer1Result:
    score: int
    breakdown: Mapping[str, int | None] = field(default_factory=lambda: MappingProxyType({}))
    forged_approval: bool = False


def _capped(per: int, count: int, cap: int) -> int:
    return min(per * count, cap)


def _keyword_hits(text: str) -> int:
    normalized = normalize(text)
    return sum(1 for pattern in _KEYWORD_PATTERNS if pattern.search(normalized))


def _has_mixed_blob(pattern: re.Pattern[str], text: str) -> bool:
    for blob in pattern.findall(text):
        has_digit = any(ch.isdigit() for ch in blob)
        has_alpha = any(ch.isalpha() for ch in blob)
        if has_digit and has_alpha:
            return True
    return False


def _obfuscated(raw: str) -> bool:
    if any(unicodedata.category(ch) == "Cf" for ch in raw):
        return True  # zero-width or bidi controls in what was written
    nfkc = unicodedata.normalize("NFKC", raw)
    return (
        _has_mixed_blob(_BASE64_BLOB, nfkc)
        or _has_mixed_blob(_HEX_BLOB, nfkc)
        or bool(_SPACED_WORD.search(normalize(raw)))
    )


def _rapid(times: Sequence[datetime], now: datetime) -> bool:
    return sum(1 for t in times if now - RAPID_WINDOW <= t <= now) > RAPID_MAX_MESSAGES


def forged_approval(call: CanonicalCall | None, tool_results: Sequence[str]) -> bool:
    if call is None or not call.high_risk:
        return False
    return any(_FORGED_APPROVAL.search(normalize(result)) for result in tool_results)


def layer1(inp: Layer1Input, weights: Mapping[str, int]) -> Layer1Result:
    high_risk = inp.call is not None and inp.call.high_risk
    signals = {
        "keyword": _capped(
            weights["keyword_per_hit"], _keyword_hits(inp.raw_text), weights["keyword_max"]
        ),
        "encoding": weights["encoding"] if _obfuscated(inp.raw_text) else 0,
        "session_denies": _capped(
            weights["session_deny_per"], max(inp.earlier_denies, 0), weights["session_deny_max"]
        ),
        "rapid_retries": weights["rapid_retries"]
        if _rapid(inp.recent_message_times, inp.now)
        else 0,
        "high_risk_tool": weights["high_risk_tool"] if high_risk else 0,
        "untrusted_context": weights["untrusted_context"]
        if high_risk and inp.tool_result_read_this_turn
        else 0,
    }
    rules = {hit.rule_id: hit.weight or 0 for hit in inp.rule_hits}
    total = sum(rules.values()) + sum(signals.values())
    return Layer1Result(
        score=min(total, MAX_SCORE),
        breakdown=MappingProxyType({**rules, **signals}),
        forged_approval=inp.check_forged_approval
        and forged_approval(inp.call, inp.tool_results_this_turn),
    )
