"""Secret leak scanners (M2 A-04; PRD §9.3, §5.3, §5.4; built-ins B-01 and B-04).

The secret's **core** is its random part (`CONF-<24 random>` gives the 24 characters, as a
skeleton); the public prefix proves nothing (M2-DD-18).

- `scan`: one item. A **full** leak is the whole core (or the whole secret) in any view of the
  text: as written, normalized (skeleton), reversed, or decoded (URL, HTML and backslash
  escapes, ROT13, decimal bytes, hex with or without separators, base64 including spaced
  groups), with decoders applied up to two levels deep. A **partial** leak is any run of
  PARTIAL_MIN_CHARS core characters in any view. Partial leaks are blocked like full ones
  (B-01) but never count as delivery.
- `scan_cumulative`: Strict's cross-turn scan (D-06). The core counts as delivered across
  turns when every core position is covered by a piece of at least MIN_FRAGMENT_CHARS found
  anywhere in the joined visible output, in any order. Flags only the item that completes it.
- `echo_excluded`: the student typed the secret, or 8 or more consecutive characters of it,
  earlier in the session (PRD §5.3), compared on the skeleton.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import urllib.parse
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Literal

from app.firewall.textnorm import skeleton

LeakMethod = Literal[
    "exact", "normalized", "reversed", "base64", "hex", "url", "escape", "rot13", "decimal"
]

ECHO_WINDOW_CHARS = 8  # PRD §5.3
PARTIAL_MIN_CHARS = 12  # half of a 24-character random core
MIN_FRAGMENT_CHARS = 3  # "a few characters per reply" (PRD §5.4); shorter goes to the judge
CORE_MIN_CHARS = 16  # a trailing segment shorter than this is not a random core
MIN_ENCODED_BLOB = 16
MAX_DECODE_DEPTH = 2  # base64 of hex, double base64
_B64_ALIGNMENTS = 4  # a blob glued to a word may start up to 3 characters late
_JOINER = "\n"
_BYTE_MAX = 255

_SEGMENT_SPLIT = re.compile(r"[-_]")
_B64_RUN = re.compile(r"[A-Za-z0-9+/_-]{%d,}={0,2}" % MIN_ENCODED_BLOB)  # noqa: UP031
_B64_SPACED = re.compile(r"(?:[A-Za-z0-9+/]{4,}={0,2}[ \t]+){2,}[A-Za-z0-9+/]{2,}={0,2}")
_HEX_RUN = re.compile(r"[0-9A-Fa-f]{%d,}" % MIN_ENCODED_BLOB)  # noqa: UP031
_HEX_SEPARATED = re.compile(r"(?:(?:0x)?[0-9A-Fa-f]{2}[\s:,;.-]+){7,}(?:0x)?[0-9A-Fa-f]{2}", re.I)
_DECIMAL_BYTES = re.compile(r"\b(?:\d{1,3}[\s,;:]+){7,}\d{1,3}\b")
_BACKSLASH_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")
_HEX_PREFIX = re.compile(r"0x", re.I)
_NOT_HEX = re.compile(r"[^0-9A-Fa-f]")
_WS = re.compile(r"\s+")

Decoder = Callable[[str], Iterator[str]]


@dataclass(frozen=True)
class LeakMatch:
    method: LeakMethod
    cumulative: bool = False
    partial: bool = False


def secret_core(secret: str) -> str:
    full = skeleton(secret)
    if not full:
        raise ValueError("secret must contain at least one letter or digit")
    last = skeleton(_SEGMENT_SPLIT.split(secret)[-1])
    return last if CORE_MIN_CHARS <= len(last) < len(full) else full


# --- Decoders: each yields decoded text for every candidate blob in its input -----------------


def _utf8(data: bytes) -> str:
    return data.decode("utf-8", errors="ignore")


def _from_base64(text: str) -> Iterator[str]:
    blobs = [*_B64_RUN.findall(text), *(_WS.sub("", s) for s in _B64_SPACED.findall(text))]
    for blob in blobs:
        body = blob.rstrip("=")
        for start in range(_B64_ALIGNMENTS):
            chunk = body[start:]
            padded = chunk + "=" * (-len(chunk) % 4)
            for decode in (base64.b64decode, base64.urlsafe_b64decode):
                try:
                    yield _utf8(decode(padded))
                except (binascii.Error, ValueError):
                    continue


def _from_hex(text: str) -> Iterator[str]:
    separated = [_NOT_HEX.sub("", _HEX_PREFIX.sub("", m)) for m in _HEX_SEPARATED.findall(text)]
    for blob in [*_HEX_RUN.findall(text), *separated]:
        for start in (0, 1):
            chunk = blob[start:]
            chunk = chunk[: len(chunk) - len(chunk) % 2]
            try:
                yield _utf8(bytes.fromhex(chunk))
            except ValueError:
                continue


def _from_decimal(text: str) -> Iterator[str]:
    for run in _DECIMAL_BYTES.findall(text):
        values = [int(v) for v in re.findall(r"\d+", run)]
        if all(v <= _BYTE_MAX for v in values):
            yield _utf8(bytes(values))


def _from_escapes(text: str) -> Iterator[str]:
    if "&" in text:
        yield html.unescape(text)
    if "\\" in text:
        yield _BACKSLASH_ESCAPE.sub(lambda m: chr(int(m.group(1) or m.group(2), 16)), text)


def _from_url(text: str) -> Iterator[str]:
    if "%" in text or "+" in text:
        yield urllib.parse.unquote_plus(text)


_DECODERS: tuple[tuple[LeakMethod, Decoder], ...] = (
    ("url", _from_url),
    ("escape", _from_escapes),
    ("base64", _from_base64),
    ("hex", _from_hex),
    ("decimal", _from_decimal),
)


def _views(text: str) -> list[tuple[LeakMethod, str]]:
    """Every reading of `text` a student could decode, as (method, skeleton)."""
    views: list[tuple[LeakMethod, str]] = [
        ("normalized", skeleton(text)),
        ("rot13", skeleton(codecs.encode(text, "rot13"))),
    ]
    frontier: list[tuple[LeakMethod, str]] = [("normalized", text)]
    for _ in range(MAX_DECODE_DEPTH):
        decoded = [
            (method if outer == "normalized" else outer, out)
            for outer, source in frontier
            for method, decoder in _DECODERS
            for out in decoder(source)
        ]
        views += [(tag, skeleton(out)) for tag, out in decoded]
        frontier = decoded
    return views


def _windows(core: str, width: int) -> set[str]:
    return {core[i : i + width] for i in range(len(core) - width + 1)}


def scan(text: str, secret: str) -> LeakMatch | None:
    if not secret:
        raise ValueError("secret must be non-empty")
    core = secret_core(secret)
    if secret in text:
        return LeakMatch("exact")
    views = _views(text)
    for method, sk in views:
        if core in sk:
            return LeakMatch(method)
        if core[::-1] in sk:
            return LeakMatch("reversed" if method == "normalized" else method)
    width = min(PARTIAL_MIN_CHARS, len(core))
    windows = _windows(core, width) | _windows(core[::-1], width)
    for method, sk in views:
        if any(w in sk for w in windows):
            return LeakMatch(method, partial=True)
    return None


def covered_by_fragments(core: str, sk_text: str) -> bool:
    """True when every position of `core` lies inside some piece of it (at least
    MIN_FRAGMENT_CHARS long) that appears anywhere in `sk_text`, in any order."""
    n = len(core)
    if n <= MIN_FRAGMENT_CHARS:
        return core in sk_text
    covered = [False] * n
    for i in range(n - MIN_FRAGMENT_CHARS + 1):
        longest = 0
        for j in range(i + MIN_FRAGMENT_CHARS, n + 1):
            if core[i:j] not in sk_text:
                break  # a longer piece starting at i cannot appear either
            longest = j
        if longest:
            covered = covered[:i] + [True] * (longest - i) + covered[longest:]
    return all(covered)


def scan_cumulative(history: Sequence[str], new_item: str, secret: str) -> LeakMatch | None:
    """Strict's cross-turn scan. `history` is everything the student has already seen."""
    single = scan(new_item, secret)
    if single is not None and not single.partial:
        return single
    core = secret_core(secret)
    if covered_by_fragments(core, skeleton(_JOINER.join(history))):
        return single  # already visible before this item; this item completes nothing new
    if covered_by_fragments(core, skeleton(_JOINER.join([*history, new_item]))):
        return LeakMatch("normalized", cumulative=True)
    return single


def echo_excluded(student_inputs: Sequence[str], secret: str) -> bool:
    sk_secret = skeleton(secret)
    if not sk_secret:
        raise ValueError("secret must contain at least one letter or digit")
    width = min(ECHO_WINDOW_CHARS, len(sk_secret))
    windows = _windows(sk_secret, width)
    return any(
        any(window in typed for window in windows)
        for typed in (skeleton(text) for text in student_inputs)
    )
