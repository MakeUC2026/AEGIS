"""Secret leak scanners (M2 A-04; PRD §9.3, §5.3, §5.4; built-ins B-01 and B-04).

- `scan`: one item. Exact, then normalized (case, spacing, zero-width, separators via the
  skeleton), reversed, and decoded forms (base64, hex, URL encoding).
- `scan_cumulative`: the session's visible output joined in order plus the new item
  (Strict, D-06). The secret counts as delivered across turns when its skeleton can be
  rebuilt, in order, from fragments of at least MIN_FRAGMENT_CHARS characters found in the
  joined output (other words may sit between fragments). Reports a hit only when the new
  item completes the secret (M2-DD-07).
- `echo_excluded`: the student typed the secret, or 8 or more consecutive characters of it,
  earlier in the session (compared on the skeleton), so a delivery does not count.

Pure functions. Callers decide what a hit means per mode (Deny, Divert or report).
"""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Literal

from app.firewall.textnorm import skeleton

LeakMethod = Literal["exact", "normalized", "reversed", "base64", "hex", "url"]

ECHO_WINDOW_CHARS = 8  # PRD §5.3
MIN_ENCODED_BLOB = 16  # shorter blobs cannot hold a secret and are mostly ordinary words
_B64_RUN = re.compile(r"[A-Za-z0-9+/_-]{%d,}={0,2}" % MIN_ENCODED_BLOB)  # noqa: UP031
_HEX_RUN = re.compile(r"[0-9A-Fa-f]{%d,}" % MIN_ENCODED_BLOB)  # noqa: UP031
_B64_ALIGNMENTS = 4  # a blob glued to a word may start up to 3 characters late
_JOINER = "\n"
MIN_FRAGMENT_CHARS = 3  # "a few characters per reply" (PRD §5.4); shorter pieces go to the judge


@dataclass(frozen=True)
class LeakMatch:
    method: LeakMethod
    cumulative: bool = False


def _secret_skeleton(secret: str) -> str:
    sk = skeleton(secret)
    if not sk:
        raise ValueError("secret must contain at least one letter or digit")
    return sk


def _b64_candidates(text: str) -> Iterator[str]:
    for run in _B64_RUN.findall(text):
        body = run.rstrip("=")
        for start in range(_B64_ALIGNMENTS):
            chunk = body[start:]
            padded = chunk + "=" * (-len(chunk) % 4)
            for decode in (base64.b64decode, base64.urlsafe_b64decode):
                try:
                    yield decode(padded).decode("utf-8", errors="ignore")
                except (binascii.Error, ValueError):
                    continue


def _hex_candidates(text: str) -> Iterator[str]:
    for run in _HEX_RUN.findall(text):
        for start in (0, 1):
            chunk = run[start:]
            chunk = chunk[: len(chunk) - len(chunk) % 2]
            try:
                yield bytes.fromhex(chunk).decode("utf-8", errors="ignore")
            except ValueError:
                continue


def _contains(sk_secret: str, text: str) -> bool:
    return sk_secret in skeleton(text)


def scan(text: str, secret: str) -> LeakMatch | None:
    if not secret:
        raise ValueError("secret must be non-empty")
    sk_secret = _secret_skeleton(secret)
    if secret in text:
        return LeakMatch("exact")
    sk_text = skeleton(text)
    if sk_secret in sk_text:
        return LeakMatch("normalized")
    if sk_secret[::-1] in sk_text:
        return LeakMatch("reversed")
    if any(_contains(sk_secret, decoded) for decoded in _b64_candidates(text)):
        return LeakMatch("base64")
    if any(_contains(sk_secret, decoded) for decoded in _hex_candidates(text)):
        return LeakMatch("hex")
    if "%" in text and _contains(sk_secret, urllib.parse.unquote_plus(text)):
        return LeakMatch("url")
    return None


def covered_by_fragments(sk_secret: str, sk_text: str) -> bool:
    """True when `sk_secret` is a concatenation of pieces (each at least MIN_FRAGMENT_CHARS
    long) that appear in `sk_text` in the same order, possibly with other text between.

    reach[i] is the earliest end position in sk_text after which secret[i:] can still be
    placed; an earlier end never hurts, so the minimum is enough (O(n^2) finds, n = secret).
    """
    n = len(sk_secret)
    if n <= MIN_FRAGMENT_CHARS:
        return sk_secret in sk_text
    unreached = len(sk_text) + 1
    reach = [0] + [unreached] * n
    for i in range(n):
        if reach[i] == unreached:
            continue
        for j in range(i + MIN_FRAGMENT_CHARS, n + 1):
            found = sk_text.find(sk_secret[i:j], reach[i])
            if found < 0:
                break  # a longer piece starting at i cannot be found either
            reach[j] = min(reach[j], found + (j - i))
    return reach[n] != unreached


def scan_cumulative(history: Sequence[str], new_item: str, secret: str) -> LeakMatch | None:
    """Strict's cross-turn scan. `history` is everything the student has already seen."""
    single = scan(new_item, secret)
    if single is not None:
        return single
    sk_secret = _secret_skeleton(secret)
    if covered_by_fragments(sk_secret, skeleton(_JOINER.join(history))):
        return None  # already visible before this item; this item completes nothing
    if covered_by_fragments(sk_secret, skeleton(_JOINER.join([*history, new_item]))):
        return LeakMatch("normalized", cumulative=True)
    return None


def echo_excluded(student_inputs: Sequence[str], secret: str) -> bool:
    sk_secret = _secret_skeleton(secret)
    width = min(ECHO_WINDOW_CHARS, len(sk_secret))
    windows = {sk_secret[i : i + width] for i in range(len(sk_secret) - width + 1)}
    return any(
        any(window in typed for window in windows)
        for typed in (skeleton(text) for text in student_inputs)
    )
