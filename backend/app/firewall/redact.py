"""Secret redaction for the C3 read API (M2 C-11; PRD §14.4; spec AEGIS-DOM-126).

`redact_secret(text, secret)` returns the text with the level secret replaced by `[SECRET]`:

1. the exact secret, and its last segment (the random part, without the public prefix), in
   any letter case;
2. the normalized forms the A-04 scanner works on: the core is searched in the text's
   skeleton (letters and digits only, case-folded, look-alike letters folded, zero-width
   characters dropped), forward and reversed, and the original characters it came from, with
   whatever sits between them, are replaced as one span;
3. a last safety check with the full scanner: if anything still matches (an encoded form such
   as base64 or hex, or a partial run of 12 or more characters), the whole text is replaced by
   the placeholder. Losing a message is better than showing the secret.
"""

from __future__ import annotations

import re
from functools import lru_cache

from app.contracts.firewall_read import SECRET_PLACEHOLDER
from app.firewall.leak import scan, secret_core
from app.firewall.textnorm import skeleton

_SEGMENT_SPLIT = re.compile(r"[-_]")


@lru_cache(maxsize=4096)
def _skel_char(ch: str) -> str:
    return skeleton(ch)


def _skeleton_spans(text: str, core: str) -> list[tuple[int, int]]:
    """Inclusive (start, end) character spans of `text` whose skeleton holds the core,
    forward or reversed."""
    letters: list[str] = []
    origin: list[int] = []
    for i, ch in enumerate(text):
        for piece in _skel_char(ch):
            letters.append(piece)
            origin.append(i)
    joined = "".join(letters)
    spans: list[tuple[int, int]] = []
    for needle in (core, core[::-1]):
        at = joined.find(needle)
        while at != -1:
            spans.append((origin[at], origin[at + len(needle) - 1]))
            at = joined.find(needle, at + len(needle))
    return spans


def _merged(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def redact_secret(text: str, secret: str) -> str:
    if not text or not secret:
        return text
    tail = _SEGMENT_SPLIT.split(secret)[-1]
    out = text
    for needle in sorted({secret, tail}, key=len, reverse=True):
        out = re.sub(re.escape(needle), SECRET_PLACEHOLDER, out, flags=re.IGNORECASE)
    for start, end in reversed(_merged(_skeleton_spans(out, secret_core(secret)))):
        out = out[:start] + SECRET_PLACEHOLDER + out[end + 1 :]
    if scan(out, secret) is not None:
        return SECRET_PLACEHOLDER
    return out
