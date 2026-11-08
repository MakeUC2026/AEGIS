"""Text normalization for matching (M2 A-03, PRD §9.1; spec AEGIS-DOM-101).

`normalize`: NFKC, format and control characters removed (zero-width, bidi overrides, NUL),
whitespace collapsed to one space, case-folded. Used by rules and keyword matching.

`skeleton`: `normalize`, then letters and digits only. Used by the secret scanners, so
spacing, zero-width characters, separators and case cannot hide a secret (PRD §9.3).
"""

from __future__ import annotations

import re
import unicodedata

_WHITESPACE = re.compile(r"\s+")
_MAX_PASSES = 4  # NFKC and casefold reach a fixed point in at most a couple of passes


def _drop_invisible(text: str) -> str:
    # Unicode category C*: control, format, surrogate, private use, unassigned.
    # Whitespace controls (tab, newline) are kept here and collapsed below.
    return "".join(
        ch for ch in text if ch.isspace() or not unicodedata.category(ch).startswith("C")
    )


def _one_pass(text: str) -> str:
    folded = unicodedata.normalize("NFKC", _drop_invisible(text)).casefold()
    cleaned = _drop_invisible(unicodedata.normalize("NFKC", folded))
    return _WHITESPACE.sub(" ", cleaned).strip()


def normalize(text: str) -> str:
    current = _one_pass(text)
    for _ in range(_MAX_PASSES):
        following = _one_pass(current)
        if following == current:
            return current
        current = following
    return current


def skeleton(text: str) -> str:
    return "".join(ch for ch in normalize(text) if ch.isalnum())
