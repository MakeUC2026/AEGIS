"""Text normalization for matching (M2 A-03, PRD §9.1; spec AEGIS-DOM-101).

`normalize`: NFKC, format and control characters removed (zero-width, bidi overrides, NUL),
case-folded, combining marks stripped, common look-alike letters (Cyrillic, Greek) folded to
Latin, whitespace collapsed to one space. With `invisible_as_space=True`, format characters
become spaces instead, so "ignore<zero-width>previous" still reads as two words (rules try
both forms, M2-DD-17).

`skeleton`: `normalize`, then letters and digits only. Used by the secret scanners, so
spacing, zero-width characters, separators, case, accents and look-alikes cannot hide a
secret (PRD §9.3).
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from types import MappingProxyType

_WHITESPACE = re.compile(r"\s+")
_MAX_PASSES = 4  # the folds reach a fixed point in at most a couple of passes

# Lower-case look-alikes that NFKC leaves alone (a common subset of Unicode confusables),
# written as code points so the source itself stays plain ASCII.
CONFUSABLES: Mapping[int, str] = MappingProxyType(
    {
        # Cyrillic
        0x0430: "a", 0x0432: "b", 0x0435: "e", 0x0455: "s", 0x0456: "i", 0x0457: "i",
        0x0458: "j", 0x043A: "k", 0x043C: "m", 0x043D: "h", 0x043E: "o", 0x0440: "p",
        0x0441: "c", 0x0442: "t", 0x0443: "y", 0x0445: "x", 0x0491: "r", 0x04BB: "h",
        0x04CF: "l", 0x0501: "d", 0x051B: "q", 0x051D: "w",
        # Greek
        0x03B1: "a", 0x03B2: "b", 0x03B5: "e", 0x03B7: "n", 0x03B9: "i", 0x03BA: "k",
        0x03BD: "v", 0x03BF: "o", 0x03C1: "p", 0x03C4: "t", 0x03C5: "u", 0x03C7: "x",
        0x03C9: "w",
        # Latin oddities
        0x0131: "i", 0x01C0: "l", 0x0251: "a", 0x0261: "g",
    }
)  # fmt: skip
_CONFUSABLE_TABLE = dict(CONFUSABLES)


def _strip_invisible(text: str, replacement: str) -> str:
    # Unicode category C*: control, format, surrogate, private use, unassigned.
    # Whitespace controls (tab, newline) are kept here and collapsed below.
    return "".join(
        ch if ch.isspace() or not unicodedata.category(ch).startswith("C") else replacement
        for ch in text
    )


def _fold(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text.casefold())
    unmarked = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    return unicodedata.normalize("NFKC", unmarked.translate(_CONFUSABLE_TABLE))


def _one_pass(text: str, replacement: str) -> str:
    nfkc = unicodedata.normalize("NFKC", _strip_invisible(text, replacement))
    cleaned = _strip_invisible(_fold(nfkc), replacement)
    return _WHITESPACE.sub(" ", cleaned).strip()


def normalize(text: str, invisible_as_space: bool = False) -> str:
    replacement = " " if invisible_as_space else ""
    current = _one_pass(text, replacement)
    for _ in range(_MAX_PASSES):
        following = _one_pass(current, replacement)
        if following == current:
            return current
        current = following
    return current


def skeleton(text: str) -> str:
    return "".join(ch for ch in normalize(text) if ch.isalnum())
