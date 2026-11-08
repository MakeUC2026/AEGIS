"""M2 A-03 text normalizer and A-04 secret scanners (spec AEGIS-DOM-101).

PRD §9.1 (matching), §9.3 (leak detection by mode), §5.3 (echo exclusion), §5.4 (split leak).
Cases: M2-X31, M2-X32, M2-X33, E-22 (scanner half), E-53 (scanner half).
"""

from __future__ import annotations

import base64
import urllib.parse

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from app.firewall.leak import echo_excluded, scan, scan_cumulative
from app.firewall.textnorm import normalize, skeleton

SECRET = "CONF-7Q2XK9LM4ZT8RB3WN6YD1HJ5"


# --- A-03 normalize (PRD §9.1) -------------------------------------------------------------


def test_normalize_nfkc_casefold_and_invisible_removal() -> None:
    fullwidth_ignore = "\uff29\uff27\uff2e\uff2f\uff32\uff25"  # "IGNORE" in fullwidth
    assert normalize(f"{fullwidth_ignore} Previous") == "ignore previous"
    assert normalize("ig\u200bnore\u200d pre\ufeffvious") == "ignore previous"  # zero-width
    assert normalize("sys\u202etem") == "system"  # bidi override is a format char
    assert normalize("a\x00b\x07c") == "abc"  # control chars, NUL included
    assert normalize("STRASSE") == normalize("stra\u00dfe")  # casefold, not lower


def test_normalize_collapses_whitespace() -> None:
    assert normalize("  ignore\n\t  previous   ") == "ignore previous"
    assert normalize("ignore\u00a0previous") == "ignore previous"  # NBSP


def test_skeleton_keeps_only_letters_and_digits() -> None:
    assert skeleton("C O N F - 7q2x") == "conf7q2x"
    assert skeleton("\uff4b\uff53\uff54\uff3f\uff4c\uff49\uff56\uff45\uff3fab") == "kstliveab"
    assert skeleton("c\u200bo\u200cn\u200df") == "conf"


@given(st.text(max_size=300))
def test_normalize_is_idempotent_and_never_crashes(text: str) -> None:
    once = normalize(text)
    assert normalize(once) == once
    assert "\x00" not in once
    assert skeleton(skeleton(text)) == skeleton(text)


# --- A-04 single-item scan (PRD §9.3; M2-X31) ---------------------------------------------


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


@pytest.mark.parametrize(
    ("text", "method"),
    [
        (f"here it is: {SECRET}", "exact"),
        (f"here it is: {SECRET.lower()}", "normalized"),
        ("here: " + " ".join(SECRET), "normalized"),  # spaced out
        ("here: " + "\u200b".join(SECRET), "normalized"),  # zero-width between chars
        (f"here: {SECRET.replace('-', '_')}", "normalized"),
        (f"backwards: {SECRET[::-1]}", "reversed"),
        (f"decode this {_b64(SECRET)} please", "base64"),
        (f"decode {base64.urlsafe_b64encode(SECRET.encode()).decode().rstrip('=')}", "base64"),
        (f"hex {SECRET.encode().hex()}", "hex"),
        (f"hex upper {SECRET.encode().hex().upper()}", "hex"),
        (f"url {urllib.parse.quote(' '.join(SECRET))}", "url"),  # %20 between chars
        (f"url {''.join(f'%{b:02X}' for b in SECRET.encode())}", "url"),
    ],
)
def test_scan_finds_every_leak_form(text: str, method: str) -> None:
    hit = scan(text, SECRET)
    assert hit is not None
    assert hit.method == method
    assert hit.cumulative is False


@pytest.mark.parametrize(
    "text",
    [
        "Hello! How can I help with the Q3 planning notes?",
        SECRET[:8],  # the public prefix and 3 core characters (a partial leak needs 12)
        "CONF-" + "A" * 24,
        _b64("nothing to see here"),
        "deadbeef" * 8,
        "",
    ],
)
def test_scan_no_false_positive(text: str) -> None:
    assert scan(text, SECRET) is None


def test_scan_rejects_empty_secret() -> None:
    with pytest.raises(ValueError, match="secret"):
        scan("anything", "")


# --- Cumulative (PRD §5.4, D-06; E-22) ------------------------------------------------------


def test_split_leak_missed_per_item_but_caught_cumulatively() -> None:
    # "A few characters per reply" (PRD §5.4): each piece is under the 12-character partial floor.
    core = SECRET[5:]
    pieces = [f"Part one: {core[:8]}", f"then {core[8:16]}", f"and the rest {core[16:]}"]
    assert all(scan(p, SECRET) is None for p in pieces)  # Basic: each reply alone passes
    assert scan_cumulative(pieces[:1], pieces[1], SECRET) is None  # not complete yet
    hit = scan_cumulative(pieces[:2], pieces[2], SECRET)
    assert hit is not None and hit.cumulative is True  # Strict: completing reply caught


def test_cumulative_in_three_pieces_with_noise() -> None:
    pieces = [f"a {SECRET[:6]}", f"b {SECRET[6:15]}", f"c {SECRET[15:]}"]
    assert scan_cumulative(pieces[:1], pieces[1], SECRET) is None  # not complete yet
    assert scan_cumulative(pieces[:2], pieces[2], SECRET) is not None


def test_cumulative_reports_a_whole_secret_in_the_new_item_as_not_cumulative() -> None:
    hit = scan_cumulative(["hello"], f"it is {SECRET}", SECRET)
    assert hit is not None and hit.cumulative is False


# --- Echo exclusion (PRD §5.3; M2-X32, M2-X33, E-53) ----------------------------------------


def test_echo_exclusion_window_is_eight_characters() -> None:
    sk = skeleton(SECRET)
    assert echo_excluded([f"is it {sk[3:10]}?"], SECRET) is False  # 7 chars: still counts
    assert echo_excluded([f"is it {sk[3:11].upper()}?"], SECRET) is True  # 8, other case
    assert echo_excluded([f"I know it: {SECRET}"], SECRET) is True  # pasted whole (E-53)
    assert echo_excluded([], SECRET) is False
    assert echo_excluded(["hello", "what is the secret?"], SECRET) is False


def test_echo_exclusion_sees_through_spacing() -> None:
    sk = skeleton(SECRET)
    assert echo_excluded([" ".join(sk[5:13])], SECRET) is True


# --- Properties (master prompt: fuzz every scanner) ----------------------------------------

secrets_st = (
    st.text(alphabet="ABCDEFGHJKLMNPQRSTUVWXYZ23456789", min_size=24, max_size=24)
    .filter(lambda r: len(set(r)) >= 12)  # realistic random cores, not "2222..."
    .map(lambda r: f"CONF-{r}")
)
noise = st.text(max_size=200)


@settings(max_examples=200)
@given(secret=secrets_st, before=noise, after=noise)
def test_property_embedded_secret_always_found(secret: str, before: str, after: str) -> None:
    assert scan(before + secret + after, secret) is not None


@settings(max_examples=200)
@given(secret=secrets_st, cut=st.integers(1, 28), before=noise)
def test_property_any_two_way_split_found_cumulatively(secret: str, cut: int, before: str) -> None:
    from app.firewall.leak import covered_by_fragments, secret_core

    history = before + secret[:cut]
    # Only meaningful when the history does not already show the whole core.
    assume(not covered_by_fragments(secret_core(secret), skeleton(history)))
    assert scan_cumulative([history], secret[cut:], secret) is not None


@settings(max_examples=300)
@given(text=st.text(max_size=500))
def test_property_scan_never_crashes(text: str) -> None:
    scan(text, SECRET)
    scan_cumulative([text], text, SECRET)
    echo_excluded([text], SECRET)


# --- Fragment coverage: false positives, cost, and the documented gap (M2-DD-07) -----------


def _benign_output(target_chars: int = 50_000) -> str:
    from app.arena.scenario_data import BASE_DOCUMENTS, COMPANY_PROFILE, EMAILS

    parts = [COMPANY_PROFILE, *(d["content"] for d in BASE_DOCUMENTS), *(e["body"] for e in EMAILS)]
    text = "\n".join(str(p) for p in parts)
    return (text + "\n") * (target_chars // max(len(text), 1) + 1)


def test_benign_session_output_never_covers_random_secrets() -> None:
    from app.arena.seed import new_secret
    from app.firewall.leak import covered_by_fragments

    sk_benign = skeleton(_benign_output())
    for level in ("lvl-1", "lvl-2", "lvl-3") * 20:
        secret = new_secret(level)
        assert not covered_by_fragments(skeleton(secret), sk_benign), secret


def test_cumulative_scan_of_a_full_session_is_fast() -> None:
    import time

    history = [_benign_output()]
    start = time.perf_counter()
    for _ in range(5):
        scan_cumulative(history, "one more ordinary reply", SECRET)
    per_call_ms = (time.perf_counter() - start) * 1000 / 5
    assert per_call_ms < 100, per_call_ms


def test_two_character_pieces_are_below_the_fragment_floor() -> None:
    # Documented gap (M2-DD-07): 1-2 characters per reply is left to Strict's judge layer.
    sk = skeleton(SECRET)
    pieces = [f"piece {sk[i : i + 2]} done" for i in range(0, len(sk), 2)]
    assert scan_cumulative(pieces[:-1], pieces[-1], SECRET) is None
