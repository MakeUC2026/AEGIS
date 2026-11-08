"""M2 C-11 secret redaction for the C3 read API (PRD §14.4; spec AEGIS-DOM-126).

`redact_secret` replaces the level secret with `[SECRET]` in any text a teacher or the recap
may see: the exact secret and its random core in any case, and the normalized forms the A-04
scanner recognises (spaced out, zero-width characters, look-alike letters, reversed). A form
that cannot be located precisely (base64, hex, a partial run of 12 characters or more) makes
the whole text a placeholder: losing a message is better than showing the secret.
"""

from __future__ import annotations

import base64

from hypothesis import given
from hypothesis import strategies as st

from app.contracts.firewall_read import SECRET_PLACEHOLDER
from app.firewall.leak import scan, secret_core
from app.firewall.redact import redact_secret

SECRET = "CONF-K3Q9ZP7X2M4TLW8D5RHV6BNA"
CORE = secret_core(SECRET)  # lower-case skeleton of the random part
ZERO_WIDTH = chr(0x200B)
CYRILLIC_KA = chr(0x041A)  # looks like a Latin K


def test_text_without_the_secret_is_unchanged() -> None:
    text = "Please send the Q3 notes to Bob. Nothing secret here."
    assert redact_secret(text, SECRET) == text
    assert redact_secret("", SECRET) == ""


def test_the_exact_secret_is_replaced_in_any_case() -> None:
    assert redact_secret(f"key {SECRET} ok", SECRET) == f"key {SECRET_PLACEHOLDER} ok"
    assert redact_secret(f"key {SECRET.lower()} ok", SECRET) == f"key {SECRET_PLACEHOLDER} ok"


def test_the_core_without_its_prefix_is_replaced() -> None:
    redacted = redact_secret(f"it is {SECRET[5:]} really", SECRET)
    assert SECRET[5:] not in redacted and SECRET_PLACEHOLDER in redacted
    assert redacted.startswith("it is ") and redacted.endswith(" really")


def test_every_occurrence_is_replaced() -> None:
    redacted = redact_secret(f"{SECRET} and again {SECRET}", SECRET)
    assert redacted.count(SECRET_PLACEHOLDER) == 2


def test_a_spaced_out_secret_is_replaced_but_the_rest_is_kept() -> None:
    spaced = " ".join(SECRET[5:])
    redacted = redact_secret(f"Here: {spaced} - thanks", SECRET)
    assert redacted == f"Here: {SECRET_PLACEHOLDER} - thanks"


def test_zero_width_and_lookalike_letters_are_replaced() -> None:
    zero_width = ZERO_WIDTH.join(SECRET[5:])
    lookalike = SECRET[5:].replace("K", CYRILLIC_KA)
    for variant in (zero_width, lookalike):
        redacted = redact_secret(f"before {variant} after", SECRET)
        assert scan(redacted, SECRET) is None and SECRET_PLACEHOLDER in redacted
        assert redacted.startswith("before ") and redacted.endswith(" after")


def test_a_reversed_secret_is_replaced() -> None:
    redacted = redact_secret(f"backwards: {SECRET[::-1]}", SECRET)
    assert scan(redacted, SECRET) is None and SECRET_PLACEHOLDER in redacted


def test_an_encoded_secret_withholds_the_whole_text() -> None:
    for encoded in (SECRET.encode().hex(), base64.b64encode(SECRET.encode()).decode()):
        assert redact_secret(f"my notes {encoded} end", SECRET) == SECRET_PLACEHOLDER


def test_a_partial_run_withholds_the_whole_text() -> None:
    assert redact_secret(f"starts {CORE[:12]} perhaps", SECRET) == SECRET_PLACEHOLDER


def test_a_short_run_is_left_alone() -> None:
    text = f"only {CORE[:8]} here"
    assert redact_secret(text, SECRET) == text  # below the 12-character floor, as in the scanner


@given(
    before=st.text(alphabet="abc xyz.,", max_size=30),
    after=st.text(alphabet="abc xyz.,", max_size=30),
    form=st.sampled_from(["exact", "lower", "spaced", "zero_width", "reversed", "core_upper"]),
)
def test_no_form_of_the_secret_survives_redaction(before: str, after: str, form: str) -> None:
    forms = {
        "exact": SECRET,
        "lower": SECRET.lower(),
        "spaced": " ".join(SECRET[5:]),
        "zero_width": ZERO_WIDTH.join(SECRET[5:]),
        "reversed": SECRET[::-1],
        "core_upper": SECRET[5:].upper(),
    }
    redacted = redact_secret(f"{before}{forms[form]}{after}", SECRET)
    assert scan(redacted, SECRET) is None
