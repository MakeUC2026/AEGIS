"""Decoys for Divert (M2 C-05; PRD §8.4, §8.6; E-48, E-49; spec AEGIS-DOM-120).

A decoy is what the student and the bot are told a diverted tool call returned. It is made
before the divert transaction, never by running the tool, and is safe by construction:

- a `DecoyGenerator` (`decoy_gemini.GeminiDecoys`, C-06) gets 5 s in all (`DECOY_TIMEOUT_S`);
  a timeout, an error or no answer falls back to the fixed per-tool template. The generator
  sees the call with any argument that holds part of the secret withheld;
- the decoy is scanned for the level secret (B-01 scan, partial runs included); a hit is
  regenerated once (E-48), then the template is used, and if the template itself holds the
  secret (a recipient that does) the plain "OK.";
- templates never echo the attempt except the recipients, so a decoy cannot carry back what
  the student tried to send out.

Replies (Strict, a secret in the bot's reply): the whole reply is replaced by `reply_decoy`,
which holds a decoy value shaped like the secret (`decoy_secret_value`: the same public
prefix, the same length and character classes, derived from the secret and the session so it
is stable all session and cannot be guessed). Substituting inside the real reply is not safe
once a secret can be encoded or split, so nothing of it is kept.

Divert never falls back to executing the real tool: nothing here can reach one.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections.abc import Iterator
from dataclasses import dataclass, replace
from typing import Protocol

from app.contracts.firewall import ToolDef
from app.firewall.canonical import CanonicalCall
from app.firewall.leak import scan

DECOY_TIMEOUT_S = 5.0

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Decoy:
    result: str  # the tool result the bot and the student are told
    mail_subject: str | None = None  # send_email only: the decoy mail written to mock state
    mail_body: str | None = None


class DecoyGenerator(Protocol):
    async def generate(self, call: CanonicalCall, tool: ToolDef | None = None) -> Decoy | None:
        """`tool` is the session's definition of the called tool (its schema), if known."""
        ...


_FAKE_ROWS = (
    '{"department": "Operations", "id": 101, "name": "Alex Morgan"}\n'
    '{"department": "Finance", "id": 102, "name": "Sam Rivera"}'
)
_PLAIN = Decoy("OK.")


def template_decoy(call: CanonicalCall) -> Decoy:
    if call.tool == "send_email":
        return Decoy(
            f"Email sent to {', '.join(call.recipients)}.",
            mail_subject="Delivery confirmation",
            mail_body="Your message was accepted for delivery.",
        )
    if call.tool == "query_db":
        return Decoy(_FAKE_ROWS)
    if call.tool == "read_file":
        return Decoy("# Notes\n\nNothing of interest in this file.")
    if call.tool == "search_docs":
        return Decoy("docs/overview.md - Company overview")
    if call.tool == "run_shell":
        return Decoy("done")
    return _PLAIN


def _text(decoy: Decoy) -> str:
    return "\n".join(p for p in (decoy.result, decoy.mail_subject, decoy.mail_body) if p)


def _safe(decoy: Decoy, secret: str) -> bool:
    return scan(_text(decoy), secret) is None


def _scrub(call: CanonicalCall, secret: str) -> CanonicalCall:
    """The call as a generator may see it: an argument holding any part of the secret (a
    student can paste it anywhere) is withheld."""
    args = {
        k: "[withheld]" if isinstance(v, str) and scan(v, secret) is not None else v
        for k, v in call.args.items()
    }
    return replace(call, args=args)


async def make_decoy(
    generator: DecoyGenerator | None,
    call: CanonicalCall,
    secret: str,
    tool: ToolDef | None = None,
) -> Decoy:
    if generator is not None:
        deadline = time.monotonic() + DECOY_TIMEOUT_S
        visible = _scrub(call, secret)
        for _attempt in range(2):  # a hit is regenerated once (E-48)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                made = await asyncio.wait_for(generator.generate(visible, tool), timeout=remaining)
            except Exception as exc:  # timeout (E-49), model error: the template, no retry
                logger.warning("decoy generation failed (%s): template", type(exc).__name__)
                break
            if made is None:
                break
            if _safe(made, secret):
                return made
    template = template_decoy(call)
    return template if _safe(template, secret) else _PLAIN


def _stream(seed: str) -> Iterator[int]:
    counter = 0
    while True:
        yield from hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        counter += 1


def decoy_secret_value(secret: str, session_id: str) -> str:
    """A fake secret shaped like the real one: the public prefix is kept, every other
    character is replaced by a random one of the same class. Stable for a session."""
    cut = max(secret.rfind("-"), secret.rfind("_")) + 1
    prefix, tail = secret[:cut], secret[cut:]
    seed = hashlib.sha256(f"{secret}|{session_id}".encode()).hexdigest()
    for attempt in range(8):
        stream = _stream(f"{seed}:{attempt}")
        chars: list[str] = []
        for ch in tail:
            byte = next(stream)
            if ch.isdigit():
                chars.append(str(byte % 10))
            elif ch.isalpha():
                letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                pick = letters[byte % 26]
                chars.append(pick if ch.isupper() else pick.lower())
            else:
                chars.append(ch)
        value = prefix + "".join(chars)
        if value != secret and scan(value, secret) is None:
            return value
    return prefix + "0" * len(tail)


def reply_decoy(secret: str, session_id: str, leaked: bool) -> str:
    """What the student is shown instead of a diverted reply (Strict outbound hit)."""
    if leaked:
        return f"Sure. The value you asked for is {decoy_secret_value(secret, session_id)}."
    return "Done."
