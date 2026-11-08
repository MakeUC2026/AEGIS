"""Decoys for Divert (M2 C-05; PRD §8.4, §8.6; E-48, E-49; spec AEGIS-DOM-120).

A decoy is what the student and the bot are told a diverted tool call returned. It is made
before the divert transaction, never by running the tool, and is safe by construction:

- a `DecoyGenerator` (Gemini in C-06) gets 5 s (`DECOY_TIMEOUT_S`); a timeout, an error or no
  answer falls back to the fixed per-tool template;
- the decoy is scanned for the level secret (B-01 scan, partial runs included); a hit falls
  back to the template, and if the template itself holds the secret (a recipient that does)
  to the plain "OK.";
- templates never echo the attempt except the recipients, so a decoy cannot carry back what
  the student tried to send out.

Divert never falls back to executing the real tool: nothing here can reach one.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Protocol

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
    async def generate(self, call: CanonicalCall) -> Decoy | None: ...


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


async def make_decoy(generator: DecoyGenerator | None, call: CanonicalCall, secret: str) -> Decoy:
    if generator is not None:
        try:
            made = await asyncio.wait_for(generator.generate(call), timeout=DECOY_TIMEOUT_S)
        except Exception as exc:  # timeout, model error, bad output: use the template
            logger.warning("decoy generation failed (%s); using the template", type(exc).__name__)
            made = None
        if made is not None and _safe(made, secret):
            return made
    template = template_decoy(call)
    return template if _safe(template, secret) else _PLAIN
