"""Strict wiring: risky history (layer 2) and the judge (layer 3) (M2 C-08; PRD §7.2, §7.3;
spec AEGIS-DOM-123).

`Sentinel.assess` runs after layer 1 for one checked item and returns what the Gatekeeper
needs (`Intel`):

- **Strict:** the user's risky history is looked up for every checked item; the judge is asked
  only when layers 1 + 2 reach 20 (`judge_needed`, PRD §18.2). A history error or a history
  `forced_deny` is Deny, and then the judge is not asked. A judge error, a timeout (8 s,
  `JUDGE_TIMEOUT_S`) or an answer that is not a verdict sets `judge_error`, which raises the
  score to at least the Deny band (the Gatekeeper's rule).
- **Off:** the same lookup, in shadow (the Gatekeeper enforces Allow); the judge only when
  `judge_in_off` is set (off by default to save cost).
- **Basic:** neither is used.

What leaves the process is kept clean: text sent to the history port (its similarity query may
call an embedder) and everything sent to the judge (Gemini) is withheld if it holds any part
of the level secret; the judge also gets the call's arguments with any such argument withheld.
The judge's reason and the per-layer latency are returned for the event; they never reach a
`PlayerView`.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from app.contracts.common import Stage
from app.contracts.sentinel import (
    CheckedItem,
    JudgePort,
    JudgeVerdict,
    RiskyHistoryPort,
    RiskyHistorySignals,
)
from app.firewall.canonical import CanonicalCall
from app.firewall.context import TurnContext
from app.firewall.gatekeeper import judge_needed, layer12_score
from app.firewall.leak import scan
from app.firewall.textnorm import normalize

JUDGE_TIMEOUT_S = 8.0  # PRD §7.3 layer 3
HISTORY_TIMEOUT_S = 2.0  # the lookup may embed the text (M1 embedder timeout 2 s)
MAX_TEXT_CHARS = 4000
EXCERPT_MESSAGES = 4
EXCERPT_MESSAGE_CHARS = 300
WITHHELD = "[withheld: holds the protected secret]"

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Intel:
    """Layers 2 and 3 for one item, as the Gatekeeper takes them."""

    history: RiskyHistorySignals | None = None
    history_error: bool = False
    judge: JudgeVerdict | None = None
    judge_error: bool = False
    latency_ms: Mapping[str, int] = field(default_factory=lambda: MappingProxyType({}))

    @property
    def judge_reason(self) -> str | None:
        return self.judge.reason if self.judge is not None else None


def clean_text(text: str, secret: str) -> str:
    return WITHHELD if scan(text, secret) is not None else text


def clean_args(args: Mapping[str, Any] | None, secret: str) -> dict[str, Any] | None:
    if args is None:
        return None
    return {
        k: WITHHELD if isinstance(v, str) and scan(v, secret) is not None else v
        for k, v in args.items()
    }


def _excerpt(ctx: TurnContext) -> str:
    """The last few messages, delimited and labelled untrusted, for the judge."""
    parts = [
        f"{m.role}: {clean_text((m.content or '')[:EXCERPT_MESSAGE_CHARS], ctx.secret)}"
        for m in ctx.history[-EXCERPT_MESSAGES:]
        if m.role in ("user", "assistant") and m.content
    ]
    return '<untrusted_context trust="untrusted">\n' + "\n".join(parts) + "\n</untrusted_context>"


def make_sentinel(
    risky: RiskyHistoryPort | None, judge: JudgePort | None, judge_in_off: bool = False
) -> Sentinel | None:
    """None when neither port is given (layers 2 and 3 are then skipped)."""
    if risky is None and judge is None:
        return None
    return Sentinel(risky, judge, judge_in_off)


def _ms(started: float) -> int:
    return round((time.monotonic() - started) * 1000)


class Sentinel:
    def __init__(
        self,
        risky: RiskyHistoryPort | None,
        judge: JudgePort | None,
        judge_in_off: bool = False,
    ) -> None:
        self._risky = risky
        self._judge = judge
        self._judge_in_off = judge_in_off

    async def assess(
        self,
        ctx: TurnContext,
        *,
        event_id: str,
        stage: Stage,
        text: str,
        layer1_score: int,
        call: CanonicalCall | None = None,
        rules_ms: float = 0.0,
        after_divert: bool = False,
    ) -> Intel:
        latency: dict[str, int] = {"rules": round(rules_ms)}
        if ctx.mode == "basic" or (self._risky is None and self._judge is None):
            return Intel(latency_ms=latency)
        shown = clean_text(normalize(text)[:MAX_TEXT_CHARS], ctx.secret)
        item = CheckedItem(
            event_id=event_id,
            stage=stage,
            mode=ctx.mode,
            user_id=ctx.owner_ref,
            fw_session_id=ctx.fw_session_id,
            manifest_id=ctx.manifest_id,
            pattern_version=ctx.pattern_version,
            tool=call.tool if call else None,
            canonical_args=dict(call.args) if call else None,
            args_hash=call.args_hash if call else None,
            text=shown,
            layer1_score=layer1_score,
            context_excerpt="",
        )
        history: RiskyHistorySignals | None = None
        if self._risky is not None:
            started = time.monotonic()
            try:
                history = await asyncio.wait_for(self._risky.lookup(item), HISTORY_TIMEOUT_S)
            except Exception as exc:  # fail closed: a history error is Deny
                logger.warning("risky-history lookup failed: %s: %s", type(exc).__name__, exc)
                latency["history"] = _ms(started)
                return Intel(history_error=True, latency_ms=latency)
            latency["history"] = _ms(started)
            if after_divert and history is not None:
                # This turn already returned a decoy. Its own divert (+20) and its own record,
                # which matches this very message (+25), must not re-score the rest of the
                # turn: a held reply would give the decoy away (PRD D-03, E-45). The next turn
                # counts them.
                history = history.model_copy(
                    update={
                        "prior_divert_points": 0,
                        "similarity_points": 0,
                        "similarity_top": None,
                    }
                )
        judge_on = ctx.mode == "strict" or self._judge_in_off
        forced = history is not None and history.forced_deny
        if (
            self._judge is None
            or not judge_on
            or forced
            or not judge_needed(layer12_score(layer1_score, history))
        ):
            return Intel(history=history, latency_ms=latency)
        return await self._ask_judge(ctx, item, history, latency)

    async def _ask_judge(
        self,
        ctx: TurnContext,
        item: CheckedItem,
        history: RiskyHistorySignals | None,
        latency: dict[str, int],
    ) -> Intel:
        assert self._judge is not None
        safe = item.model_copy(
            update={
                "canonical_args": clean_args(item.canonical_args, ctx.secret),
                "context_excerpt": _excerpt(ctx),
            }
        )
        started = time.monotonic()
        try:
            verdict = await asyncio.wait_for(self._judge.assess(safe), JUDGE_TIMEOUT_S)
            if not isinstance(verdict, JudgeVerdict):
                raise TypeError("the judge did not return a verdict")
        except Exception as exc:  # timeout, error or an unusable answer: at least Deny
            logger.warning("judge failed: %s", type(exc).__name__)
            latency["judge"] = _ms(started)
            return Intel(history=history, judge_error=True, latency_ms=latency)
        latency["judge"] = _ms(started)
        return Intel(history=history, judge=verdict, latency_ms=latency)
