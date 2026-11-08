"""Per-item checks for one turn (M2 B-08; PRD §7.1, §7.6, §9.3; spec AEGIS-DOM-112).

Pure functions: each one runs limits, rules, Sentinel layer 1, the B-01 leak scan and the
Gatekeeper for one checked item and returns a `Checked` record. The pipeline acts on it.

- input check: the student's message (rules on `player_message` and `session_history`);
- tool-call check: canonicalize, argument limits, rules on `bot_tool_call`, B-01 on the
  arguments, B-02 from the tool results read this turn;
- output check: reply limit, rules on `bot_reply`, B-01 per reply in Basic, cumulative in
  Strict and (reported) Off, and the Strict 50,000-character cap.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from app.contracts.common import Stage
from app.firewall.canonical import CanonicalCall, CanonicalError, canonicalize
from app.firewall.context import TurnContext
from app.firewall.events import SourceTrust
from app.firewall.gatekeeper import GateDecision, GateInput, decide
from app.firewall.leak import LeakMatch, scan, scan_cumulative
from app.firewall.limits import check_args, check_text, cumulative_exceeded
from app.firewall.rules import Evaluation, RuleSubject, evaluate
from app.firewall.sentinel_l1 import Layer1Input, layer1
from app.firewall.textnorm import storable
from app.llm.base import ToolCall


@dataclass(frozen=True)
class Checked:
    stage: Stage
    source_trust: SourceTrust
    gate: GateDecision
    text: str  # what was checked (after Off truncation)
    tool: str | None = None
    call_id: str | None = None
    call: CanonicalCall | None = None
    leak: LeakMatch | None = None

    @property
    def allowed(self) -> bool:
        return self.gate.decision == "allow"


def _evaluate(ctx: TurnContext, *subjects: RuleSubject) -> Evaluation:
    results = [evaluate(ctx.rules, s) for s in subjects]
    return Evaluation(
        hits=tuple(h for r in results for h in r.hits),
        failures=tuple(f for r in results for f in r.failures),
        elapsed_ms=sum(r.elapsed_ms for r in results),
    )


def _gate(ctx: TurnContext, rules: Evaluation, signals: Layer1Input, **flags: Any) -> GateDecision:
    scored = layer1(replace(signals, rule_hits=rules.hits), ctx.weights)
    return decide(
        GateInput(
            mode=ctx.mode,
            thresholds=ctx.thresholds,
            divert_enabled=ctx.divert_enabled,
            layer1=scored,
            rules=rules,
            **flags,
        )
    )


def check_input(ctx: TurnContext, message: str, now: datetime) -> Checked:
    limited = check_text("player_text", message, ctx.mode)
    turn_count = len(ctx.student_inputs) + 1
    rules = _evaluate(
        ctx,
        RuleSubject(applies_on="player_message", text=limited.text, turn_count=turn_count,
                    earlier_denies=ctx.earlier_denies),
        RuleSubject(applies_on="session_history", text="", turn_count=turn_count,
                    earlier_denies=ctx.earlier_denies),
    )  # fmt: skip
    signals = Layer1Input(
        raw_text=limited.text,
        now=now,
        earlier_denies=ctx.earlier_denies,
        recent_message_times=(*ctx.student_times, now),
    )
    gate = _gate(ctx, rules, signals, limit_exceeded=limited.action != "ok")
    return Checked("input_check", "player", gate, limited.text)


def _invalid_call(ctx: TurnContext, call: ToolCall, call_id: str, now: datetime) -> Checked:
    gate = _gate(
        ctx, Evaluation((), (), 0.0), Layer1Input(raw_text="", now=now), canonical_error=True
    )
    tool = storable(call.name)
    return Checked("tool_call_check", "bot_output", gate, "", tool=tool, call_id=call_id)


def check_tool_call(
    ctx: TurnContext,
    call: ToolCall,
    call_id: str,
    tool_results: Sequence[str],
    now: datetime,
    seen_before: Sequence[str] = (),
) -> Checked:
    canonical = canonicalize(call.name, call.arguments, ctx.tools, call_id)
    if isinstance(canonical, CanonicalError):
        return _invalid_call(ctx, call, call_id, now)
    limited = check_args(canonical.args, ctx.mode)
    if limited.action == "truncate":  # Off only: re-canonicalize what will actually run
        canonical = canonicalize(call.name, dict(limited.args), ctx.tools, call_id)
        if isinstance(canonical, CanonicalError):
            return _invalid_call(ctx, call, call_id, now)
    args_text = " ".join(str(v) for v in canonical.args.values())
    # Strict (and Off, for the shadow) scan tool arguments over everything already visible,
    # so a secret split across several visible tool effects is caught (M2-DD-37).
    if ctx.mode == "basic":
        leak = scan(args_text, ctx.secret)
    else:
        leak = scan_cumulative(seen_before, args_text, ctx.secret)
    rules = _evaluate(ctx, RuleSubject(applies_on="bot_tool_call", text=args_text, call=canonical))
    signals = Layer1Input(
        raw_text=args_text,
        now=now,
        call=canonical,
        earlier_denies=ctx.earlier_denies,
        tool_result_read_this_turn=bool(tool_results),
        tool_results_this_turn=tuple(tool_results),
    )
    gate = _gate(ctx, rules, signals, leak=leak, limit_exceeded=limited.action != "ok")
    return Checked(
        "tool_call_check", "bot_output", gate, args_text, canonical.tool, call_id, canonical, leak
    )


def check_output(
    ctx: TurnContext, reply: str, seen_before: Sequence[str], now: datetime
) -> Checked:
    limited = check_text("reply", storable(reply), ctx.mode)
    if ctx.mode == "basic":
        leak = scan(limited.text, ctx.secret)
    else:  # Strict enforces the cumulative scan; Off computes it for the shadow decision
        leak = scan_cumulative(seen_before, limited.text, ctx.secret)
    seen_chars = sum(len(s) for s in seen_before) + len(limited.text)
    over = limited.action != "ok" or cumulative_exceeded(seen_chars, ctx.mode)
    rules = _evaluate(ctx, RuleSubject(applies_on="bot_reply", text=limited.text))
    signals = Layer1Input(raw_text=limited.text, now=now, earlier_denies=ctx.earlier_denies)
    gate = _gate(ctx, rules, signals, leak=leak, limit_exceeded=over)
    return Checked("output_check", "bot_output", gate, limited.text, leak=leak)
