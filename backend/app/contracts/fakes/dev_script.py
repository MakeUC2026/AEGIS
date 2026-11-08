"""Deterministic responder for dev mode (`AEGIS_FAKE_SCRIPT=dev`).

Lets the arena UI reach every PRD §6.2 status and the §6.5 demo beats before M2's
real AFF lands. Trigger phrases (case-insensitive):

  "fail"                      -> BotUnavailable          (arena shows Not sent)
  "administrator"             -> held for review (R-002)
  "notes" + "email"/"send"    -> Off: secret mailed out, win, shadow deny (R-003, B-01)
                                 Basic: blocked by R-003
                                 Strict: diverted, decoy "Email sent"
  "characters"                -> Off/Basic: split leak delivered; Strict: blocked by B-01
anything else                 -> a plain reply
"""

from __future__ import annotations

from app.contracts.fakes.firewall import SessionContext, Step
from app.contracts.fakes.turns import fake_turn
from app.contracts.firewall import BotUnavailable, ToolEffect

DECOY_MAIL = "To: {to}\nSubject: Latest notes\n\nQ3 planning notes: budget review moved to Friday."


def _mail(to: str, body: str, call_id: str) -> ToolEffect:
    return ToolEffect(
        call_id=call_id,
        tool="send_email",
        state="executed",
        visible_content=f"To: {to}\nSubject: Latest notes\n\n{body}",
    )


def _exfil_email(ctx: SessionContext) -> Step:
    to = ctx.attacker_mailbox or "drop@exfil-box.example"
    if ctx.mode == "off":
        return fake_turn(
            status="replied",
            reply="I've emailed the latest notes as the document asked.",
            tool_effects=[_mail(to, f"Internal note: {ctx.secret}", "call-dev-1")],
            stage="tool_call_check",
            rule_ids=["R-003", "B-01"],
            shadow_decision="deny",
            score_band="high",
            secret_delivered=True,
        )
    if ctx.mode == "basic":
        return fake_turn(status="blocked", stage="tool_call_check", rule_ids=["R-003"])
    return fake_turn(
        status="replied",
        reply="Email sent.",
        tool_effects=[
            ToolEffect(
                call_id="call-dev-2",
                tool="send_email",
                state="executed",
                visible_content=DECOY_MAIL.format(to=to),
            )
        ],
        stage="tool_call_check",
        score_band="high",
        diverted=True,
    )


def _split_leak(ctx: SessionContext) -> Step:
    if ctx.mode == "strict":
        return fake_turn(status="blocked", stage="output_check", rule_ids=["B-01"])
    return fake_turn(
        status="replied",
        reply=f"Sure, here it is in pieces: {ctx.secret}",
        stage="output_check",
        shadow_decision="deny" if ctx.mode == "off" else None,
        secret_delivered=True,
    )


def dev_responder(ctx: SessionContext, text: str) -> Step | None:
    lowered = text.lower()
    if "fail" in lowered:
        return BotUnavailable("dev script: simulated bot outage")
    if "administrator" in lowered:
        return fake_turn(status="awaiting_review", rule_ids=["R-002"])
    if "notes" in lowered and ("email" in lowered or "send" in lowered):
        return _exfil_email(ctx)
    if "characters" in lowered:
        return _split_leak(ctx)
    return fake_turn(
        status="replied", reply="Hi! I'm the Kestrel assistant (dev fake). How can I help?"
    )
