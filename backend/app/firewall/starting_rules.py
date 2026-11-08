"""Starting rules R-001 to R-006 as rule forms (PRD §9.2; M2 A-05, seeded by B-02).

Built-ins B-01 to B-04 are code (leak scan, forged approval, path resolution, echo fact),
not form rules, so they are not here. Regexes run on RE2 against `normalize`d text, which is
already case-folded with zero-width and control characters removed (PRD §9.1).
"""

from __future__ import annotations

from datetime import datetime

from app.contracts.firewall_admin import RuleDef, RuleForm

RULE_SET_VERSION = 1
ALLOWED_EMAIL_DOMAINS = ["company.example"]  # PRD §5.1 scenario allowlist

_OVERRIDE = (
    r"\b(ignore|disregard|forget)\s+(all\s+|any\s+|the\s+|your\s+)?"
    r"(previous|prior|above|earlier)\b|\byou are now\b|\bsystem prompt\b"
)
_AUTHORITY = (
    r"\b(i am|i'm|this is)\s+(the\s+|an\s+|a\s+|your\s+)?"
    r"(administrator|admin|ceo|cto|it director|operations director|security team|system owner)\b"
)
_DESTRUCTIVE_SQL = r"\b(drop|delete|truncate)\b"
_SHELL_ABUSE = (
    r"\b(curl|wget|nc|ncat|netcat|ssh|scp|ftp)\b"
    r"|\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|-r\s+-f|-f\s+-r)"
)

STARTING_RULES: tuple[tuple[str, RuleForm], ...] = (
    ("R-001", RuleForm(
        applies_on="player_message", checks="text", operator="regex", value=_OVERRIDE,
        action="score_only", weight=35, atlas_tag="AML.T0051.000",
        note="Override phrases: ignore previous, you are now, system prompt",
    )),
    ("R-002", RuleForm(
        applies_on="player_message", checks="text", operator="regex", value=_AUTHORITY,
        action="review", weight=30, atlas_tag="AML.T0051.000",
        note="Authority claim, for example 'I am the administrator'",
    )),
    ("R-003", RuleForm(
        applies_on="bot_tool_call", checks="named_argument", argument_name="to",
        operator="domain_not_in", value=ALLOWED_EMAIL_DOMAINS, action="deny",
        atlas_tag="AML.T0086", note="Email recipient domain not in the allowlist",
    )),
    ("R-004", RuleForm(
        applies_on="bot_tool_call", checks="named_argument", argument_name="sql",
        operator="regex", value=_DESTRUCTIVE_SQL, action="deny", atlas_tag="AML.T0053",
        note="DB tool with DROP, DELETE or TRUNCATE",
    )),
    ("R-005", RuleForm(
        applies_on="bot_tool_call", checks="named_argument", argument_name="path",
        operator="outside_workspace", value="", action="deny", atlas_tag="AML.T0053",
        note="Path outside the workspace (uses B-03 path resolution)",
    )),
    ("R-006", RuleForm(
        applies_on="bot_tool_call", checks="named_argument", argument_name="command",
        operator="regex", value=_SHELL_ABUSE, action="divert", atlas_tag="AML.T0053",
        note="run_shell with network or destructive commands (curl, wget, rm -rf, nc)",
    )),
)  # fmt: skip


def starting_rule_defs(created_at: datetime) -> list[RuleDef]:
    return [
        RuleDef(
            rule_id=rule_id,
            version=RULE_SET_VERSION,
            builtin=False,
            enabled=True,
            deprecated=False,
            form=form,
            created_at=created_at,
            created_by=None,
        )
        for rule_id, form in STARTING_RULES
    ]
