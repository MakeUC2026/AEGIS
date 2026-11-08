"""Rules engine (M2 A-05; PRD §9.1; spec AEGIS-DOM-103).

Evaluates form rules (`RuleDef` with a `RuleForm`) against one checked item. Text is matched
after `normalize`; regexes run on RE2 only (linear time, no backreferences), case-insensitive.
Each rule evaluation is capped at 50 ms. A bad regex, a value of the wrong type, or a slow
rule becomes a `RuleFailure`, never an exception: the Gatekeeper turns any failure into Deny
in Basic and Strict, and a shadow Deny in Off (PRD §9.1, M2-X13).

Built-in, disabled and deprecated rules are skipped; built-ins are code, not forms.
"""

from __future__ import annotations

import functools
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Literal

import re2

from app.contracts.firewall_admin import RuleAction, RuleAppliesOn, RuleDef, RuleForm
from app.firewall.canonical import RECIPIENT_ARGS, CanonicalCall
from app.firewall.textnorm import normalize

RULE_TIME_CAP_MS = 50
_REGEX_CACHE_SIZE = 512
_MS_PER_S = 1000

FailureKind = Literal["bad_regex", "bad_value", "timeout"]
Clock = Callable[[], float]


@dataclass(frozen=True)
class RuleSubject:
    applies_on: RuleAppliesOn
    text: str
    call: CanonicalCall | None = None
    turn_count: int = 0
    earlier_denies: int = 0


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    version: int
    action: RuleAction
    weight: int | None
    atlas_tag: str | None


@dataclass(frozen=True)
class RuleFailure:
    rule_id: str
    version: int
    kind: FailureKind
    detail: str


@dataclass(frozen=True)
class Evaluation:
    hits: tuple[RuleHit, ...]
    failures: tuple[RuleFailure, ...]
    elapsed_ms: float


class _Failure(Exception):
    def __init__(self, kind: FailureKind, detail: str) -> None:
        super().__init__(detail)
        self.kind: FailureKind = kind
        self.detail = detail


_NOT_APPLICABLE = object()  # the rule's field does not exist on this item


@functools.lru_cache(maxsize=_REGEX_CACHE_SIZE)
def _compile(pattern: str) -> Any:
    options = re2.Options()
    options.case_sensitive = False
    options.log_errors = False
    return re2.compile(pattern, options)


def _regex(pattern: str) -> Any:
    try:
        return _compile(pattern)
    except (re2.error, TypeError, ValueError) as exc:
        raise _Failure("bad_regex", f"not a valid RE2 pattern: {type(exc).__name__}") from exc


def _field(form: RuleForm, subject: RuleSubject) -> Any:
    if form.checks == "text":
        return subject.text
    if form.checks == "turn_count":
        return subject.turn_count
    if form.checks == "earlier_denies":
        return subject.earlier_denies
    call = subject.call
    if call is None:
        return _NOT_APPLICABLE
    if form.checks == "tool_name":
        return call.tool
    if form.argument_name not in call.args:
        return _NOT_APPLICABLE
    return call.args[form.argument_name]


def _as_str(value: Any) -> str:
    if not isinstance(value, str):
        raise _Failure("bad_value", "this operator needs a text value")
    return value


def _as_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return value
    raise _Failure("bad_value", "this operator needs a list of text values")


def _as_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _Failure("bad_value", "this operator needs a whole number")
    return value


def _numeric(op: str, field: Any, value: Any) -> bool:
    target = _as_int(value)
    if op == "greater_than":
        return int(field) > target
    if op == "less_than":
        return int(field) < target
    return int(field) == target


def _domains(form: RuleForm, call: CanonicalCall | None) -> tuple[str, ...] | None:
    if call is None or form.argument_name not in RECIPIENT_ARGS.get(call.tool, ()):
        return None
    return call.recipient_domains


def _matches(form: RuleForm, subject: RuleSubject) -> bool:
    field = _field(form, subject)
    if field is _NOT_APPLICABLE:
        return False
    op = form.operator
    if form.checks in ("turn_count", "earlier_denies"):
        return _numeric(op, field, form.value)
    if op in ("domain_in", "domain_not_in"):
        domains = _domains(form, subject.call)
        if not domains:  # the argument exists but was never parsed as recipients: fail closed
            raise _Failure("bad_value", "domain operators need a parsed recipient argument")
        allowed = {d.lower() for d in _as_list(form.value)}
        outside = any(d not in allowed for d in domains)
        return outside if op == "domain_not_in" else not outside
    if op in ("inside_workspace", "outside_workspace"):
        path = subject.call.paths.get(form.argument_name or "") if subject.call else None
        if path is None:  # the argument exists but was never resolved as a path: fail closed
            raise _Failure("bad_value", "workspace operators need a resolved path argument")
        return path.inside_workspace if op == "inside_workspace" else not path.inside_workspace
    # Both readings of the text: invisible characters removed, and read as spaces (M2-DD-17).
    texts = {normalize(str(field)), normalize(str(field), invisible_as_space=True)}
    if op == "contains":
        needle = normalize(_as_str(form.value))
        return any(needle in text for text in texts)
    if op == "equals":
        return normalize(_as_str(form.value)) in texts
    if op == "in_list":
        return bool(texts & {normalize(v) for v in _as_list(form.value)})
    if op == "regex":
        pattern = _regex(_as_str(form.value))
        return any(pattern.search(text) is not None for text in texts)
    raise _Failure("bad_value", f"operator {op!r} does not apply to {form.checks!r}")


def _active(rule: RuleDef, applies_on: str) -> bool:
    return (
        rule.form is not None
        and not rule.builtin
        and rule.enabled
        and not rule.deprecated
        and rule.form.applies_on == applies_on
    )


def evaluate(
    rules: Sequence[RuleDef], subject: RuleSubject, clock: Clock = time.perf_counter
) -> Evaluation:
    began = clock()
    hits: list[RuleHit] = []
    failures: list[RuleFailure] = []
    for rule in (r for r in rules if _active(r, subject.applies_on)):
        form = rule.form
        if form is None:  # already excluded by _active; keeps the type checker honest
            continue
        start = clock()
        try:
            matched = _matches(form, subject)
        except _Failure as failed:
            failures.append(RuleFailure(rule.rule_id, rule.version, failed.kind, failed.detail))
            continue
        if (clock() - start) * _MS_PER_S > RULE_TIME_CAP_MS:
            failures.append(RuleFailure(rule.rule_id, rule.version, "timeout", "over 50 ms"))
            continue
        if matched:
            hits.append(
                RuleHit(rule.rule_id, rule.version, form.action, form.weight, form.atlas_tag)
            )
    return Evaluation(tuple(hits), tuple(failures), (clock() - began) * _MS_PER_S)
