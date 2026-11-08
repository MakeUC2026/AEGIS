"""Draft validation, clustering and storage (M3 C-03..C-05, PRD §10.3).

A draft must match its own (redacted) source event and no benign fixture. Failures are kept as
`failed_validation` with every reason and are never clustered or listed for approval. Validation
re-runs on every edit and at approval (M3-X31), so this module is pure apart from `store_draft`.
"""

from __future__ import annotations

import json
import logging
import pathlib
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from app.contracts.firewall_admin import RuleForm
from app.contracts.fixtures import FixtureFile, FixtureToolCall
from app.contracts.sentinel import RiskyHistoryError
from app.firewall.risky_history import as_float32, vector_literal
from app.firewall.risky_patterns import (
    Condition,
    PatternSpec,
    condition_matches,
    fixtures_dir,
    structural_errors,
    validate_for_approval,
)
from app.llm.base import Embedder, LLMError

log = logging.getLogger("aegis.workers.drafts")

DraftKind = Literal["rule", "pattern"]
CLUSTER_MIN_COSINE = 0.9  # PRD §10.3 / plan §10
EMBED_TIMEOUT_S = 2.0

# Rule form `applies_on` -> the event stage it checks (PRD §9.1, §10.1).
STAGE_OF: dict[str, str] = {
    "player_message": "input_check",
    "bot_tool_call": "tool_call_check",
    "tool_result": "tool_executed",
    "bot_reply": "output_check",
}
# Rule operators -> the pattern matcher's operators (same semantics, PRD §9.1, §7.5).
_OPERATOR = {"in_list": "in", "greater_than": "gt", "less_than": "lt"}
_UNCHECKABLE = frozenset({"turn_count", "earlier_denies"})  # need a session, not one turn


@dataclass(frozen=True)
class Benign:
    messages: list[str] = field(default_factory=list)
    calls: list[FixtureToolCall] = field(default_factory=list)


def load_benign(root: pathlib.Path | None = None) -> Benign:
    """Every message and tool call in `fixtures/benign/*.json` (read fresh on each call)."""
    folder = (root or fixtures_dir()) / "benign"
    fixtures = [
        fx
        for path in sorted(folder.glob("*.json"))
        for fx in FixtureFile.model_validate(json.loads(path.read_text())).benign
    ]
    return Benign(
        messages=[m for fx in fixtures for m in fx.messages],
        calls=[c for fx in fixtures for c in fx.tool_calls],
    )


def _condition(form: RuleForm) -> Condition:
    return Condition(arg="value", op=_OPERATOR.get(form.operator, form.operator), value=form.value)


# ponytail: local rule evaluator for one turn, built on the pattern matcher; switch to M2's rules
# engine once it lands. Session rules (turn_count, earlier_denies) are refused, never guessed.
def rule_matches(
    form: RuleForm, *, text: str, tool: str | None, args: dict[str, Any] | None
) -> bool:
    if form.checks == "text":
        subject: Any = text
    elif form.checks == "tool_name":
        subject = tool
    elif form.checks == "named_argument":
        subject = (args or {}).get(form.argument_name or "")
    else:
        return False
    if subject is None:
        return False
    return condition_matches(_condition(form), {"value": subject})


def _rule_errors(form: RuleForm, source: dict[str, Any], benign: Benign) -> list[str]:
    if form.checks in _UNCHECKABLE:
        return [f"rule checks {form.checks}, which fixtures cannot validate"]
    errors = [
        e.replace("condition 1 (value ", "rule (")
        for e in structural_errors(PatternSpec(tool="rule", conditions=[_condition(form)]))
    ]
    if errors:
        return errors
    stage = STAGE_OF.get(form.applies_on)  # session_history applies at every stage
    if stage is not None and stage != source.get("stage"):
        errors.append("rule does not apply at the source event's stage")
    elif not rule_matches(
        form,
        text=source.get("text") or "",
        tool=source.get("tool"),
        args=source.get("canonical_args"),
    ):
        errors.append("rule does not match its original event")
    if not benign.messages and not benign.calls:
        errors.append("no benign fixtures to check against")
    # Conservative: every benign message and call is checked whatever `applies_on` says, so a
    # rule that would fire on ordinary traffic anywhere is refused.
    for message in benign.messages:
        if rule_matches(form, text=message, tool=None, args=None):
            errors.append(f"rule matches a benign message: {message[:80]}")
    for call in benign.calls:
        call_text = json.dumps(call.arguments, ensure_ascii=False)
        if rule_matches(form, text=call_text, tool=call.tool, args=call.arguments):
            errors.append(f"rule matches a benign call: {call.tool} {call.arguments}")
    return errors


def validate_draft(
    kind: DraftKind, body: dict[str, Any], source: dict[str, Any], benign: Benign
) -> list[str]:
    """Every reason the draft cannot be approved; empty means it may reach `pending`."""
    reasons = _validate(kind, body, source, benign)
    if _uses_placeholder(body):
        reasons.insert(0, "draft depends on the redacted secret placeholder")
    elif _reads_redacted(kind, body, source):
        reasons.append(
            "draft reads a value that was redacted (it held the secret), so it cannot be"
            " checked against the original event"
        )
    return reasons


def _reads_redacted(kind: DraftKind, body: dict[str, Any], source: dict[str, Any]) -> bool:
    """Fail closed (Codex rounds 3 and 4): the stored source differs from the real call where
    the sanitizer changed it (`[SECRET]`, dropped delimiters or invisible characters), and the
    real value is never kept, so a condition that reads such a field cannot be shown to match
    the original attack. Conditions on unchanged fields are exact and stay checkable."""
    args = source.get("canonical_args") or {}
    changed = set(source.get("redacted_fields") or [])

    def reads(name: Any) -> bool:
        return isinstance(name, str) and (name in changed or _uses_placeholder(args.get(name)))

    if kind == "pattern":
        conditions = body.get("conditions")
        if not isinstance(conditions, list):
            return False
        return any(isinstance(c, dict) and reads(c.get("arg")) for c in conditions)
    if body.get("checks") == "text":
        return "text" in changed or _uses_placeholder(source.get("text"))
    if body.get("checks") == "named_argument":
        return reads(body.get("argument_name"))
    return False


def _uses_placeholder(node: Any) -> bool:
    """A condition on `[SECRET]` (any case, regex-escaped or spaced) only matches redacted text,
    never real traffic, so it can never block the attack (Codex round 1)."""
    if isinstance(node, str):
        return "[secret]" in re.sub(r"[\\\s]", "", node.casefold())
    if isinstance(node, list):
        return any(_uses_placeholder(v) for v in node)
    if isinstance(node, dict):
        return any(_uses_placeholder(v) for v in node.values())
    return False


def _validate(
    kind: DraftKind, body: dict[str, Any], source: dict[str, Any], benign: Benign
) -> list[str]:
    if kind == "pattern":
        try:
            pattern = PatternSpec.model_validate(body)
        except ValidationError as exc:
            return [f"draft is not a valid pattern: {exc.error_count()} error(s)"]
        if source.get("tool") is None:
            return ["the source event has no tool call"]
        original = FixtureToolCall(
            tool=source["tool"], arguments=source.get("canonical_args") or {}
        )
        return validate_for_approval(pattern, original, benign.calls)
    try:
        form = RuleForm.model_validate(body)
    except ValidationError as exc:
        return [f"draft is not a valid rule: {exc.error_count()} error(s)"]
    return _rule_errors(form, source, benign)


async def draft_embedding(embedder: Embedder, kind: str, body: dict[str, Any]) -> str | None:
    """The draft's vector for clustering, or None when the embedding call fails (the draft is
    kept and becomes its own cluster). A programming error still propagates."""
    canonical = json.dumps({"kind": kind, "body": body}, sort_keys=True, ensure_ascii=False)
    try:
        floats = as_float32(await embedder.embed(canonical, timeout_s=EMBED_TIMEOUT_S))
    except (LLMError, TimeoutError, RiskyHistoryError) as exc:
        log.warning("draft embedding failed (%s); draft kept unclustered", type(exc).__name__)
        return None
    return vector_literal(floats) if any(floats) else None


_INSERT = text(
    "INSERT INTO drafts (source_event_id, kind, body, status, validation, source)"
    " VALUES (:event_id, :kind, CAST(:body AS jsonb), :status, CAST(:validation AS jsonb),"
    " CAST(:source AS jsonb)) ON CONFLICT (source_event_id) DO NOTHING RETURNING draft_id"
)
# Nearest open draft of the same kind at cosine >= 0.9 (C-05). Bound vector, no f-string SQL.
_NEAREST = text(
    "SELECT cluster_id FROM drafts WHERE status = 'pending' AND kind = :kind"
    " AND embedding IS NOT NULL AND draft_id <> CAST(:id AS uuid)"
    " AND 1 - (embedding <=> CAST(CAST(:e AS text) AS vector(768))) >= :min_cos"
    " ORDER BY embedding <=> CAST(CAST(:e AS text) AS vector(768)) LIMIT 1"
)
_CLUSTER_LOCK = text("SELECT pg_advisory_xact_lock(hashtext(:key))")
_CLUSTER = text(
    "UPDATE drafts SET cluster_id = CAST(:cluster AS uuid),"
    " embedding = CAST(CAST(:e AS text) AS vector(768)) WHERE draft_id = CAST(:id AS uuid)"
)


async def cluster_of(conn: AsyncConnection, draft_id: str, kind: str, embedding: str | None) -> str:
    if embedding is None:
        return draft_id
    row = await conn.execute(
        _NEAREST, {"kind": kind, "id": draft_id, "e": embedding, "min_cos": CLUSTER_MIN_COSINE}
    )
    found = row.scalar_one_or_none()
    return draft_id if found is None else str(found)


async def store_draft(
    conn: AsyncConnection,
    *,
    event_id: str,
    kind: DraftKind,
    body: dict[str, Any],
    source: dict[str, Any],
    benign: Benign,
    embedder: Embedder,
    original: dict[str, Any] | None = None,
) -> str | None:
    """Insert at most one draft per event (unique index); returns its id, or None if one exists.

    `original` is the unredacted source, held in memory only: the draft must also match the real
    call, not just its redacted copy. Only its "original" reasons are kept (they never quote it).
    """
    reasons = validate_draft(kind, body, source, benign)
    if original is not None:
        reasons += [
            r
            for r in validate_draft(kind, body, original, benign)
            if "original" in r and r not in reasons
        ]
    status = "failed_validation" if reasons else "pending"
    row = await conn.execute(
        _INSERT,
        {
            "event_id": event_id,
            "kind": kind,
            "body": json.dumps(body, ensure_ascii=False),
            "status": status,
            "validation": json.dumps({"ok": not reasons, "reasons": reasons}),
            "source": json.dumps(source, ensure_ascii=False),
        },
    )
    draft_id = row.scalar_one_or_none()
    if draft_id is None:
        return None
    draft_id = str(draft_id)
    if reasons:
        return draft_id  # never clustered, never in the approve list (E-56)
    embedding = await draft_embedding(embedder, kind, body)
    # One cluster assignment per kind at a time (held to commit), so concurrent workers see each
    # other's drafts and never open two clusters for one attack type (C-05, M3-X30).
    await conn.execute(_CLUSTER_LOCK, {"key": f"m3_draft_cluster:{kind}"})
    cluster = await cluster_of(conn, draft_id, kind, embedding)
    await conn.execute(_CLUSTER, {"cluster": cluster, "e": embedding, "id": draft_id})
    return draft_id
