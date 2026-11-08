"""C3: the AFF read API for Classroom and the arena recap (M2 C-11; PRD §10, §14.4; AEGIS-DOM-126).

`FirewallRead` implements `FirewallReadPort` over the real tables. Server-side only:

- every text field comes back through `redact_secret` (the level's secret becomes `[SECRET]`);
- no judge reason, tool argument, blocked text or trace-back field is ever selected;
- the transcript is what the student saw: their message, any readable tool effect (the decoy
  mail, or the attacker mailbox in Off), and the final reply as the arena showed it (the
  neutral refusal when blocked, the pending message while held, the decoy reply when diverted);
- session summaries are one query however many sessions are asked for (no N+1);
- insight counts read the one-minute continuous aggregates `fw_rule_fires_1m` and
  `fw_decisions_1m` (real time), with filters for mode, level and time (minute granularity).
  Leaving admin test sessions out needs the raw events, since an aggregate has no session;
- forensics (`get_forensics`, `get_attack_family_counts`) belong to M3: they are delegated to
  M3's `app.firewall.forensics_read` when it exists on this branch, else empty.
"""

from __future__ import annotations

import importlib
import json
from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.contracts.arena import SessionFilters
from app.contracts.firewall import NotFound, TurnResult
from app.contracts.firewall_read import (
    DecisionCount,
    DecisionItem,
    DivertItem,
    FamilyCount,
    ForensicItem,
    InsightFilters,
    ManifestSummary,
    PatternCount,
    RuleCount,
    SessionSummary,
    TicketItem,
    TranscriptItem,
)
from app.firewall.redact import redact_secret

ADMIN_TEST_SESSION_PAGE = 1000
SUMMARY_CHARS = 200

_FETCH_KEY = "SELECT secret FROM fw_sessions WHERE fw_session_id = :s"
_STUDENT_ROWS = (
    "SELECT message_id, content, created_at FROM fw_conversation"
    " WHERE fw_session_id = :s AND role = 'student' ORDER BY seq"
)
_CLAIMS = "SELECT message_id, result, updated_at FROM fw_claims WHERE fw_session_id = :s"
_TOOL_CALLS = "SELECT call_id, result, is_decoy FROM fw_tool_calls WHERE fw_session_id = :s"
_REPLY_DIVERTS = (
    "SELECT message_id FROM fw_events WHERE fw_session_id = :s AND stage = 'output_check'"
    " AND execution_status = 'diverted'"
)
_DECISIONS = (
    "SELECT event_id, time, message_id, stage, decision, shadow_decision, execution_status,"
    " sentinel_score, score_breakdown, thresholds_used, rule_ids_fired AS rule_ids,"
    " risky_pattern_ids_matched AS risky_pattern_ids FROM fw_events"
    " WHERE fw_session_id = :s ORDER BY time, event_id"
)
_TICKETS = (
    "SELECT ticket_id, stage, status, created_at, decided_at,"
    " CAST(decided_by AS text) AS decided_by FROM fw_tickets"
    " WHERE fw_session_id = :s ORDER BY created_at"
)
_SECRETS_ANY = (
    "SELECT fw_session_id, secret FROM fw_sessions WHERE fw_session_id = ANY(CAST(:ids AS text[]))"
)
_DIVERT_EVENTS_ANY = (
    "SELECT fw_session_id, event_id, time, stage, tool, call_id, message_id FROM fw_events"
    " WHERE fw_session_id = ANY(CAST(:ids AS text[])) AND execution_status = 'diverted'"
    " ORDER BY time, event_id"
)
_STUDENT_ROWS_ANY = (
    "SELECT fw_session_id, message_id, content FROM fw_conversation"
    " WHERE fw_session_id = ANY(CAST(:ids AS text[])) AND role = 'student'"
)
_BOT_ROWS_ANY = (
    "SELECT fw_session_id, message_id, content FROM fw_conversation"
    " WHERE fw_session_id = ANY(CAST(:ids AS text[])) AND role = 'bot'"
)
_TOOL_CALLS_ANY = (
    "SELECT fw_session_id, call_id, result FROM fw_tool_calls"
    " WHERE fw_session_id = ANY(CAST(:ids AS text[]))"
)
_DECOY_MAIL_ANY = (
    "SELECT fw_session_id, emails FROM fw_mock_state"
    " WHERE fw_session_id = ANY(CAST(:ids AS text[]))"
)
_SUMMARIES = (
    "SELECT s.fw_session_id,"
    " count(e.event_id) FILTER (WHERE e.execution_status = 'diverted') AS diverted_count,"
    " max(e.sentinel_score) AS max_sentinel_score,"
    " min(e.time) FILTER (WHERE e.secret_delivered) AS secret_delivered_at,"
    " coalesce(bool_or(e.echo_excluded), false) AS echo_excluded"
    " FROM fw_sessions s LEFT JOIN fw_events e ON e.fw_session_id = s.fw_session_id"
    " WHERE s.fw_session_id = ANY(CAST(:ids AS text[])) GROUP BY s.fw_session_id"
)
_MANIFEST = (
    "SELECT manifest_id, level_id, level_version, mode, rule_set_version AS rule_version,"
    " pattern_version, thresholds, weights, bot_model_id, judge_model_id, judge_policy_hash"
    " FROM fw_manifests WHERE fw_session_id = :s"
)

# Every filter is a bound parameter; NULL means "no filter". Aggregates are per minute, so
# `since` keeps a bucket that ends after it and `until` one that starts before it. Each query is
# one literal (no assembly), so none can be built from input.
_RULE_FIRES_AGG = (
    "SELECT r.rule_id AS key, sum(f.events)::int AS n FROM fw_rule_fires_1m f,"
    " unnest(f.rule_ids_fired) AS r(rule_id) WHERE true"
    " AND (CAST(:mode AS text) IS NULL OR f.mode = CAST(:mode AS text))"
    " AND (CAST(:level AS text) IS NULL OR f.level_id = CAST(:level AS text))"
    " AND (CAST(:since AS timestamptz) IS NULL"
    "      OR f.bucket + INTERVAL '1 minute' > CAST(:since AS timestamptz))"
    " AND (CAST(:until AS timestamptz) IS NULL OR f.bucket < CAST(:until AS timestamptz))"
    " GROUP BY r.rule_id ORDER BY n DESC, key"
)
_RULE_FIRES_RAW = (
    "SELECT r.rule_id AS key, count(*)::int AS n FROM fw_events e,"
    " unnest(e.rule_ids_fired) AS r(rule_id)"
    " WHERE e.stage NOT IN ('tool_executed', 'finalize')"
    " AND (CAST(:mode AS text) IS NULL OR e.mode = CAST(:mode AS text))"
    " AND (CAST(:level AS text) IS NULL OR e.level_id = CAST(:level AS text))"
    " AND (CAST(:since AS timestamptz) IS NULL OR e.time >= CAST(:since AS timestamptz))"
    " AND (CAST(:until AS timestamptz) IS NULL OR e.time < CAST(:until AS timestamptz))"
    " AND NOT (e.fw_session_id = ANY(CAST(:excluded AS text[])))"
    " GROUP BY r.rule_id ORDER BY n DESC, key"
)
_DECISIONS_AGG = (
    "SELECT f.mode, f.decision, sum(f.events)::int AS n FROM fw_decisions_1m f WHERE true"
    " AND (CAST(:mode AS text) IS NULL OR f.mode = CAST(:mode AS text))"
    " AND (CAST(:level AS text) IS NULL OR f.level_id = CAST(:level AS text))"
    " AND (CAST(:since AS timestamptz) IS NULL"
    "      OR f.bucket + INTERVAL '1 minute' > CAST(:since AS timestamptz))"
    " AND (CAST(:until AS timestamptz) IS NULL OR f.bucket < CAST(:until AS timestamptz))"
    " GROUP BY f.mode, f.decision ORDER BY f.mode, f.decision"
)
_DECISIONS_RAW = (
    "SELECT e.mode, e.decision, count(*)::int AS n FROM fw_events e"
    " WHERE e.stage NOT IN ('tool_executed', 'finalize')"
    " AND (CAST(:mode AS text) IS NULL OR e.mode = CAST(:mode AS text))"
    " AND (CAST(:level AS text) IS NULL OR e.level_id = CAST(:level AS text))"
    " AND (CAST(:since AS timestamptz) IS NULL OR e.time >= CAST(:since AS timestamptz))"
    " AND (CAST(:until AS timestamptz) IS NULL OR e.time < CAST(:until AS timestamptz))"
    " AND NOT (e.fw_session_id = ANY(CAST(:excluded AS text[])))"
    " GROUP BY e.mode, e.decision ORDER BY e.mode, e.decision"
)
_PATTERNS = (
    "SELECT p.pattern_id AS key, count(*)::int AS n FROM fw_events e,"
    " unnest(e.risky_pattern_ids_matched) AS p(pattern_id)"
    " WHERE e.stage NOT IN ('tool_executed', 'finalize')"
    " AND (CAST(:mode AS text) IS NULL OR e.mode = CAST(:mode AS text))"
    " AND (CAST(:level AS text) IS NULL OR e.level_id = CAST(:level AS text))"
    " AND (CAST(:since AS timestamptz) IS NULL OR e.time >= CAST(:since AS timestamptz))"
    " AND (CAST(:until AS timestamptz) IS NULL OR e.time < CAST(:until AS timestamptz))"
    " AND NOT (e.fw_session_id = ANY(CAST(:excluded AS text[])))"
    " GROUP BY p.pattern_id ORDER BY n DESC, key"
)


class SessionLister(Protocol):
    """The one thing needed from the arena service (C4): which sessions are admin tests."""

    async def list_sessions(self, filters: SessionFilters) -> Sequence[Any]: ...


class ForensicsSource(Protocol):
    """M3's forensics reader (`app.firewall.forensics_read.ForensicsRead`)."""

    async def get_forensics(self, fw_session_id: str) -> list[ForensicItem]: ...

    async def get_attack_family_counts(self, filters: InsightFilters) -> list[FamilyCount]: ...


def _json(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


def _mail_text(mail: Mapping[str, Any]) -> str:
    return f"To: {', '.join(mail['to'])}\nSubject: {mail['subject']}\n\n{mail['body']}"


def _filter_params(filters: InsightFilters, excluded: list[str]) -> dict[str, Any]:
    return {
        "mode": filters.mode,
        "level": filters.level_id,
        "since": filters.since,
        "until": filters.until,
        "excluded": excluded,
    }


class FirewallRead:
    def __init__(
        self,
        engine: AsyncEngine,
        arena: SessionLister | None = None,
        forensics: ForensicsSource | None = None,
    ) -> None:
        self._engine = engine
        self._arena = arena
        self._forensics = forensics

    # --- helpers ---------------------------------------------------------------------------

    async def _secret(self, conn: AsyncConnection, fw_session_id: str) -> str:
        found = (await conn.execute(text(_FETCH_KEY), {"s": fw_session_id})).scalar_one_or_none()
        if found is None:
            raise NotFound("session not found")
        return str(found)

    async def _admin_test_sessions(self) -> list[str]:
        """Every admin test session, page by page (no silent cap)."""
        if self._arena is None:
            raise RuntimeError("leaving admin test sessions out needs the arena service (C4)")
        found: list[str] = []
        while True:
            page = await self._arena.list_sessions(
                SessionFilters(admin_test=True, limit=ADMIN_TEST_SESSION_PAGE, offset=len(found))
            )
            found += [s.fw_session_id for s in page]
            if len(page) < ADMIN_TEST_SESSION_PAGE:
                return found

    # --- per session ------------------------------------------------------------------------

    async def get_transcript(self, fw_session_id: str) -> list[TranscriptItem]:
        async with self._engine.connect() as conn:
            secret = await self._secret(conn, fw_session_id)
            p = {"s": fw_session_id}
            students = (await conn.execute(text(_STUDENT_ROWS), p)).mappings().all()
            claims = {r["message_id"]: r for r in (await conn.execute(text(_CLAIMS), p)).mappings()}
            decoy_calls = {
                r["call_id"] for r in (await conn.execute(text(_TOOL_CALLS), p)).mappings()
                if r["is_decoy"]
            }  # fmt: skip
            reply_decoys = set((await conn.execute(text(_REPLY_DIVERTS), p)).scalars())

        def red(value: str) -> str:
            return redact_secret(value, secret)

        items: list[TranscriptItem] = []
        for row in students:
            mid = row["message_id"]
            items.append(
                TranscriptItem(
                    message_id=mid,
                    time=row["created_at"],
                    speaker="student",
                    text=red(row["content"]),
                )
            )
            claim = claims.get(mid)
            if claim is None or claim["result"] is None:
                continue
            view = TurnResult.model_validate(_json(claim["result"])).player_view
            for effect in view.tool_effects:
                if effect.visible_content:
                    items.append(
                        TranscriptItem(
                            message_id=mid,
                            time=claim["updated_at"],
                            speaker="tool",
                            text=red(effect.visible_content),
                            is_decoy=effect.call_id in decoy_calls,
                        )
                    )
            if view.reply is not None:
                items.append(
                    TranscriptItem(
                        message_id=mid,
                        time=claim["updated_at"],
                        speaker="bot",
                        text=red(view.reply),
                        status=view.status,
                        is_decoy=mid in reply_decoys,
                    )
                )
        return items

    async def get_decisions(self, fw_session_id: str) -> list[DecisionItem]:
        async with self._engine.connect() as conn:
            rows = (await conn.execute(text(_DECISIONS), {"s": fw_session_id})).mappings().all()
        return [
            DecisionItem.model_validate(
                {
                    **r,
                    "score_breakdown": _json(r["score_breakdown"]),
                    "thresholds_used": _json(r["thresholds_used"]),
                    "rule_ids": list(r["rule_ids"] or []),
                    "risky_pattern_ids": list(r["risky_pattern_ids"] or []),
                }
            )
            for r in rows
        ]

    async def get_tickets(self, fw_session_id: str) -> list[TicketItem]:
        async with self._engine.connect() as conn:
            rows = (await conn.execute(text(_TICKETS), {"s": fw_session_id})).mappings().all()
        return [TicketItem.model_validate(dict(r)) for r in rows]

    async def get_diverts(self, fw_session_id: str) -> list[DivertItem]:
        found = await self.divert_items([fw_session_id])
        if fw_session_id not in found:
            raise NotFound("session not found")
        return found[fw_session_id]

    async def divert_items(self, session_ids: Sequence[str]) -> dict[str, list[DivertItem]]:
        """Divert items for several sessions in a fixed number of queries (also used by the
        admin API). A session that does not exist is absent from the answer."""
        ids = list(dict.fromkeys(session_ids))
        if not ids:
            return {}
        p = {"ids": ids}
        async with self._engine.connect() as conn:
            secrets = {
                r["fw_session_id"]: r["secret"]
                for r in (await conn.execute(text(_SECRETS_ANY), p)).mappings()
            }
            events = (await conn.execute(text(_DIVERT_EVENTS_ANY), p)).mappings().all()
            asked = {
                (r["fw_session_id"], r["message_id"]): r["content"]
                for r in (await conn.execute(text(_STUDENT_ROWS_ANY), p)).mappings()
            }
            said = {
                (r["fw_session_id"], r["message_id"]): r["content"]
                for r in (await conn.execute(text(_BOT_ROWS_ANY), p)).mappings()
            }
            results = {
                (r["fw_session_id"], r["call_id"]): r["result"] or ""
                for r in (await conn.execute(text(_TOOL_CALLS_ANY), p)).mappings()
            }
            states = (await conn.execute(text(_DECOY_MAIL_ANY), p)).mappings().all()
        mails = {
            (st["fw_session_id"], m["call_id"]): _mail_text(m)
            for st in states
            for m in _json(st["emails"])
            if m.get("is_decoy") and m.get("call_id")
        }
        found: dict[str, list[DivertItem]] = {sid: [] for sid in secrets}
        for e in events:
            sid = e["fw_session_id"]
            question = (asked.get((sid, e["message_id"])) or "")[:SUMMARY_CHARS]
            if e["tool"]:
                summary = f'Asked: "{question}". The assistant tried to use {e["tool"]}.'
                shown = mails.get((sid, e["call_id"])) or results.get((sid, e["call_id"]), "")
            else:
                summary = (
                    f'Asked: "{question}". The assistant\'s reply would have revealed the secret.'
                )
                shown = said.get((sid, e["message_id"]), "")
            found[sid].append(
                DivertItem(
                    event_id=e["event_id"],
                    time=e["time"],
                    stage=e["stage"],
                    tool=e["tool"],
                    attempted_summary=redact_secret(summary, secrets[sid]),
                    decoy_shown=redact_secret(shown, secrets[sid]),
                )
            )
        return found

    async def get_forensics(self, fw_session_id: str) -> list[ForensicItem]:
        if self._forensics is None:
            return []
        return await self._forensics.get_forensics(fw_session_id)

    # --- batches, manifest, redaction ---------------------------------------------------------

    async def get_session_summaries(self, fw_session_ids: list[str]) -> list[SessionSummary]:
        ids = list(dict.fromkeys(fw_session_ids))
        if not ids:
            return []
        async with self._engine.connect() as conn:
            rows = (await conn.execute(text(_SUMMARIES), {"ids": ids})).mappings().all()
        by_id = {r["fw_session_id"]: SessionSummary.model_validate(dict(r)) for r in rows}
        return [by_id[i] for i in ids if i in by_id]

    async def get_manifest_summary(self, fw_session_id: str) -> ManifestSummary:
        async with self._engine.connect() as conn:
            row = (await conn.execute(text(_MANIFEST), {"s": fw_session_id})).mappings().first()
        if row is None:
            raise NotFound("session not found")
        return ManifestSummary.model_validate(
            {**row, "thresholds": _json(row["thresholds"]), "weights": _json(row["weights"])}
        )

    async def redact_for_session(self, fw_session_id: str, text_value: str) -> str:
        async with self._engine.connect() as conn:
            secret = await self._secret(conn, fw_session_id)
        return redact_secret(text_value, secret)

    # --- insight counts ---------------------------------------------------------------------------

    async def _counts(
        self, aggregate: str, raw: str, filters: InsightFilters
    ) -> list[Mapping[str, Any]]:
        excluded = [] if filters.include_admin_test else await self._admin_test_sessions()
        params = _filter_params(filters, excluded)
        statement = raw if excluded else aggregate
        async with self._engine.connect() as conn:
            return list((await conn.execute(text(statement), params)).mappings())

    async def get_rule_fire_counts(self, filters: InsightFilters) -> list[RuleCount]:
        rows = await self._counts(_RULE_FIRES_AGG, _RULE_FIRES_RAW, filters)
        return [RuleCount(rule_id=r["key"], count=r["n"]) for r in rows]

    async def get_decision_counts(self, filters: InsightFilters) -> list[DecisionCount]:
        rows = await self._counts(_DECISIONS_AGG, _DECISIONS_RAW, filters)
        return [DecisionCount(mode=r["mode"], decision=r["decision"], count=r["n"]) for r in rows]

    async def get_risky_pattern_counts(self, filters: InsightFilters) -> list[PatternCount]:
        rows = await self._counts(_PATTERNS, _PATTERNS, filters)
        return [PatternCount(pattern_id=r["key"], count=r["n"]) for r in rows]

    async def get_attack_family_counts(self, filters: InsightFilters) -> list[FamilyCount]:
        if self._forensics is None:
            return []
        return await self._forensics.get_attack_family_counts(filters)


class _LazyArena:
    """The arena service (C4), looked up the first time it is needed so that building this
    reader never builds the arena."""

    async def list_sessions(self, filters: SessionFilters) -> Sequence[Any]:
        from app.firewall.ports import get_arena_service

        return await get_arena_service().list_sessions(filters)


def _forensics_reader() -> ForensicsSource | None:
    try:
        module = importlib.import_module("app.firewall.forensics_read")
    except ModuleNotFoundError:  # M3's reader is not on this branch yet
        return None
    reader: ForensicsSource = module.create()
    return reader


def create() -> FirewallRead:
    """The factory M1's `ports.py` calls when `read` is not faked."""
    from app.config import get_settings
    from app.db.engine import make_engine

    engine = make_engine(get_settings().database_url)
    return FirewallRead(engine, _LazyArena(), _forensics_reader())
