"""Strict Sentinel layer 2: risky history (PRD §7.3, §7.5, C7 `RiskyHistoryPort`, M3 A-02, B-02).

`lookup` is one SQL round trip per checked item and fails closed: any DB, embedding or stored
pattern problem raises `RiskyHistoryError`, never partial signals (I-2). `record_behavior` and
`add_candidate` run on M2's connection inside M2's transaction and make no network calls (§15.1).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import struct
import time
from collections import OrderedDict
from typing import Any, Literal

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.contracts.sentinel import (
    CheckedItem,
    PatternCandidate,
    RiskyBehaviorRecord,
    RiskyHistoryError,
    RiskyHistorySignals,
)
from app.firewall.risky_patterns import PatternSpec, match, structural_errors
from app.llm.base import EMBEDDING_DIMENSIONS, Embedder

EMBED_TIMEOUT_S = 2.0
# ponytail: per-process LRU of text-hash -> embedding (lookup then record_behavior on the same
# item). A miss writes NULL and the C-08 backfill fills it; share across processes only if needed.
EMBED_CACHE_SIZE = 4096
SIMILAR_TOP_K = 3

USER_TOOL_POINTS_EACH = 15
USER_TOOL_POINTS_MAX = 30
USER_TOOL_WINDOW_DAYS = 7
PRIOR_DIVERT_POINTS = 20
SIMILARITY_HIGH = 0.85  # +25
SIMILARITY_LOW = 0.75  # +10


def similarity_points(top: float | None) -> Literal[0, 10, 25]:
    """Only one bucket applies (PRD §7.3)."""
    if top is None:
        return 0
    if top >= SIMILARITY_HIGH:
        return 25
    if top >= SIMILARITY_LOW:
        return 10
    return 0


def score_signals(
    *,
    tool: str | None,
    matched_pattern_ids: list[str],
    same_tool_events: int,
    has_prior_divert: bool,
    similarity_top: float | None,
    latency_ms: int,
) -> RiskyHistorySignals:
    """Layer 2 points from already-filtered counts.

    `same_tool_events`: this user's non-shadow events on `tool` in the last 7 days.
    `has_prior_divert`: any earlier non-shadow divert by this user.
    An input check (`tool is None`) skips the user-tool signal (M3-X06).
    """
    user_points = (
        0 if tool is None else min(USER_TOOL_POINTS_EACH * same_tool_events, USER_TOOL_POINTS_MAX)
    )
    return RiskyHistorySignals(
        forced_deny=bool(matched_pattern_ids),
        matched_pattern_ids=matched_pattern_ids,
        user_tool_events_points=user_points,
        prior_divert_points=PRIOR_DIVERT_POINTS if has_prior_divert else 0,
        similarity_points=similarity_points(similarity_top),
        similarity_top=similarity_top,
        latency_ms=latency_ms,
    )


# One round trip (PRD §7.5). The pinned version decides at both ends (E-43, M3-X15, I-7);
# shadow rows count only for similarity (M3-X07); a NULL tool (input check) counts nothing.
LOOKUP_SQL = """
WITH patterns AS (
    SELECT coalesce(
        jsonb_agg(jsonb_build_object('id', pattern_id::text, 'conditions', conditions)
                  ORDER BY approved_in_version),
        '[]'::jsonb) AS rows
    FROM risky_tool_patterns
    WHERE status = 'approved' AND tool = :tool AND approved_in_version <= :pin
      AND (retired_in_version IS NULL OR retired_in_version > :pin)
), user_tool AS (
    SELECT count(*) AS n FROM risky_behavior_events
    WHERE user_id = CAST(:user_id AS uuid) AND tool = :tool AND NOT shadow
      AND time >= now() - make_interval(days => :window_days)
), prior_divert AS (
    SELECT EXISTS (
        SELECT 1 FROM risky_behavior_events
        WHERE user_id = CAST(:user_id AS uuid) AND action = 'divert' AND NOT shadow
    ) AS hit
), nearest AS (
    SELECT input_embedding <=> CAST(CAST(:embedding AS text) AS vector(768)) AS distance
    FROM risky_behavior_events
    WHERE input_embedding IS NOT NULL
    ORDER BY distance
    LIMIT :top_k
)
SELECT patterns.rows AS patterns, user_tool.n AS same_tool_events,
       prior_divert.hit AS has_prior_divert,
       (SELECT max(1 - distance) FROM nearest) AS similarity_top
FROM patterns, user_tool, prior_divert
"""
_LOOKUP = text(LOOKUP_SQL)

_RECORD = text(
    "INSERT INTO risky_behavior_events (time, user_id, fw_session_id, event_id, stage, tool,"
    " args_hash, action, sentinel_score, rule_ids, input_text_hash, input_embedding, trace_id,"
    " shadow) VALUES (:time, CAST(:user_id AS uuid), :fw_session_id, :event_id, :stage, :tool,"
    " :args_hash, :action, :sentinel_score, CAST(:rule_ids AS text[]), :input_text_hash,"
    " CAST(CAST(:embedding AS text) AS vector(768)), :trace_id, :shadow)"
)
_CANDIDATE = text(
    "INSERT INTO risky_tool_patterns (tool, status, source_event_id, source_user_id,"
    " source_args, source_args_hash) VALUES (:tool, 'candidate', :source_event_id,"
    " CAST(:user_id AS uuid), CAST(:args AS jsonb), :args_hash)"
    " ON CONFLICT (tool, source_args_hash) WHERE source_args_hash IS NOT NULL DO NOTHING"
)
VERSION_SQL = text(
    "SELECT greatest("
    " (SELECT coalesce(max(version), 0) FROM risky_pattern_versions),"
    " coalesce(max(approved_in_version), 0), coalesce(max(retired_in_version), 0))"
    " FROM risky_tool_patterns"
)


def text_hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def canonical_args_hash(args: dict[str, Any]) -> str:
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text_hash(canonical)


def as_float32(values: Any) -> list[float]:
    """Round-trip through float32 (pgvector's storage): overflow raises, underflow flushes."""
    try:
        floats = [float(v) for v in values]
        if len(floats) != EMBEDDING_DIMENSIONS or not all(map(math.isfinite, floats)):
            raise ValueError("wrong shape or non-finite")
        packed = struct.pack(f"<{len(floats)}f", *floats)  # OverflowError outside float32
    except (TypeError, ValueError, OverflowError, struct.error) as exc:
        raise RiskyHistoryError("embedding is not 768 finite float32 numbers") from exc
    return list(struct.unpack(f"<{len(floats)}f", packed))


def vector_literal(values: list[float]) -> str:
    return "[" + ",".join(repr(float(v)) for v in values) + "]"


def lookup_params(item: CheckedItem, embedding: str) -> dict[str, Any]:
    return {
        "tool": item.tool,
        "pin": item.pattern_version,
        "user_id": item.user_id,
        "window_days": USER_TOOL_WINDOW_DAYS,
        "embedding": embedding,
        "top_k": SIMILAR_TOP_K,
    }


def _matched(rows: list[dict[str, Any]], item: CheckedItem) -> list[str]:
    """Re-validate stored conditions through `PatternSpec`; a corrupt row fails closed."""
    if item.tool is None:
        return []
    try:
        specs = [(r["id"], PatternSpec(tool=item.tool, conditions=r["conditions"])) for r in rows]
    except (ValidationError, KeyError, TypeError) as exc:
        raise RiskyHistoryError("a stored approved pattern is invalid") from exc
    # A malformed approved pattern would silently never match: fail closed instead.
    if any(structural_errors(spec) for _, spec in specs):
        raise RiskyHistoryError("a stored approved pattern is structurally invalid")
    return [pid for pid, spec in specs if match(spec, item.tool, item.canonical_args or {})]


class RiskyHistory:
    def __init__(self, engine: AsyncEngine, embedder: Embedder) -> None:
        self._engine = engine
        self._embedder = embedder
        self._cache: OrderedDict[str, str] = OrderedDict()

    async def _embed(self, value: str) -> str:
        try:
            async with asyncio.timeout(EMBED_TIMEOUT_S):
                values = await self._embedder.embed(value, timeout_s=EMBED_TIMEOUT_S)
        except Exception as exc:  # LLMError, timeout, budget: fail closed (M3-X10)
            raise RiskyHistoryError(f"embedding failed: {type(exc).__name__}") from exc
        # Validate before caching, so a bad vector can never reach M2's transaction later.
        floats = as_float32(values)  # exactly what pgvector will store
        if not any(floats):
            raise RiskyHistoryError("embedding has zero norm as float32 (cosine undefined)")
        literal = vector_literal(floats)
        key = text_hash(value)
        self._cache[key] = literal
        self._cache.move_to_end(key)
        while len(self._cache) > EMBED_CACHE_SIZE:
            self._cache.popitem(last=False)
        return literal

    async def lookup(self, item: CheckedItem) -> RiskyHistorySignals:
        start = time.perf_counter()
        embedding = await self._embed(item.text)
        try:
            async with self._engine.connect() as conn:
                row = (await conn.execute(_LOOKUP, lookup_params(item, embedding))).one()
        except Exception as exc:  # any DB error fails closed (M3-X09)
            raise RiskyHistoryError(f"risky history query failed: {type(exc).__name__}") from exc
        try:
            top = row.similarity_top
            if top is not None and not math.isfinite(top):  # e.g. a zero vector in the corpus
                raise RiskyHistoryError("similarity is not a finite number")
            return score_signals(
                tool=item.tool,
                matched_pattern_ids=_matched(row.patterns, item),
                same_tool_events=int(row.same_tool_events),
                has_prior_divert=bool(row.has_prior_divert),
                similarity_top=None if top is None else float(top),
                latency_ms=round((time.perf_counter() - start) * 1000),
            )
        except RiskyHistoryError:
            raise
        except Exception as exc:  # matcher or scoring bug: still only RiskyHistoryError (I-2)
            raise RiskyHistoryError(f"risky history scoring failed: {type(exc).__name__}") from exc

    async def record_behavior(self, record: RiskyBehaviorRecord, conn: AsyncConnection) -> None:
        """Joins the caller's transaction. Embedding from the lookup cache, else NULL (M3-X11)."""
        key = text_hash(record.input_text)
        await conn.execute(
            _RECORD,
            {
                **record.model_dump(exclude={"input_text"}),
                "input_text_hash": key,
                "embedding": self._cache.get(key),
            },
        )

    async def add_candidate(self, candidate: PatternCandidate, conn: AsyncConnection) -> None:
        """A `candidate` row with no conditions yet; the same tool and arguments only once."""
        await conn.execute(
            _CANDIDATE,
            {
                "tool": candidate.tool,
                "source_event_id": candidate.source_event_id,
                "user_id": candidate.user_id,
                "args": json.dumps(candidate.canonical_args, ensure_ascii=False),
                "args_hash": canonical_args_hash(candidate.canonical_args),
            },
        )

    async def current_pattern_version(self) -> int:
        """Highest version issued by an approval or a retirement, else 0 (plan §10)."""
        try:
            async with self._engine.connect() as conn:
                return int((await conn.execute(VERSION_SQL)).scalar_one())
        except Exception as exc:
            raise RiskyHistoryError("pattern version query failed") from exc


def create() -> RiskyHistory:
    """`ports.py` factory (`app.firewall.risky_history:create`)."""
    from app.config import get_settings
    from app.db.engine import get_engine
    from app.llm.budget import DailyBudget
    from app.llm.gemini import GeminiClient

    settings = get_settings()
    if not settings.gemini_embedding_model_id:
        raise RuntimeError("AEGIS_GEMINI_EMBEDDING_MODEL_ID is not set")
    engine = get_engine()
    client = GeminiClient(
        settings.gemini_api_key.get_secret_value(),
        DailyBudget(engine, settings.daily_llm_budget),
        settings.gemini_embedding_model_id,
    )
    return RiskyHistory(engine, client)
