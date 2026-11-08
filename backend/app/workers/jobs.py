"""Background jobs in the worker process (M3 C-08, PRD §7.5, §8.5, §15.1).

`backfill_embeddings` fills `risky_behavior_events.input_embedding` rows that `record_behavior`
wrote as NULL (M3-X11). It runs outside any M2 transaction: a short read, model calls with no
transaction open, then one short update per row. Only the text whose SHA-256 equals the stored
`input_text_hash` is ever embedded. `purge_trace_back` calls M2's purge every hour (M3-X41).
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.contracts.firewall_admin import FirewallAdminPort
from app.contracts.sentinel import RiskyHistoryError
from app.firewall.risky_history import EMBED_TIMEOUT_S, as_float32, text_hash, vector_literal
from app.llm.base import Embedder, LLMError

log = logging.getLogger("aegis.workers.jobs")

BACKFILL_INTERVAL_S = 60.0
BACKFILL_BATCH = 50
PURGE_INTERVAL_S = 3600  # hourly (PRD §8.5, M3-X41)

_PENDING = text(
    "SELECT time, event_id, input_text_hash FROM risky_behavior_events"
    " WHERE input_embedding IS NULL AND NOT (event_id = ANY(CAST(:skip AS text[])))"
    " ORDER BY time LIMIT :n"
)
_FILL = text(
    "UPDATE risky_behavior_events SET input_embedding = CAST(CAST(:e AS text) AS vector(768))"
    " WHERE time = :time AND event_id = :event_id AND input_embedding IS NULL"
)

TextsFor = Callable[[list[str]], Awaitable[dict[str, str]]]


class _Transient(Exception):
    """The model call failed this time; the row is retried at the next run (Codex round 1)."""


async def _vector(embedder: Embedder, value: str) -> str | None:
    """The same checks as the lookup (768 finite float32 values, not all zero). None for a
    vector that can never be stored; `_Transient` for a call that may work next time."""
    try:
        raw = await embedder.embed(value, timeout_s=EMBED_TIMEOUT_S)
    except (LLMError, TimeoutError) as exc:
        raise _Transient(type(exc).__name__) from exc
    try:
        floats = as_float32(raw)
    except RiskyHistoryError:
        log.warning("backfill embedding refused: not 768 finite float32 values")
        return None
    return vector_literal(floats) if any(floats) else None


async def backfill_embeddings(
    engine: AsyncEngine,
    embedder: Embedder,
    texts_for: TextsFor,
    skipped: set[str],
    batch: int = BACKFILL_BATCH,
) -> int:
    """Embed one batch of NULL rows; returns how many were filled. Rows that can never be filled
    (no text, text not matching the stored hash, an unusable vector) go into `skipped`, kept by
    the caller for the process lifetime, so they never block the batch. A transient model error
    stops this run and leaves the row for the next one."""
    async with engine.connect() as conn:
        rows = (await conn.execute(_PENDING, {"skip": sorted(skipped), "n": batch})).all()
    if not rows:
        return 0
    texts = await texts_for([r.event_id for r in rows])
    filled = 0
    for row in rows:
        value = texts.get(row.event_id)
        if value is None or text_hash(value) != row.input_text_hash:
            skipped.add(row.event_id)
            continue
        try:
            vector = await _vector(embedder, value)
        except _Transient as exc:
            log.warning("backfill paused until the next run: %s", exc)
            break
        if vector is None:
            skipped.add(row.event_id)
            continue
        async with engine.begin() as conn:
            result = await conn.execute(
                _FILL, {"e": vector, "time": row.time, "event_id": row.event_id}
            )
        filled += result.rowcount
    return filled


async def purge_trace_back(admin: FirewallAdminPort) -> int:
    """M2 deletes trace-back rows older than 30 days (C6 `purge_expired_trace_back`)."""
    purged = await admin.purge_expired_trace_back(datetime.now(UTC))
    log.info("trace-back purge removed %d row(s)", purged)
    return purged
