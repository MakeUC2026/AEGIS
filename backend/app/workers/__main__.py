"""Worker entry point (`python -m app.workers`): the forensic worker plus its jobs (M3 C-01, C-08).

Until M2's `0003_firewall_core` lands there is no `fw_events` to read, so the worker runs on an
empty `InMemoryEventSource`: it listens, polls and runs the jobs, and analyses nothing. When
`0003` lands, swap in the real `fw_events` source (see `events.py`).
"""

from __future__ import annotations

import asyncio
import logging
import signal

from app.config import get_settings
from app.db.engine import get_engine
from app.firewall import ports
from app.llm.budget import DailyBudget
from app.llm.gemini import GeminiClient
from app.workers.events import InMemoryEventSource
from app.workers.forensics import ForensicWorker, run_worker
from app.workers.jobs import (
    BACKFILL_INTERVAL_S,
    PURGE_INTERVAL_S,
    backfill_embeddings,
    purge_trace_back,
)

log = logging.getLogger("aegis.workers")


async def main() -> None:
    settings = get_settings()
    model = settings.gemini_pro_model_id or settings.gemini_flash_model_id  # Pro if budgeted
    if not model or not settings.gemini_embedding_model_id:
        raise RuntimeError("forensic and embedding model IDs must be set (AEGIS_GEMINI_*)")
    engine = get_engine()
    client = GeminiClient(
        settings.gemini_api_key.get_secret_value(),
        DailyBudget(engine, settings.daily_llm_budget),
        settings.gemini_embedding_model_id,
    )
    source = InMemoryEventSource(engine)
    log.warning("no fw_events yet (M2 0003 not landed): the forensic worker has nothing to read")
    worker = ForensicWorker(source, client, model, client)
    skipped: set[str] = set()

    async def backfill() -> None:
        await backfill_embeddings(engine, client, source.texts_for, skipped)

    async def purge() -> None:
        await purge_trace_back(ports.get_firewall_admin())

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    jobs = [(BACKFILL_INTERVAL_S, backfill), (float(PURGE_INTERVAL_S), purge)]
    try:
        await run_worker(worker, engine, stop=stop, jobs=jobs)
    finally:
        await client.aclose()
        await engine.dispose()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
