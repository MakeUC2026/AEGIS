"""Worker entry point (`python -m app.workers`). Gate 0 placeholder created by M1 so the
compose and Railway `worker` service runs; M3 replaces it with the forensic worker.
"""

from __future__ import annotations

import asyncio
import logging

IDLE_LOG_INTERVAL_S = 300

log = logging.getLogger("aegis.workers")


async def _idle() -> None:
    while True:
        log.info("no workers registered yet (M3 forensic worker pending)")
        await asyncio.sleep(IDLE_LOG_INTERVAL_S)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(_idle())
