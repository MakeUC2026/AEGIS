"""B-06 / AC-7: risky history lookup under 50 ms p95 (PRD §7.5, §15.1).

10,000 `risky_behavior_events` rows with embeddings, 200 patterns, 200 timed lookups. The
embedding API call is excluded (an instant embedder), so the number is the DB round trip plus
the Python pattern match. Prints p50, p95 and the EXPLAIN ANALYZE plan for the Progress log.
"""

from __future__ import annotations

import json
import re
import statistics
import time

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.firewall import risky_history
from app.firewall.risky_history import RiskyHistory
from tests.integration.m3_helpers import ConstEmbedder, item, vec_text

EVENTS = 10_000
PATTERNS = 200
USERS = 50
RUNS = 200
P95_LIMIT_MS = 50.0
TOOLS = ("send_email", "query_db", "run_shell", "read_file", "search_docs")


async def _seed(engine: AsyncEngine) -> list[str]:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO users (auth0_sub, role)"
                " SELECT 'auth0|perf-' || g, 'student' FROM generate_series(1, :n) g"
            ),
            {"n": USERS},
        )
        users = [
            str(r[0])
            for r in await conn.execute(
                text("SELECT id FROM users WHERE auth0_sub LIKE 'auth0|perf-%' ORDER BY id")
            )
        ]
        # Random 768-d embeddings, spread over 30 days, a mix of shadow rows and actions.
        await conn.execute(
            text(
                "INSERT INTO risky_behavior_events (time, user_id, fw_session_id, event_id,"
                " stage, tool, args_hash, action, sentinel_score, rule_ids, input_text_hash,"
                " input_embedding, trace_id, shadow)"
                " SELECT now() - (random() * interval '30 days'),"
                " (CAST(:users AS uuid[]))[1 + (g % :nu)], 'fws-perf-' || (g % 400),"
                " 'evt-perf-' || g, 'tool_call_check', (CAST(:tools AS text[]))[1 + (g % 5)],"
                " 'sha256:' || g, (ARRAY['deny', 'human_deny', 'divert'])[1 + (g % 3)],"
                " 60 + (g % 40), ARRAY['R-003'], 'sha256:t' || g,"
                " (SELECT CAST(array_agg(random() - 0.5) AS vector)"
                "  FROM generate_series(1, 768) d WHERE g > 0),"
                " NULL, g % 4 = 0"
                " FROM generate_series(1, :n) g"
            ),
            {"users": users, "nu": USERS, "tools": list(TOOLS), "n": EVENTS},
        )
        for i in range(PATTERNS):
            await conn.execute(
                text(
                    "INSERT INTO risky_tool_patterns (tool, conditions, status,"
                    " approved_in_version) VALUES (:t, CAST(:c AS jsonb), 'approved', :v)"
                ),
                {
                    "t": TOOLS[i % len(TOOLS)],
                    "c": json.dumps(
                        [{"arg": "to", "op": "contains", "value": f"perf-nomatch-{i}"}]
                    ),
                    "v": i + 1,
                },
            )
        await conn.execute(text("ANALYZE risky_behavior_events"))
        await conn.execute(text("ANALYZE risky_tool_patterns"))
    return users


async def test_b06_lookup_p95_under_50ms(engine: AsyncEngine) -> None:
    users = await _seed(engine)
    probe = [0.01 * ((i * 7) % 13 - 6) for i in range(768)]
    hist = RiskyHistory(engine, ConstEmbedder(probe))
    for _ in range(20):  # warm the pool and plan cache
        await hist.lookup(item(users[0], pin=PATTERNS))
    timings: list[float] = []
    for i in range(RUNS):
        it = item(users[i % USERS], tool=TOOLS[i % len(TOOLS)], pin=PATTERNS)
        start = time.perf_counter()
        sig = await hist.lookup(it)
        timings.append((time.perf_counter() - start) * 1000)
        assert sig.similarity_top is not None
    p50 = statistics.median(timings)
    p95 = statistics.quantiles(timings, n=100)[94]

    async with engine.connect() as conn:
        plan = await conn.execute(
            text("EXPLAIN (ANALYZE, BUFFERS) " + risky_history.LOOKUP_SQL),
            risky_history.lookup_params(item(users[1], pin=PATTERNS), vec_text(probe) or ""),
        )
        plan_text = re.sub(r"'\[[^\]]*\]'", "'[probe]'", "\n".join(r[0] for r in plan))
    print(f"\nB-06 lookup over {RUNS} runs: p50={p50:.2f} ms p95={p95:.2f} ms\n{plan_text}")
    # The vector branch walks each chunk's HNSW index in distance order, never a seq scan + sort.
    assert "risky_behavior_events_embedding_idx" in plan_text
    assert "Order By: (input_embedding <=>" in plan_text
    assert "Seq Scan" not in plan_text
    assert p95 < P95_LIMIT_MS
