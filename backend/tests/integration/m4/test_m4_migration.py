"""M4 B-01: the 0005_classroom migration, its constraints and its views.

Covers the schema half of E-60 (server-only key columns), M4-X14 (no duplicate open attempt)
and the `clean_db` question (does TRUNCATE ... users CASCADE also empty the quiz tables?).
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from tests.integration.conftest import M1_TABLES, run_alembic

QUIZ_TABLES = ("quiz", "quiz_questions", "quiz_turns", "quiz_result")
QUIZ_VIEWS = ("quiz_session_status", "quiz_class_items")
SESSION = "11111111-1111-1111-1111-111111111111"


async def _user(conn: AsyncConnection, sub: str = "auth0|stu") -> str:
    row = await conn.execute(
        text("INSERT INTO users (auth0_sub, role) VALUES (:s, 'student') RETURNING id"),
        {"s": sub},
    )
    return str(row.scalar_one())


async def _quiz(
    conn: AsyncConnection,
    user_id: str,
    *,
    status: str = "in_progress",
    attempt: int = 1,
    session: str = SESSION,
) -> str:
    row = await conn.execute(
        text(
            "INSERT INTO quiz (session_id, user_id, attempt_number, status, rubric_version)"
            " VALUES (:s, :u, :a, :st, 'r1') RETURNING id"
        ),
        {"s": session, "u": user_id, "a": attempt, "st": status},
    )
    return str(row.scalar_one())


async def test_tables_and_views_exist(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        tables = {
            r[0]
            for r in await conn.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            )
        }
        views = {
            r[0]
            for r in await conn.execute(
                text("SELECT viewname FROM pg_views WHERE schemaname = 'public'")
            )
        }
    assert set(QUIZ_TABLES) <= tables
    assert set(QUIZ_VIEWS) <= views


def test_head_has_classroom_label_and_upgrade_is_idempotent(engine: AsyncEngine) -> None:
    heads = run_alembic("heads", "--verbose")
    assert heads.returncode == 0, heads.stderr
    assert "0005_classroom" in heads.stdout
    assert "classroom" in heads.stdout
    again = run_alembic("upgrade", "heads")
    assert again.returncode == 0, again.stderr


async def test_foreign_keys_only_reach_users_and_own_tables(engine: AsyncEngine) -> None:
    """PRD 14: no foreign keys across parts except to users.id."""
    sql = text(
        "SELECT c.conrelid::regclass::text, c.confrelid::regclass::text"
        " FROM pg_constraint c WHERE c.contype = 'f' AND c.conrelid::regclass::text = ANY(:t)"
    )
    async with engine.connect() as conn:
        rows = (await conn.execute(sql, {"t": list(QUIZ_TABLES)})).all()
    assert rows, "expected foreign keys on the quiz tables"
    assert {target for _, target in rows} <= {"users", *QUIZ_TABLES}


async def test_session_id_is_a_plain_uuid_column(engine: AsyncEngine) -> None:
    sql = text(
        "SELECT data_type FROM information_schema.columns"
        " WHERE table_name = 'quiz' AND column_name = 'session_id'"
    )
    async with engine.connect() as conn:
        assert (await conn.execute(sql)).scalar_one() == "uuid"


async def test_quiz_status_is_checked(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        uid = await _user(conn)
        for ok in ("assigned", "in_progress", "grading_failed", "done"):
            await _quiz(conn, uid, status=ok)
            await conn.execute(text("DELETE FROM quiz"))
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            uid = await _user(conn, "auth0|other")
            await _quiz(conn, uid, status="cancelled")


async def test_only_one_open_attempt_per_session_and_student(engine: AsyncEngine) -> None:
    """M4-X14: a second open attempt is refused by the schema, a retake after done is fine."""
    async with engine.begin() as conn:
        uid = await _user(conn)
        await _quiz(conn, uid, status="done", attempt=1)
        await _quiz(conn, uid, status="in_progress", attempt=2)
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            uid = str((await conn.execute(text("SELECT id FROM users"))).scalar_one())
            await _quiz(conn, uid, status="assigned", attempt=3)


async def test_attempt_numbers_are_unique_and_positive(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        uid = await _user(conn)
        await _quiz(conn, uid, status="done", attempt=1)
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            uid = str((await conn.execute(text("SELECT id FROM users"))).scalar_one())
            await _quiz(conn, uid, status="done", attempt=1)
    with pytest.raises(IntegrityError):
        async with engine.begin() as conn:
            uid = str((await conn.execute(text("SELECT id FROM users"))).scalar_one())
            await _quiz(conn, uid, status="done", attempt=0)


async def _question(conn: AsyncConnection, quiz_id: str, **cols: object) -> None:
    base = {"q": "q1", "pos": 1, "type": "mcq", "topic": "attack", "prompt": "p"}
    base.update({k: v for k, v in cols.items() if k in base})
    await conn.execute(
        text(
            "INSERT INTO quiz_questions (quiz_id, question_id, position, type, topic, prompt,"
            " options, answer_index, explanation, rubric_items)"
            " VALUES (:quiz, :q, :pos, :type, :topic, :prompt,"
            " CAST(:options AS jsonb), :ai, :ex, CAST(:ri AS jsonb))"
        ),
        {
            **base,
            "quiz": quiz_id,
            "options": json.dumps(cols.get("options")) if cols.get("options") else None,
            "ai": cols.get("answer_index"),
            "ex": cols.get("explanation"),
            "ri": json.dumps(cols.get("rubric_items")) if cols.get("rubric_items") else None,
        },
    )


async def test_question_shape_is_checked_per_type(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        qid = await _quiz(conn, await _user(conn))
        await _question(conn, qid, options=["a", "b", "c"], answer_index=1, explanation="e")
        await _question(
            conn,
            qid,
            q="q6",
            pos=6,
            type="free_response",
            topic="why",
            rubric_items=["why"],
        )
    bad_cases = [
        {"options": ["a", "b", "c"], "explanation": "e"},  # mcq without answer_index
        {"options": ["a", "b", "c"], "answer_index": 3, "explanation": "e"},  # out of range
        {"answer_index": 0, "explanation": "e"},  # mcq without options
        {"type": "free_response", "answer_index": 0, "rubric_items": ["why"]},  # key on FR
        {"type": "free_response"},  # FR without rubric items
        {"type": "essay", "options": ["a", "b", "c"], "answer_index": 0, "explanation": "e"},
    ]
    for n, case in enumerate(bad_cases):
        with pytest.raises(IntegrityError):
            async with engine.begin() as conn:
                qid = await _quiz(conn, await _user(conn, f"auth0|bad{n}"), session=SESSION)
                await _question(conn, qid, q=f"q{n}", **case)  # type: ignore[arg-type]


async def test_result_ranges_are_checked(engine: AsyncEngine) -> None:
    insert = text(
        "INSERT INTO quiz_result (quiz_id, rubric_version, mcq_points, item_scores,"
        " total_points, percent, feedback) VALUES (:q, 'r1', :m, '{}', :t, :p, 'ok')"
    )
    async with engine.begin() as conn:
        qid = await _quiz(conn, await _user(conn), status="done")
        await conn.execute(insert, {"q": qid, "m": 5, "t": 17, "p": 100})
    for m, t, p in ((6, 17, 100), (5, 18, 100), (5, 17, 101), (-1, 0, 0)):
        with pytest.raises(IntegrityError):
            async with engine.begin() as conn:
                uid = await _user(conn, f"auth0|r{m}{t}{p}")
                qid = await _quiz(conn, uid, status="done", session=SESSION)
                await conn.execute(insert, {"q": qid, "m": m, "t": t, "p": p})


async def test_views_report_latest_and_best(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        uid = await _user(conn)
        first = await _quiz(conn, uid, status="done", attempt=1)
        second = await _quiz(conn, uid, status="done", attempt=2)
        await _quiz(conn, uid, status="in_progress", attempt=3)
        for qid, pct, scores in (
            (first, 90, {"attack": 3, "why": 3, "defense_layer": 3, "prevention": 3}),
            (second, 40, {"attack": 1, "why": 1, "defense_layer": 0, "prevention": 2}),
        ):
            await conn.execute(
                text(
                    "INSERT INTO quiz_result (quiz_id, rubric_version, mcq_points, item_scores,"
                    " total_points, percent, feedback)"
                    " VALUES (:q, 'r1', 1, CAST(:s AS jsonb), 5, :p, 'f')"
                ),
                {"q": qid, "s": json.dumps(scores), "p": pct},
            )
        row = (
            (
                await conn.execute(
                    text(
                        "SELECT latest_status, latest_percent, best_percent, attempts"
                        " FROM quiz_session_status WHERE session_id = :s AND user_id = :u"
                    ),
                    {"s": SESSION, "u": uid},
                )
            )
            .mappings()
            .one()
        )
        assert row["latest_status"] == "in_progress"
        assert row["latest_percent"] is None  # the open attempt has no score yet
        assert row["best_percent"] == 90
        assert row["attempts"] == 3
        items = {
            r["item"]: r["avg_score"]
            for r in (await conn.execute(text("SELECT item, avg_score FROM quiz_class_items")))
            .mappings()
            .all()
        }
    # Items average the latest *done* attempt only (the 40% retake), not the best.
    assert float(items["defense_layer"]) == 0.0
    assert float(items["prevention"]) == 2.0


async def test_clean_db_truncate_also_clears_the_quiz_tables(engine: AsyncEngine) -> None:
    """The conftest TRUNCATE lists only M1 tables; CASCADE must reach ours through users."""
    async with engine.begin() as conn:
        qid = await _quiz(conn, await _user(conn))
        await _question(conn, qid, options=["a", "b", "c"], answer_index=0, explanation="e")
        await conn.execute(
            text(
                "INSERT INTO quiz_turns (quiz_id, question_id, seq, role, text)"
                " SELECT :q, 'q1', 1, 'student', 'hi'"
            ),
            {"q": qid},
        )
    async with engine.begin() as conn:
        await conn.execute(text(f"TRUNCATE {', '.join(M1_TABLES)} RESTART IDENTITY CASCADE"))
        counts = [
            (await conn.execute(text(f"SELECT count(*) FROM {t}"))).scalar_one()  # noqa: S608
            for t in QUIZ_TABLES
        ]
    assert counts == [0, 0, 0, 0]


def test_downgrade_removes_everything_and_upgrade_restores_it(engine: AsyncEngine) -> None:
    down = run_alembic("downgrade", "classroom@base")
    try:
        assert down.returncode == 0, down.stderr
    finally:
        up = run_alembic("upgrade", "heads")
    assert up.returncode == 0, up.stderr
