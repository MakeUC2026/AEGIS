"""Classroom tables (M4 B-01): quiz, quiz_questions, quiz_turns, quiz_result, plus two views.

Foreign keys reach only users.id and this part's own tables (PRD 14, M4 section 0.2 rule 5).
The arena session id is a plain uuid. `answer_index` and `explanation` on quiz_questions and
`answer_key` on quiz are server-only; no route may select them before the student answers (E-60).

Revision ID: 0005_classroom
Revises: 0001_foundation
"""

from __future__ import annotations

from alembic import op

revision = "0005_classroom"
down_revision = "0001_foundation"
branch_labels = ("classroom",)
depends_on = None

_TABLES = (
    """
    CREATE TABLE quiz (
        id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        session_id      uuid NOT NULL,
        user_id         uuid NOT NULL REFERENCES users (id),
        attempt_number  int NOT NULL CHECK (attempt_number >= 1),
        status          text NOT NULL CHECK (status IN
                        ('assigned', 'in_progress', 'grading_failed', 'done')),
        rubric_version  text NOT NULL,
        assigned_by     uuid REFERENCES users (id),
        answer_key      jsonb,
        created_at      timestamptz NOT NULL DEFAULT now(),
        started_at      timestamptz,
        finished_at     timestamptz,
        UNIQUE (session_id, user_id, attempt_number)
    )
    """,
    """
    CREATE TABLE quiz_questions (
        quiz_id        uuid NOT NULL REFERENCES quiz (id) ON DELETE CASCADE,
        question_id    text NOT NULL,
        position       int NOT NULL CHECK (position >= 1),
        type           text NOT NULL CHECK (type IN ('mcq', 'free_response')),
        topic          text NOT NULL,
        prompt         text NOT NULL,
        options        jsonb,
        max_follow_ups int,
        rubric_items   jsonb,
        answer_index   int,
        explanation    text,
        chosen_index   int,
        answered_at    timestamptz,
        PRIMARY KEY (quiz_id, question_id),
        CONSTRAINT quiz_questions_mcq_shape CHECK (
            type <> 'mcq' OR (
                options IS NOT NULL AND jsonb_typeof(options) = 'array'
                AND answer_index IS NOT NULL AND explanation IS NOT NULL
                AND answer_index >= 0 AND answer_index < jsonb_array_length(options)
                AND (chosen_index IS NULL
                     OR (chosen_index >= 0 AND chosen_index < jsonb_array_length(options)))
            )
        ),
        CONSTRAINT quiz_questions_free_shape CHECK (
            type <> 'free_response' OR (
                rubric_items IS NOT NULL AND options IS NULL AND answer_index IS NULL
                AND explanation IS NULL AND chosen_index IS NULL
            )
        )
    )
    """,
    """
    CREATE TABLE quiz_turns (
        quiz_id      uuid NOT NULL,
        question_id  text NOT NULL,
        seq          int NOT NULL CHECK (seq >= 1),
        role         text NOT NULL CHECK (role IN ('student', 'classmate')),
        text         text NOT NULL,
        created_at   timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY (quiz_id, question_id, seq),
        FOREIGN KEY (quiz_id, question_id)
            REFERENCES quiz_questions (quiz_id, question_id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE quiz_result (
        quiz_id         uuid PRIMARY KEY REFERENCES quiz (id) ON DELETE CASCADE,
        rubric_version  text NOT NULL,
        mcq_points      int NOT NULL CHECK (mcq_points BETWEEN 0 AND 5),
        item_scores     jsonb NOT NULL,
        total_points    int NOT NULL CHECK (total_points BETWEEN 0 AND 17),
        percent         int NOT NULL CHECK (percent BETWEEN 0 AND 100),
        feedback        text NOT NULL,
        graded_at       timestamptz NOT NULL DEFAULT now()
    )
    """,
)

_INDEXES = (
    # M4-X14: at most one open attempt per student and session; retakes only after done.
    "CREATE UNIQUE INDEX quiz_one_open_attempt_idx ON quiz (session_id, user_id)"
    " WHERE status <> 'done'",
    "CREATE INDEX quiz_user_idx ON quiz (user_id, created_at DESC)",
    "CREATE INDEX quiz_session_idx ON quiz (session_id)",
)

_VIEWS = (
    # One row per (session, student): latest attempt's status and score, best score, count.
    """
    CREATE VIEW quiz_session_status AS
    SELECT l.session_id, l.user_id, l.status AS latest_status, r.percent AS latest_percent,
           agg.best_percent, agg.attempts, l.assigned_by
    FROM (
        SELECT DISTINCT ON (session_id, user_id) *
        FROM quiz ORDER BY session_id, user_id, attempt_number DESC
    ) l
    LEFT JOIN quiz_result r ON r.quiz_id = l.id
    JOIN (
        SELECT q.session_id, q.user_id, count(*)::int AS attempts, max(qr.percent) AS best_percent
        FROM quiz q LEFT JOIN quiz_result qr ON qr.quiz_id = q.id
        GROUP BY q.session_id, q.user_id
    ) agg ON agg.session_id = l.session_id AND agg.user_id = l.user_id
    """,
    # Class insights: average per rubric item over each student's latest done attempt.
    """
    CREATE VIEW quiz_class_items AS
    SELECT s.key AS item, avg(s.value::numeric) AS avg_score, count(*)::int AS n
    FROM (
        SELECT DISTINCT ON (session_id, user_id) id
        FROM quiz WHERE status = 'done' ORDER BY session_id, user_id, attempt_number DESC
    ) latest
    JOIN quiz_result r ON r.quiz_id = latest.id
    CROSS JOIN LATERAL jsonb_each_text(r.item_scores) AS s
    GROUP BY s.key
    """,
)


def upgrade() -> None:
    for ddl in (*_TABLES, *_INDEXES, *_VIEWS):
        op.execute(ddl)


def downgrade() -> None:
    for view in ("quiz_class_items", "quiz_session_status"):
        op.execute(f"DROP VIEW IF EXISTS {view}")
    for table in ("quiz_result", "quiz_turns", "quiz_questions", "quiz"):
        op.execute(f"DROP TABLE IF EXISTS {table}")
