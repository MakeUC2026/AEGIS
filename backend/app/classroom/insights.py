"""Class insights (PRD 12.3), teachers only. AFF numbers come from C3 (M2's 1-minute
aggregates), session numbers from C4, quiz numbers from M4's views."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.classroom.schemas import (
    DecisionCountRow,
    DefenseActivity,
    FamilyRow,
    InsightQuery,
    Insights,
    ItemAverage,
    LevelOutcome,
    Overview,
    PatternRow,
    QuizPanel,
    RuleCountRow,
)
from app.contracts.arena import ArenaServicePort, ArenaSession, SessionFilters
from app.contracts.firewall_read import FirewallReadPort, InsightFilters
from app.quiz import rubric

TOP_N = 10
ACTIVE_WINDOW = timedelta(hours=24)
_PANEL_SQL = text(
    "SELECT count(*) FILTER (WHERE latest_status = 'done')::int,"
    " count(*) FILTER (WHERE latest_status <> 'done')::int,"
    " round(avg(latest_percent) FILTER (WHERE latest_status = 'done'))::int"
    " FROM quiz_session_status"
)
_ITEMS_SQL = text("SELECT item, avg_score, n FROM quiz_class_items")
_TITLES = {i.key: i.title for i in rubric.RUBRIC}


def _overview(sessions: list[ArenaSession]) -> Overview:
    students = {s.user_id for s in sessions}
    cutoff = datetime.now(UTC) - ACTIVE_WINDOW
    active = {s.user_id for s in sessions if s.started_at >= cutoff}
    return Overview(
        students=len(students),
        sessions=len(sessions),
        sessions_per_student=round(len(sessions) / len(students), 2) if students else 0.0,
        active_today=len(active),
    )


async def _quiz_panel(engine: AsyncEngine) -> QuizPanel:
    async with engine.connect() as conn:
        taken, open_, avg = (await conn.execute(_PANEL_SQL)).one()
        items = (await conn.execute(_ITEMS_SQL)).all()
    ranked = sorted(items, key=lambda r: (float(r[1]), r[0]))
    return QuizPanel(
        taken=taken,
        open=open_,
        average_percent=avg,
        lowest_items=[
            ItemAverage(
                item=r[0], title=_TITLES.get(r[0], r[0]), average=round(float(r[1]), 2), n=r[2]
            )
            for r in ranked
        ],
    )


async def insights_view(
    q: InsightQuery, *, engine: AsyncEngine, arena: ArenaServicePort, read: FirewallReadPort
) -> Insights:
    c3 = InsightFilters(level_id=q.level, mode=q.mode, include_admin_test=q.include_admin_test)
    sessions_task = arena.list_sessions(
        SessionFilters(
            level_id=q.level,
            mode=q.mode,
            admin_test=None if q.include_admin_test else False,
            limit=1000,
        )
    )
    sessions, levels, rules, decisions, families, patterns, quiz = await asyncio.gather(
        sessions_task,
        arena.list_levels(),
        read.get_rule_fire_counts(c3),
        read.get_decision_counts(c3),
        read.get_attack_family_counts(c3),
        read.get_risky_pattern_counts(c3),
        _quiz_panel(engine),
    )
    outcomes = []
    for lv in levels:
        if q.level and lv.level_id != q.level:
            continue
        mine = [s for s in sessions if s.level_id == lv.level_id]
        got = sum(1 for s in mine if s.secret_obtained_at is not None)
        outcomes.append(
            LevelOutcome(
                level_id=lv.level_id,
                level_name=lv.name,
                sessions=len(mine),
                obtained=got,
                not_obtained=len(mine) - got,
                rate=round(got / len(mine), 2) if mine else 0.0,
            )
        )
    return Insights(
        overview=_overview(sessions),
        outcomes=outcomes,
        defense=DefenseActivity(
            top_rules=[
                RuleCountRow(rule_id=r.rule_id, count=r.count)
                for r in sorted(rules, key=lambda r: (-r.count, r.rule_id))[:TOP_N]
            ],
            decisions=[
                DecisionCountRow(mode=d.mode, decision=d.decision, count=d.count) for d in decisions
            ],
            divert_count=sum(d.count for d in decisions if d.decision == "divert"),
        ),
        attack_families=[
            FamilyRow(attack_family=f.attack_family, count=f.count)
            for f in sorted(families, key=lambda f: (-f.count, f.attack_family))
        ],
        risky_patterns=[
            PatternRow(pattern_id=p.pattern_id, count=p.count)
            for p in sorted(patterns, key=lambda p: (-p.count, p.pattern_id))[:TOP_N]
        ],
        quiz=quiz,
    )
