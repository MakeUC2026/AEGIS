"""Session registration and the immutable manifest (M2 B-04; PRD §15.1; spec AEGIS-DOM-108).

`register_session` validates the level config (M2-DD-05), pins the rule set version (the
level's `rule_version`, or the latest rule set when it is 0, so newly approved rules reach
new sessions only, E-57), reads the risky pattern table version, records the judge's model
and policy hash in Strict, then writes the session, its manifest and its mock state in one
transaction. The manifest is immutable (database trigger), so a session replays exactly.
"""

from __future__ import annotations

import json
import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.contracts.firewall import LevelConfig, RegisterSession, SessionHandle
from app.contracts.sentinel import JudgePort, RiskyHistoryPort

SESSION_PREFIX = "fws-"
MANIFEST_PREFIX = "man-"
THRESHOLD_ORDER: tuple[str, ...] = ("review", "deny", "divert", "alert")
REQUIRED_WEIGHTS: frozenset[str] = frozenset(
    {
        "keyword_per_hit",
        "keyword_max",
        "encoding",
        "session_deny_per",
        "session_deny_max",
        "rapid_retries",
        "high_risk_tool",
        "untrusted_context",
        "user_tool_event_per",
        "user_tool_event_max",
        "prior_divert",
        "similarity_high",
        "similarity_mid",
    }
)
SCORE_MAX = 100

_LATEST_SET = "SELECT max(version) FROM rule_sets"
_SET_EXISTS = "SELECT count(*) FROM rule_sets WHERE version = :v"
_INSERT_SESSION = (
    "INSERT INTO fw_sessions (fw_session_id, owner_ref, mode, secret, eval)"
    " VALUES (:sid, CAST(:owner AS uuid), :mode, :secret, :eval)"
)
_INSERT_MANIFEST = (
    "INSERT INTO fw_manifests (manifest_id, fw_session_id, owner_ref, level_id, level_version,"
    " mode, rule_set_version, pattern_version, thresholds, weights, agent, bot_model_id,"
    " judge_model_id, judge_policy_hash, review_timeout_s, divert_enabled)"
    " VALUES (:mid, :sid, CAST(:owner AS uuid), :level_id, :level_version, :mode, :rule_set,"
    " :pattern_version, CAST(:thresholds AS jsonb), CAST(:weights AS jsonb),"
    " CAST(:agent AS jsonb), :bot_model_id, :judge_model_id, :judge_policy_hash,"
    " :review_timeout_s, :divert_enabled)"
)
_INSERT_MOCK_STATE = (
    "INSERT INTO fw_mock_state (fw_session_id, documents, emails, db_rows, filesystem,"
    " attacker_mailbox, allowlist_domains) VALUES (:sid, CAST(:documents AS jsonb),"
    " CAST(:emails AS jsonb), CAST(:db_rows AS jsonb), CAST(:filesystem AS jsonb),"
    " :attacker_mailbox, :allowlist_domains)"
)


def validate_level(level: LevelConfig) -> None:
    """Fail closed: a level that cannot be scored must not start (M2-DD-05)."""
    missing = [k for k in THRESHOLD_ORDER if k not in level.thresholds]
    if missing:
        raise ValueError(f"level thresholds missing {missing}")
    values = [level.thresholds[k] for k in THRESHOLD_ORDER]
    ordered = values[0] < values[1] < values[2] <= values[3]
    if not ordered or values[0] < 0 or values[3] > SCORE_MAX:
        raise ValueError(
            "level thresholds must satisfy 0 <= review < deny < divert <= alert <= 100"
        )
    absent = sorted(REQUIRED_WEIGHTS - set(level.weights))
    if absent:
        raise ValueError(f"level weights missing {absent}")


async def _pin_rule_set(conn: AsyncConnection, requested: int) -> int:
    if requested == 0:
        latest = (await conn.execute(text(_LATEST_SET))).scalar_one()
        if latest is None:
            raise ValueError("no rule set has been seeded; refusing to start a session")
        return int(latest)
    found = (await conn.execute(text(_SET_EXISTS), {"v": requested})).scalar_one()
    if not found:
        raise ValueError(f"rule set version {requested} does not exist")
    return requested


async def register_session(
    engine: AsyncEngine, req: RegisterSession, risky: RiskyHistoryPort, judge: JudgePort
) -> SessionHandle:
    level = req.level
    validate_level(level)
    pattern_version = await risky.current_pattern_version()
    strict = level.mode == "strict"
    sid = SESSION_PREFIX + uuid.uuid4().hex
    mid = MANIFEST_PREFIX + uuid.uuid4().hex
    seed = req.mock_state_seed
    async with engine.begin() as conn:
        rule_set = await _pin_rule_set(conn, level.rule_version)
        await conn.execute(
            text(_INSERT_SESSION),
            {"sid": sid, "owner": req.owner_ref, "mode": level.mode, "secret": req.secret,
             "eval": req.eval},
        )  # fmt: skip
        await conn.execute(
            text(_INSERT_MANIFEST),
            {
                "mid": mid,
                "sid": sid,
                "owner": req.owner_ref,
                "level_id": level.level_id,
                "level_version": level.level_version,
                "mode": level.mode,
                "rule_set": rule_set,
                "pattern_version": pattern_version,
                "thresholds": json.dumps(level.thresholds),
                "weights": json.dumps(level.weights),
                "agent": json.dumps(req.agent.model_dump(mode="json")),
                "bot_model_id": req.agent.model_id,
                "judge_model_id": judge.model_id() if strict else None,
                "judge_policy_hash": judge.policy_hash() if strict else None,
                "review_timeout_s": level.review_timeout_s,
                "divert_enabled": level.divert_enabled,
            },
        )
        await conn.execute(
            text(_INSERT_MOCK_STATE),
            {
                "sid": sid,
                "documents": json.dumps([d.model_dump(mode="json") for d in seed.documents]),
                "emails": json.dumps([e.model_dump(mode="json") for e in seed.emails]),
                "db_rows": json.dumps(seed.db_rows),
                "filesystem": json.dumps(seed.filesystem),
                "attacker_mailbox": seed.attacker_mailbox,
                "allowlist_domains": list(seed.allowlist_domains),
            },
        )
    return SessionHandle(fw_session_id=sid, manifest_id=mid)
