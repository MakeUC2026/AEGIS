"""M2 B-04 register_session (spec AEGIS-DOM-108; PRD §15.1 reproducibility, E-57 groundwork).

Requests are built from M1's real scenario and level seed, exactly what the arena sends.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.arena.scenario_data import SYSTEM_PROMPT, TOOLS
from app.arena.seed import BASIC_THRESHOLDS, DEFAULT_WEIGHTS, STRICT_THRESHOLDS, build_mock_state
from app.contracts.fakes import InMemoryRiskyHistory, StubJudge
from app.contracts.firewall import AgentDefinition, LevelConfig, RegisterSession, ToolDef
from app.firewall.seed import seed
from app.firewall.sessions import register_session

SECRET = "CONF-K3Q9ZP7X2M4TLW8D5RHV6BNA"


async def _user(engine: AsyncEngine) -> str:
    async with engine.begin() as conn:
        row = await conn.execute(
            text("INSERT INTO users (auth0_sub, role) VALUES ('auth0|reg', 'student') RETURNING id")
        )
        return str(row.scalar_one())


def _request(owner: str, mode: str = "basic", **level: Any) -> RegisterSession:
    thresholds = STRICT_THRESHOLDS if mode != "basic" else BASIC_THRESHOLDS
    config: dict[str, Any] = {
        "level_id": "lvl-2",
        "level_version": 1,
        "mode": mode,
        "rule_version": 0,
        "weights": DEFAULT_WEIGHTS,
        "thresholds": thresholds,
        "review_timeout_s": 120,
        "divert_enabled": mode != "off",
        **level,
    }
    return RegisterSession(
        owner_ref=owner,
        agent=AgentDefinition(
            system_prompt=SYSTEM_PROMPT,
            tools=[
                ToolDef(name=t["name"], json_schema=t["json_schema"], high_risk=t["high_risk"])
                for t in TOOLS
            ],
            model_id="gemini-bot-test",
        ),
        level=LevelConfig(**config),
        secret=SECRET,
        mock_state_seed=build_mock_state("lvl-2", SECRET),
    )


async def _row(engine: AsyncEngine, sql: str, **params: Any) -> dict[str, Any]:
    async with engine.connect() as conn:
        row = (await conn.execute(text(sql), params)).first()
    assert row is not None
    return dict(row._mapping)


def _json(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


class _History(InMemoryRiskyHistory):
    """M1's fake with a non-default pattern version, to prove it is read (not assumed)."""

    async def current_pattern_version(self) -> int:
        return 3


async def _register(engine: AsyncEngine, req: RegisterSession) -> Any:
    return await register_session(engine, req, risky=_History(), judge=StubJudge())


async def test_register_writes_session_manifest_and_mock_state(engine: AsyncEngine) -> None:
    await seed(engine)
    owner = await _user(engine)
    handle = await _register(engine, _request(owner))
    assert handle.fw_session_id.startswith("fws-") and handle.manifest_id.startswith("man-")

    session = await _row(engine, "SELECT * FROM fw_sessions WHERE fw_session_id = :s",
                         s=handle.fw_session_id)  # fmt: skip
    assert (str(session["owner_ref"]), session["mode"], session["secret"], session["status"]) == (
        owner, "basic", SECRET, "active",
    )  # fmt: skip

    manifest = await _row(engine, "SELECT * FROM fw_manifests WHERE manifest_id = :m",
                          m=handle.manifest_id)  # fmt: skip
    assert manifest["fw_session_id"] == handle.fw_session_id
    assert (manifest["rule_set_version"], manifest["pattern_version"]) == (1, 3)
    assert _json(manifest["thresholds"]) == BASIC_THRESHOLDS
    assert _json(manifest["weights"]) == DEFAULT_WEIGHTS
    assert manifest["bot_model_id"] == "gemini-bot-test"
    assert _json(manifest["agent"])["system_prompt"] == SYSTEM_PROMPT
    assert manifest["judge_model_id"] is None  # Basic never calls the judge

    state = await _row(engine, "SELECT * FROM fw_mock_state WHERE fw_session_id = :s",
                       s=handle.fw_session_id)  # fmt: skip
    seed_state = build_mock_state("lvl-2", SECRET)
    assert state["attacker_mailbox"] == seed_state.attacker_mailbox
    assert list(state["allowlist_domains"]) == seed_state.allowlist_domains
    assert _json(state["filesystem"]) == seed_state.filesystem


async def test_strict_manifest_records_the_judge(engine: AsyncEngine) -> None:
    await seed(engine)
    handle = await _register(engine, _request(await _user(engine), mode="strict"))
    manifest = await _row(engine, "SELECT * FROM fw_manifests WHERE manifest_id = :m",
                          m=handle.manifest_id)  # fmt: skip
    judge = StubJudge()
    assert (manifest["judge_model_id"], manifest["judge_policy_hash"]) == (
        judge.model_id(), judge.policy_hash(),
    )  # fmt: skip


async def test_rule_version_zero_pins_the_latest_set(engine: AsyncEngine) -> None:
    await seed(engine)
    async with engine.begin() as conn:
        await conn.execute(text("INSERT INTO rule_sets (version, note) VALUES (2, 'draft rule')"))
    owner = await _user(engine)
    latest = await _register(engine, _request(owner))
    pinned = await _register(engine, _request(owner, rule_version=1))
    versions = {}
    for handle in (latest, pinned):
        row = await _row(engine, "SELECT rule_set_version FROM fw_manifests WHERE manifest_id = :m",
                         m=handle.manifest_id)  # fmt: skip
        versions[handle.manifest_id] = row["rule_set_version"]
    assert (versions[latest.manifest_id], versions[pinned.manifest_id]) == (2, 1)


async def test_unknown_rule_version_is_rejected(engine: AsyncEngine) -> None:
    await seed(engine)
    with pytest.raises(ValueError, match="rule set"):
        await _register(engine, _request(await _user(engine), rule_version=9))


async def test_no_rule_set_at_all_fails_closed(engine: AsyncEngine) -> None:
    with pytest.raises(ValueError, match="rule set"):
        await _register(engine, _request(await _user(engine)))


@pytest.mark.parametrize(
    "level",
    [
        {"thresholds": {"review": 40, "deny": 70, "divert": 95}},  # no alert
        {"thresholds": {"review": 70, "deny": 40, "divert": 95, "alert": 99}},  # out of order
        {"weights": {k: v for k, v in DEFAULT_WEIGHTS.items() if k != "encoding"}},
    ],
)
async def test_invalid_level_config_writes_nothing(
    engine: AsyncEngine, level: dict[str, Any]
) -> None:
    await seed(engine)
    with pytest.raises(ValueError):
        await _register(engine, _request(await _user(engine), **level))
    async with engine.connect() as conn:
        sessions = (await conn.execute(text("SELECT count(*) FROM fw_sessions"))).scalar_one()
    assert sessions == 0
