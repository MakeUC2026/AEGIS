"""B-05: the C7 factories resolve through `ports.py` with `risky` and `judge` not faked.

Settings are built without reading `.env` (synthetic values only, I-5).
"""

from __future__ import annotations

import hashlib
import pathlib
from collections.abc import Iterator

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from app import config
from app.config import Settings
from app.contracts.sentinel import JudgePort, RiskyHistoryPort
from app.db import engine as db_engine
from app.firewall import judge, ports, risky_history

FLASH = "gemini-flash-test-pin"


def _settings(**overrides: str) -> Settings:
    values = {
        "GEMINI_API_KEY": "test-key-not-real",
        "AEGIS_GEMINI_FLASH_MODEL_ID": FLASH,
        "AEGIS_GEMINI_EMBEDDING_MODEL_ID": "embedding-test-pin",
        **overrides,
    }
    return Settings(_env_file=None, **values)  # type: ignore[call-arg]


@pytest.fixture
def wired(monkeypatch: pytest.MonkeyPatch) -> Iterator[pytest.MonkeyPatch]:
    fake_engine = create_async_engine("postgresql+asyncpg://u:p@127.0.0.1:1/none")
    monkeypatch.setattr(config, "get_settings", _settings)
    monkeypatch.setattr(db_engine, "get_engine", lambda: fake_engine)
    monkeypatch.setenv("AEGIS_USE_FAKES", "firewall,read,admin,arena")
    ports.reset()
    yield monkeypatch
    ports.reset()


def test_risky_and_judge_resolve_to_real_implementations(wired: pytest.MonkeyPatch) -> None:
    risky = ports.get_risky_history()
    jdg = ports.get_judge()
    assert isinstance(risky, risky_history.RiskyHistory)
    assert isinstance(risky, RiskyHistoryPort)
    assert isinstance(jdg, judge.Judge)
    assert isinstance(jdg, JudgePort)
    assert jdg.model_id() == FLASH  # read from settings, not hard-coded (A-16 pin)


def test_judge_needs_a_pinned_flash_model(wired: pytest.MonkeyPatch) -> None:
    wired.setattr(config, "get_settings", lambda: _settings(AEGIS_GEMINI_FLASH_MODEL_ID=""))
    with pytest.raises(RuntimeError, match="AEGIS_GEMINI_FLASH_MODEL_ID"):
        judge.create()


def test_risky_needs_a_pinned_embedding_model(wired: pytest.MonkeyPatch) -> None:
    wired.setattr(config, "get_settings", lambda: _settings(AEGIS_GEMINI_EMBEDDING_MODEL_ID=""))
    with pytest.raises(RuntimeError, match="AEGIS_GEMINI_EMBEDDING_MODEL_ID"):
        risky_history.create()


@pytest.mark.parametrize("factory", [judge.create, risky_history.create])
def test_factories_refuse_a_missing_api_key(wired: pytest.MonkeyPatch, factory: object) -> None:
    wired.setattr(config, "get_settings", lambda: _settings(GEMINI_API_KEY=""))
    with pytest.raises(ValueError, match="GEMINI_API_KEY"):
        factory()  # type: ignore[operator]


def test_policy_path_env_override(wired: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
    policy = tmp_path / "judge-policy.md"
    policy.write_text("synthetic policy for the test\n")
    wired.setenv("AEGIS_POLICY_PATH", str(policy))
    expected = "sha256:" + hashlib.sha256(policy.read_bytes()).hexdigest()
    assert judge.create().policy_hash() == expected


def test_default_policy_file_is_the_repo_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AEGIS_POLICY_PATH", raising=False)
    assert judge.policy_path() == judge.POLICY_PATH
    assert judge.POLICY_PATH.is_file()
