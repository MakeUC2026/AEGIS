"""M4 C2: quiz model runtime wiring."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.config import Settings
from app.quiz.llm import build_runtime
from tests.m4_support import KEYS, PROXY_SECRET


def _settings(**extra: str) -> Settings:
    return Settings(
        _env_file=None,
        APP_ENV="test",
        AEGIS_AUTH_MODE="dev",
        AEGIS_DEV_JWT_PUBLIC_KEY=KEYS.public_pem,
        AEGIS_PROXY_SECRET=PROXY_SECRET,
        DATABASE_URL="unused",
        **extra,
    )


def test_unconfigured_models_give_a_clear_503() -> None:
    with pytest.raises(HTTPException) as err:
        build_runtime(_settings(), engine=None)
    assert err.value.status_code == 503


def test_configured_models_build_a_runtime() -> None:
    rt = build_runtime(
        _settings(
            GEMINI_API_KEY="k",
            AEGIS_GEMINI_PRO_MODEL_ID="pro-x",
            AEGIS_GEMINI_FLASH_MODEL_ID="flash-x",
        ),
        engine=None,
    )
    assert (rt.pro_model, rt.flash_model) == ("pro-x", "flash-x")
