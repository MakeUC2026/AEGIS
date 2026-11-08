"""Pure auth helpers, with Hypothesis fuzzing of untrusted inputs (master prompt: fuzzing)."""

from __future__ import annotations

import ipaddress

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.auth.claims import ROLES_CLAIM, primary_role, roles_from_claims
from app.auth.proxy import parse_fingerprint, parse_forwarded_for
from app.config import Settings
from app.contracts.common import ROLES


def test_no_roles_claim_is_student() -> None:
    assert roles_from_claims({}) == frozenset({"student"})
    assert roles_from_claims({ROLES_CLAIM: "teacher"}) == frozenset({"student"})  # not a list


def test_known_roles_kept() -> None:
    claims = {ROLES_CLAIM: ["teacher", "firewall_admin"]}
    assert roles_from_claims(claims) == frozenset({"teacher", "firewall_admin"})
    assert primary_role(roles_from_claims(claims)) == "firewall_admin"


json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(),
    lambda children: st.lists(children) | st.dictionaries(st.text(), children),
    max_leaves=20,
)


@given(st.dictionaries(st.text(), json_values) | st.fixed_dictionaries({ROLES_CLAIM: json_values}))
def test_roles_from_arbitrary_claims_never_raise(claims: dict) -> None:
    roles = roles_from_claims(claims)
    assert roles and roles <= ROLES


@given(st.text())
def test_forwarded_for_fuzz(value: str) -> None:
    ip = parse_forwarded_for(value)
    if ip is not None:
        ipaddress.ip_address(ip)


def test_forwarded_for_takes_first_valid_hop() -> None:
    assert parse_forwarded_for("2001:db8::1, 10.0.0.1") == "2001:db8::1"
    assert parse_forwarded_for("") is None
    assert parse_forwarded_for(None) is None


@given(st.text())
def test_fingerprint_fuzz(value: str) -> None:
    parsed = parse_fingerprint(value)
    assert parsed is None or (len(parsed) == 64 and int(parsed, 16) >= 0)


def test_dev_public_key_escaped_newlines_are_normalised() -> None:
    # .env stores PEMs on one line with "\n" escapes; shells keep them literal.
    pem = "-----BEGIN PUBLIC KEY-----\\nABC\\n-----END PUBLIC KEY-----"
    settings = Settings(_env_file=None, AEGIS_AUTH_MODE="dev", AEGIS_DEV_JWT_PUBLIC_KEY=pem)
    assert settings.dev_jwt_public_key == (
        "-----BEGIN PUBLIC KEY-----\nABC\n-----END PUBLIC KEY-----"
    )


def test_dev_auth_refused_in_production() -> None:
    with pytest.raises(ValueError, match="not allowed in production"):
        Settings(
            _env_file=None,
            APP_ENV="production",
            AEGIS_AUTH_MODE="dev",
            AEGIS_DEV_JWT_PUBLIC_KEY="x",
            AEGIS_PROXY_SECRET="p" * 40,
            AUTH0_DOMAIN="t.example",
            AUTH0_AUDIENCE="a",
        )


def test_short_proxy_secret_refused_in_production() -> None:
    with pytest.raises(ValueError, match="AEGIS_PROXY_SECRET"):
        Settings(
            _env_file=None,
            APP_ENV="production",
            AEGIS_PROXY_SECRET="short",
            AUTH0_DOMAIN="t.example",
            AUTH0_AUDIENCE="a",
        )


def test_migration_url_prefers_env_then_falls_back_to_dotenv_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # `uv run alembic upgrade heads` must work with only a .env file (onboarding step).
    from app.db import engine as db_engine

    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://from-env/db")
    assert db_engine.migration_url() == "postgresql+asyncpg://from-env/db"

    monkeypatch.delenv("DATABASE_URL")
    from_dotenv = Settings(_env_file=None, DATABASE_URL="postgresql+asyncpg://from-dotenv/db")
    monkeypatch.setattr(db_engine, "get_settings", lambda: from_dotenv)
    assert db_engine.migration_url() == "postgresql+asyncpg://from-dotenv/db"

    empty = Settings(_env_file=None)
    monkeypatch.setattr(db_engine, "get_settings", lambda: empty)
    with pytest.raises(RuntimeError, match="DATABASE_URL"):
        db_engine.migration_url()
