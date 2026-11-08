"""Shared test helper (M1 C5 `make_token`): mint dev-mode tokens for any machine's tests.

Keys are generated in memory per test run; nothing here is a real credential.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.auth.claims import EMAIL_CLAIM, NAME_CLAIM, ROLES_CLAIM

DEV_ISSUER = "aegis-dev"
DEV_AUDIENCE = "aegis-dev-api"
RSA_KEY_BITS = 2048
DEFAULT_TTL_S = 3600


@dataclass(frozen=True)
class DevKeys:
    private_pem: str
    public_pem: str


def make_keys() -> DevKeys:
    key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_BITS)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return DevKeys(private_pem=private_pem, public_pem=public_pem)


def make_token(
    keys: DevKeys,
    *,
    sub: str,
    roles: list[str] | None = None,
    name: str | None = None,
    email: str | None = None,
    issuer: str = DEV_ISSUER,
    audience: str = DEV_AUDIENCE,
    expires_in: int = DEFAULT_TTL_S,
) -> str:
    now = int(time.time())
    claims: dict[str, object] = {
        "sub": sub,
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + expires_in,
    }
    if roles is not None:
        claims[ROLES_CLAIM] = roles
    if name is not None:
        claims[NAME_CLAIM] = name
    if email is not None:
        claims[EMAIL_CLAIM] = email
    return jwt.encode(claims, keys.private_pem, algorithm="RS256", headers={"kid": "dev"})
