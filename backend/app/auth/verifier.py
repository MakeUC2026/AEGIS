"""Access-token verification: Auth0 (`auth0-api-python`, PRD §3.2) or a local dev key.

Dev mode exists so the stack runs and is tested without an Auth0 tenant; it is refused
in production by `Settings`.
"""

from __future__ import annotations

from typing import Any, Protocol

import jwt
from auth0_api_python import ApiClient, ApiClientOptions

from app.config import Settings

CLOCK_LEEWAY_S = 30
REQUIRED_CLAIMS = ["exp", "iat", "sub"]


class AuthError(Exception):
    """Token missing, malformed, expired, or not ours."""


class TokenVerifier(Protocol):
    async def verify(self, token: str) -> dict[str, Any]: ...


class DevVerifier:
    def __init__(self, public_pem: str, issuer: str, audience: str) -> None:
        self._key = public_pem
        self._issuer = issuer
        self._audience = audience

    async def verify(self, token: str) -> dict[str, Any]:
        try:
            return jwt.decode(
                token,
                self._key,
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._issuer,
                leeway=CLOCK_LEEWAY_S,
                options={"require": REQUIRED_CLAIMS},
            )
        except jwt.PyJWTError as exc:
            raise AuthError(str(exc)) from exc


class Auth0Verifier:
    def __init__(self, domain: str, audience: str) -> None:
        self._client = ApiClient(ApiClientOptions(domain=domain, audience=audience))

    async def verify(self, token: str) -> dict[str, Any]:
        try:
            claims = await self._client.verify_access_token(token)
        except Exception as exc:  # library raises several unrelated types
            raise AuthError("token rejected") from exc
        if not isinstance(claims.get("sub"), str):
            raise AuthError("token has no subject")
        return claims


def make_verifier(settings: Settings) -> TokenVerifier:
    if settings.auth_mode == "dev":
        return DevVerifier(
            settings.dev_jwt_public_key, settings.dev_jwt_issuer, settings.dev_jwt_audience
        )
    return Auth0Verifier(settings.auth0_domain, settings.auth0_audience)
