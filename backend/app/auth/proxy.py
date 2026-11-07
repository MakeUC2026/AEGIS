"""Next.js -> FastAPI trust boundary (PRD §8.5, §15.1: "FastAPI accepts calls only from the
Next.js server").

Every /api request must carry the shared secret header. Only then are the forwarded
client IP, user agent and fingerprint trusted and turned into `ClientMeta`.
Fails closed: with no secret configured, every /api request is rejected.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import re

from starlette.types import ASGIApp, Receive, Scope, Send

from app.contracts.common import ClientMeta

PROXY_SECRET_HEADER = "x-aegis-proxy-secret"  # noqa: S105 - header name, not a secret value
CLIENT_UA_HEADER = "x-aegis-client-ua"
FINGERPRINT_HEADER = "x-aegis-fingerprint"
FORWARDED_FOR_HEADER = "x-forwarded-for"
PROTECTED_PREFIX = "/api"
MAX_USER_AGENT_LEN = 512
_FINGERPRINT = re.compile(r"[0-9a-f]{64}")


def parse_forwarded_for(value: str | None) -> str | None:
    """The first hop is the client (Vercel sets it). Anything that is not an IP is dropped."""
    if not value:
        return None
    first = value.split(",", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(first))
    except ValueError:
        return None


def parse_fingerprint(value: str | None) -> str | None:
    """SHA-256 hex computed by the arena page (PRD §8.5)."""
    return value if value is not None and _FINGERPRINT.fullmatch(value) else None


def _headers(scope: Scope) -> dict[str, str]:
    return {k.decode("latin-1"): v.decode("latin-1") for k, v in scope.get("headers", [])}


class ProxySecretMiddleware:
    def __init__(self, app: ASGIApp, secret: str) -> None:
        self.app = app
        self._secret = secret.encode()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope["path"].startswith(PROTECTED_PREFIX):
            await self.app(scope, receive, send)
            return
        headers = _headers(scope)
        presented = headers.get(PROXY_SECRET_HEADER, "").encode()
        if not self._secret or not hmac.compare_digest(presented, self._secret):
            await _reject(send)
            return
        ua = headers.get(CLIENT_UA_HEADER)
        scope.setdefault("state", {})["client_meta"] = ClientMeta(
            ip=parse_forwarded_for(headers.get(FORWARDED_FOR_HEADER)),
            user_agent=ua[:MAX_USER_AGENT_LEN] if ua else None,
            fingerprint_hash=parse_fingerprint(headers.get(FINGERPRINT_HEADER)),
        )
        await self.app(scope, receive, send)


async def _reject(send: Send) -> None:
    body = json.dumps({"detail": "untrusted caller"}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": body})
