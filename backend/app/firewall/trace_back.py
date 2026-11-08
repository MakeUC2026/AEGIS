"""Trace-back rows for diverted turns (M2 C-05, C-07; PRD §8.5; spec AEGIS-DOM-120, -122).

One `trace_back` row is written inside every divert transaction (tool call or reply):

- the client IP only as a salted HMAC-SHA256 (`ip_hash`) and the clear /24 (IPv4) or /48
  (IPv6) `subnet`; the raw address is never stored. The key is `AEGIS_TRACE_SALT`, else
  derived from the proxy secret, else absent (then no hash is stored, the subnet still is);
- ASN, organisation and country from offline GeoLite2 files (`geoip.py`), `None` when the
  files or the address are missing;
- the user agent, the arena's fingerprint hash, and the tool names attempted in the session;
- `methods_used` is filled later by M3's forensic worker.

The hash is also written onto the divert event (`client_ip_hash`). Retention is 30 days:
`purge_expired_trace_back` deletes older rows and leaves only the hash on the event.
Admin-only data: it never reaches a `PlayerView` or the teacher API (PRD §8.5, I-3).
"""

from __future__ import annotations

import hashlib
import hmac
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.contracts.common import ClientMeta
from app.db.audit import record_audit
from app.firewall.geoip import GeoIP, TraceSettings
from app.firewall.textnorm import storable

TRACE_ID_PREFIX = "trc-"
MAX_FIELD_CHARS = 512
TRACE_RETENTION_DAYS = 30
IPV4_PREFIX, IPV6_PREFIX = 24, 48

_TOOLS_ATTEMPTED = (
    "SELECT DISTINCT tool FROM fw_events"
    " WHERE fw_session_id = :sid AND tool IS NOT NULL ORDER BY tool"
)
_INSERT = (
    "INSERT INTO trace_back (trace_id, user_id, fw_session_id, event_id, ip_hash, subnet, asn,"
    " asn_org, country, user_agent, client_fingerprint, tools_called)"
    " VALUES (:trace_id, CAST(:user_id AS uuid), :sid, :event_id, :ip_hash, :subnet, :asn,"
    " :asn_org, :country, :user_agent, :fingerprint, :tools)"
)
_KEEP_HASH = (  # the hash outlives the row: copy it onto an event that lacks it
    "UPDATE fw_events e SET client_ip_hash = t.ip_hash FROM trace_back t"
    " WHERE e.trace_back_id = t.trace_id AND e.client_ip_hash IS NULL"
    " AND t.ip_hash IS NOT NULL AND t.time < :cutoff"
)
_PURGE = "DELETE FROM trace_back WHERE time < :cutoff"


@dataclass(frozen=True)
class NetworkFields:
    ip_hash: str | None = None
    subnet: str | None = None
    asn: int | None = None
    asn_org: str | None = None
    country: str | None = None


def ip_hash_key(salt: str, proxy_secret: str) -> bytes | None:
    """The HMAC key: the dedicated salt, else one derived from the proxy secret (never the
    secret itself), else None, in which case no IP hash is stored."""
    if salt:
        return hashlib.sha256(b"aegis-trace-salt:" + salt.encode()).digest()
    if proxy_secret:
        return hmac.new(proxy_secret.encode(), b"aegis-trace-back-ip-v1", hashlib.sha256).digest()
    return None


def _parse(ip: str | None) -> IPv4Address | IPv6Address | None:
    if not ip or not ip.strip():
        return None
    try:
        address = ip_address(ip.strip())
    except ValueError:
        return None
    if isinstance(address, IPv6Address):
        if address.ipv4_mapped is not None:
            return address.ipv4_mapped
        return IPv6Address(address.packed)  # drops any scope ID
    return address


def network_fields(ip: str | None, key: bytes | None, geo: GeoIP) -> NetworkFields:
    address = _parse(ip)
    if address is None:
        return NetworkFields()
    prefix = IPV4_PREFIX if isinstance(address, IPv4Address) else IPV6_PREFIX
    found = geo.lookup(address)
    return NetworkFields(
        ip_hash=hmac.new(key, str(address).encode(), hashlib.sha256).hexdigest() if key else None,
        subnet=str(ip_network(f"{address}/{prefix}", strict=False)),
        asn=found.asn,
        asn_org=found.asn_org,
        country=found.country,
    )


class Tracer:
    """The IP-hash key and the GeoLite2 files, ready to turn a `ClientMeta` into fields."""

    def __init__(self, key: bytes | None, geo: GeoIP) -> None:
        self._key = key
        self._geo = geo

    @classmethod
    def disabled(cls) -> Tracer:
        return cls(None, GeoIP())

    @classmethod
    def from_settings(cls, proxy_secret: str, trace: TraceSettings | None = None) -> Tracer:
        trace = trace or TraceSettings()
        key = ip_hash_key(trace.trace_salt.get_secret_value(), proxy_secret)
        return cls(key, GeoIP.from_dir(trace.geolite_dir or None))

    def network(self, ip: str | None) -> NetworkFields:
        return network_fields(ip, self._key, self._geo)


def new_trace_id() -> str:
    return TRACE_ID_PREFIX + uuid.uuid4().hex


def _clip(value: str | None) -> str | None:
    return None if value is None else str(storable(value))[:MAX_FIELD_CHARS]


async def insert_trace_back(
    conn: AsyncConnection,
    *,
    trace_id: str,
    user_id: str,
    fw_session_id: str,
    event_id: str,
    client: ClientMeta,
    tool: str | None,
    net: NetworkFields,
) -> None:
    tools = (await conn.execute(text(_TOOLS_ATTEMPTED), {"sid": fw_session_id})).scalars().all()
    await conn.execute(
        text(_INSERT),
        {
            "trace_id": trace_id,
            "user_id": user_id,
            "sid": fw_session_id,
            "event_id": event_id,
            "ip_hash": net.ip_hash,
            "subnet": net.subnet,
            "asn": net.asn,
            "asn_org": _clip(net.asn_org),
            "country": net.country,
            "user_agent": _clip(client.user_agent),
            "fingerprint": _clip(client.fingerprint_hash),
            "tools": sorted({*tools, *([tool] if tool else [])}),
        },
    )


async def purge_expired_trace_back(engine: AsyncEngine, now: datetime) -> int:
    """Delete trace-back rows older than 30 days; only the hash stays, on the event.
    Returns the number of rows deleted."""
    cutoff = now - timedelta(days=TRACE_RETENTION_DAYS)
    async with engine.begin() as conn:
        await conn.execute(text(_KEEP_HASH), {"cutoff": cutoff})
        removed = (await conn.execute(text(_PURGE), {"cutoff": cutoff})).rowcount
        if removed:  # a system job: no actor; a purge that removed nothing leaves no trace
            await record_audit(
                conn,
                actor_id=None,
                entity="trace_back",
                entity_id="purge",
                action="purge",
                before=None,
                after={"deleted": removed},
            )
        return removed
