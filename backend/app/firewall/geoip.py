"""Offline GeoLite2 lookups and the trace-back settings (M2 C-07; PRD §8.5, M2-X44; AEGIS-DOM-122).

ASN, ASN organisation and country come from MaxMind GeoLite2 files read from disk: no
third-party API call is ever made. The files are optional and may be absent, unreadable or
partial; every such case gives `None` fields and never an error. Look-ups are in-memory
reads of an open database, so they are cheap enough to do on the divert path.

Files, in the directory `AEGIS_GEOLITE_DIR`:
- `GeoLite2-ASN.mmdb`: `autonomous_system_number`, `autonomous_system_organization`;
- `GeoLite2-Country.mmdb`: `country.iso_code`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Any

import maxminddb
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

ASN_FILE = "GeoLite2-ASN.mmdb"
COUNTRY_FILE = "GeoLite2-Country.mmdb"

logger = logging.getLogger(__name__)


class TraceSettings(BaseSettings):
    """M2's own settings, kept out of M1's `Settings`: the IP-hash salt and the GeoLite2 files."""

    model_config = SettingsConfigDict(env_file=(".env", "../.env"), extra="ignore")

    trace_salt: SecretStr = Field(default=SecretStr(""), alias="AEGIS_TRACE_SALT")
    geolite_dir: str = Field(default="", alias="AEGIS_GEOLITE_DIR")


@dataclass(frozen=True)
class GeoResult:
    asn: int | None = None
    asn_org: str | None = None
    country: str | None = None


def _open(path: Path) -> Any | None:
    try:
        return maxminddb.open_database(str(path))
    except Exception as exc:  # missing, empty or corrupt: no fields, never an error
        logger.warning("GeoLite2 file %s not usable: %s", path.name, type(exc).__name__)
        return None


def _record(reader: Any | None, address: IPv4Address | IPv6Address) -> dict[str, Any]:
    if reader is None:
        return {}
    try:
        record = reader.get(str(address))
    except Exception:  # e.g. an IPv6 address in an IPv4-only file
        return {}
    return record if isinstance(record, dict) else {}


class GeoIP:
    def __init__(self, asn: Any | None = None, country: Any | None = None) -> None:
        self._asn = asn
        self._country = country

    @classmethod
    def from_dir(cls, directory: str | Path | None) -> GeoIP:
        if not directory:
            return cls()
        base = Path(directory)
        asn = _open(base / ASN_FILE) if (base / ASN_FILE).is_file() else None
        country = _open(base / COUNTRY_FILE) if (base / COUNTRY_FILE).is_file() else None
        if asn is None and country is None:
            logger.warning("no usable GeoLite2 files in %s: ASN and country will be empty", base)
        return cls(asn, country)

    def lookup(self, address: IPv4Address | IPv6Address) -> GeoResult:
        asn_rec = _record(self._asn, address)
        number = asn_rec.get("autonomous_system_number")
        org = asn_rec.get("autonomous_system_organization")
        country_rec = _record(self._country, address).get("country")
        iso = country_rec.get("iso_code") if isinstance(country_rec, dict) else None
        return GeoResult(
            asn=number if isinstance(number, int) and not isinstance(number, bool) else None,
            asn_org=org if isinstance(org, str) else None,
            country=iso if isinstance(iso, str) and len(iso) == 2 else None,
        )

    def close(self) -> None:
        for reader in (self._asn, self._country):
            if reader is not None:
                reader.close()
