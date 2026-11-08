"""M2 C-07 trace-back network fields (PRD §8.5; M2-X44; spec AEGIS-DOM-122).

The client IP is stored only as a salted HMAC plus the clear /24 (IPv4) or /48 (IPv6)
subnet. ASN, organisation and country come from offline GeoLite2 files; a missing,
unreadable or incomplete file gives `None` fields, never an error. Nothing here touches
the network.
"""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from typing import Any

import pytest
from mmdb_writer import MMDBWriter
from netaddr import IPSet

from app.firewall.geoip import ASN_FILE, COUNTRY_FILE, GeoIP, TraceSettings
from app.firewall.trace_back import NetworkFields, Tracer, ip_hash_key, network_fields

KEY = b"k" * 32
IP = "203.0.113.7"


def _db(path: Path, kind: str, networks: dict[str, dict[str, Any]]) -> Path:
    writer = MMDBWriter(ip_version=6, database_type=kind, ipv4_compatible=True)
    for network, record in networks.items():
        writer.insert_network(IPSet([network]), record)
    writer.to_db_file(str(path))
    return path


@pytest.fixture
def geo_dir(tmp_path: Path) -> Path:
    _db(
        tmp_path / ASN_FILE,
        "GeoLite2-ASN",
        {
            "203.0.113.0/24": {
                "autonomous_system_number": 64500,
                "autonomous_system_organization": "Example Net",
            },
            "2001:db8::/32": {
                "autonomous_system_number": 64501,
                "autonomous_system_organization": "Example v6",
            },
        },
    )
    _db(
        tmp_path / COUNTRY_FILE,
        "GeoLite2-Country",
        {"203.0.113.0/24": {"country": {"iso_code": "US"}}},
    )
    return tmp_path


# --- IP hash and subnet ------------------------------------------------------------------------


def test_ipv4_is_hashed_with_the_key_and_its_slash_24_kept() -> None:
    net = network_fields(IP, KEY, GeoIP())
    assert net.ip_hash == hmac.new(KEY, IP.encode(), hashlib.sha256).hexdigest()
    assert net.subnet == "203.0.113.0/24"
    assert IP not in repr(net)


def test_ipv6_keeps_its_slash_48() -> None:
    net = network_fields("2001:db8:abcd:12::7", KEY, GeoIP())
    assert net.subnet == "2001:db8:abcd::/48" and net.ip_hash


def test_an_ipv4_mapped_ipv6_address_is_the_same_client() -> None:
    plain = network_fields(IP, KEY, GeoIP())
    mapped = network_fields("::ffff:203.0.113.7", KEY, GeoIP())
    assert mapped == plain


def test_the_hash_depends_on_the_key_and_the_address() -> None:
    a = network_fields(IP, KEY, GeoIP())
    assert network_fields(IP, b"z" * 32, GeoIP()).ip_hash != a.ip_hash
    assert network_fields("203.0.113.8", KEY, GeoIP()).ip_hash != a.ip_hash
    assert network_fields(IP, KEY, GeoIP()).ip_hash == a.ip_hash  # stable


def test_without_a_key_no_hash_is_stored_but_the_subnet_is() -> None:
    net = network_fields(IP, None, GeoIP())
    assert net.ip_hash is None and net.subnet == "203.0.113.0/24"


@pytest.mark.parametrize("bad", [None, "", "not-an-ip", "999.1.1.1", "203.0.113", "1.2.3.4/24"])
def test_a_missing_or_malformed_address_gives_no_network_fields(bad: str | None) -> None:
    assert network_fields(bad, KEY, GeoIP()) == NetworkFields()


# --- the key ---------------------------------------------------------------------------------


def test_the_key_comes_from_the_salt_then_the_proxy_secret_then_nothing() -> None:
    salted = ip_hash_key("my-salt", "proxy-secret-value")
    derived = ip_hash_key("", "proxy-secret-value")
    assert salted and derived and salted != derived
    assert derived == ip_hash_key("", "proxy-secret-value")  # stable across restarts
    assert derived != b"proxy-secret-value"  # never the proxy secret itself
    assert ip_hash_key("", "") is None


# --- GeoLite2 --------------------------------------------------------------------------------


def test_asn_org_and_country_come_from_the_files(geo_dir: Path) -> None:
    geo = GeoIP.from_dir(geo_dir)
    net = network_fields(IP, KEY, geo)
    assert (net.asn, net.asn_org, net.country) == (64500, "Example Net", "US")
    v6 = network_fields("2001:db8::5", KEY, geo)
    assert (v6.asn, v6.asn_org, v6.country) == (64501, "Example v6", None)  # no v6 country row


def test_an_address_not_in_the_files_has_no_geo_fields(geo_dir: Path) -> None:
    net = network_fields("198.51.100.9", KEY, GeoIP.from_dir(geo_dir))
    assert (net.asn, net.asn_org, net.country) == (None, None, None)
    assert net.subnet == "198.51.100.0/24"  # the rest still works


def test_one_missing_file_only_loses_its_fields(geo_dir: Path) -> None:
    (geo_dir / COUNTRY_FILE).unlink()
    net = network_fields(IP, KEY, GeoIP.from_dir(geo_dir))
    assert (net.asn, net.asn_org, net.country) == (64500, "Example Net", None)


@pytest.mark.parametrize("target", [None, "empty", "nowhere"])
def test_no_files_gives_nulls_never_an_error(tmp_path: Path, target: str | None) -> None:
    if target == "empty":
        geo = GeoIP.from_dir(tmp_path)
    elif target == "nowhere":
        geo = GeoIP.from_dir(tmp_path / "does-not-exist")
    else:
        geo = GeoIP.from_dir(None)
    net = network_fields(IP, KEY, geo)
    assert (net.asn, net.asn_org, net.country) == (None, None, None)
    assert net.subnet == "203.0.113.0/24" and net.ip_hash


def test_a_corrupt_file_gives_nulls_never_an_error(tmp_path: Path) -> None:
    (tmp_path / ASN_FILE).write_bytes(b"this is not a maxmind database")
    (tmp_path / COUNTRY_FILE).write_bytes(b"")
    net = network_fields(IP, KEY, GeoIP.from_dir(tmp_path))
    assert (net.asn, net.asn_org, net.country) == (None, None, None)


def test_odd_record_shapes_are_ignored(tmp_path: Path) -> None:
    _db(tmp_path / ASN_FILE, "GeoLite2-ASN", {"203.0.113.0/24": {"autonomous_system_number": "x"}})
    _db(tmp_path / COUNTRY_FILE, "GeoLite2-Country", {"203.0.113.0/24": {"country": "US"}})
    net = network_fields(IP, KEY, GeoIP.from_dir(tmp_path))
    assert (net.asn, net.asn_org, net.country) == (None, None, None)


# --- settings and the tracer -----------------------------------------------------------------


def test_trace_settings_read_the_salt_and_the_directory(tmp_path: Path) -> None:
    settings = TraceSettings(_env_file=None, AEGIS_TRACE_SALT="s", AEGIS_GEOLITE_DIR=str(tmp_path))
    assert settings.trace_salt.get_secret_value() == "s" and settings.geolite_dir == str(tmp_path)
    assert TraceSettings(_env_file=None).geolite_dir == ""


def test_the_tracer_ties_the_key_and_the_files_together(geo_dir: Path) -> None:
    tracer = Tracer(KEY, GeoIP.from_dir(geo_dir))
    assert tracer.network(IP).asn == 64500
    assert Tracer.disabled().network(IP) == NetworkFields(subnet="203.0.113.0/24")


def test_a_tracer_from_settings_uses_the_salt_or_the_proxy_secret(geo_dir: Path) -> None:
    with_dir = TraceSettings(_env_file=None, AEGIS_GEOLITE_DIR=str(geo_dir))
    derived = Tracer.from_settings("proxy-secret-value", with_dir).network(IP)
    assert derived.ip_hash and derived.asn == 64500
    salted = TraceSettings(_env_file=None, AEGIS_TRACE_SALT="s")
    assert Tracer.from_settings("proxy-secret-value", salted).network(IP).ip_hash != derived.ip_hash
    bare = Tracer.from_settings("", TraceSettings(_env_file=None)).network(IP)
    assert bare == NetworkFields(subnet="203.0.113.0/24")  # no key, no files
