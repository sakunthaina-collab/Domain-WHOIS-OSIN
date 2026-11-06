"""
Deterministic Unit & Integration Tests for IP Geolocation & Threat Intelligence OSINT Skill v1.5.0
Mocked HTTP and DNS interfaces with frozen time testing. Zero network flakiness.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from freezegun import freeze_time

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Dynamically load ip-geolocation-osint run.py module
skill_file = ROOT / "skills" / "investigation" / "ip-geolocation-osint" / "run.py"
spec = importlib.util.spec_from_file_location("ip_geolocation_osint", str(skill_file))
ip_mod = importlib.util.module_from_spec(spec)
sys.modules["ip_geolocation_osint"] = ip_mod
spec.loader.exec_module(ip_mod)

run = ip_mod.run
normalize_ip = ip_mod.normalize_ip
check_bogon = ip_mod.check_bogon
resolve_reverse_dns = ip_mod.resolve_reverse_dns
check_tor_exit_node = ip_mod.check_tor_exit_node
_fetch_ip_api = ip_mod._fetch_ip_api
_fetch_ipwhois = ip_mod._fetch_ipwhois


# =====================================================================
# Group 1: Input Normalization & Bogon Filter Tests (Zero Network)
# =====================================================================

def test_ip_normalize_valid_ipv4_and_ipv6():
    ip_str, ip_obj = normalize_ip("8.8.8.8")
    assert ip_str == "8.8.8.8"
    assert ip_obj.version == 4

    ip_str6, ip_obj6 = normalize_ip("2001:4860:4860::8888")
    assert ip_str6 == "2001:4860:4860::8888"
    assert ip_obj6.version == 6


def test_ip_normalize_strip_ports_and_schemes():
    ip_str, _ = normalize_ip("https://1.1.1.1:443/path?query=1")
    assert ip_str == "1.1.1.1"

    ip_str, _ = normalize_ip("[2606:4700:4700::1111]:8080")
    assert ip_str == "2606:4700:4700::1111"


def test_ip_normalize_reject_forbidden_characters():
    with pytest.raises(ValueError, match="Forbidden characters"):
        normalize_ip("8.8.8.8; rm -rf /")

    with pytest.raises(ValueError, match="Forbidden characters"):
        normalize_ip("1.2.3.4\x00evil")

    with pytest.raises(ValueError, match="Forbidden characters"):
        normalize_ip("1.2.3.4..5")


def test_ip_invalid_format_handling():
    res = run("999.999.999.999", passive_only=True)
    assert res["ok"] is False
    assert "Invalid IP address format" in res["error"]

    res_empty = run("", passive_only=True)
    assert res_empty["ok"] is False
    assert "non-empty string" in res_empty["error"]


def test_ip_opsec_passive_only_violation():
    with pytest.raises(ValueError, match="OPSEC violation"):
        run("8.8.8.8", passive_only=False)


def test_ip_private_rfc1918():
    for private_ip in ("192.168.1.1", "10.0.0.1", "172.16.5.10"):
        res = run(private_ip, passive_only=True)
        assert res["ok"] is True
        assert res["ip"] == private_ip
        assert res["is_bogon"] is True
        assert res["is_private"] is True
        assert res["country"] == "Local / Private Network"
        assert res["asn"] == "AS0"
        assert len(res["evidence"]) >= 1
        assert res["evidence"][0]["claim"] == "bogon_ip_classification"
        assert "source" in res["evidence"][0]
        assert "response_sha256" in res["evidence"][0]


def test_ip_loopback():
    for loopback in ("127.0.0.1", "::1"):
        res = run(loopback, passive_only=True)
        assert res["ok"] is True
        assert res["is_bogon"] is True
        assert res["is_private"] is True


def test_ip_cgnat_rfc6598():
    res = run("100.64.0.1", passive_only=True)
    assert res["ok"] is True
    assert res["is_bogon"] is True
    assert "CGNAT" in res["bogon_type"] or "Shared Address Space" in res["bogon_type"]


def test_ip_cloud_metadata_blocked():
    for meta_ip in ("169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254"):
        res = run(meta_ip, passive_only=True)
        assert res["ok"] is True
        assert res["is_bogon"] is True
        assert res["blocked"] is True
        assert res["is_cloud_metadata"] is True
        assert res["status"] == "blocked_metadata_ip"


# =====================================================================
# Group 2: Mocked Geolocation Resolution Tests
# =====================================================================

@freeze_time("2026-11-06 12:00:00")
@patch("requests.get")
@patch("ip_geolocation_osint.resolve_reverse_dns")
def test_ip_public_ipv4_mocked(mock_rdns, mock_requests):
    mock_rdns.return_value = (["dns.google"], {
        "claim": "reverse_dns_ptr",
        "source": "DNS query PTR 8.8.8.8.in-addr.arpa",
        "query": "PTR 8.8.8.8",
        "timestamp": "2026-11-06T12:00:00Z",
        "retrieved_at": "2026-11-06T12:00:00Z",
        "response_sha256": "abc123",
        "raw_response_sha256": "abc123"
    })

    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_payload = {
        "status": "success",
        "country": "United States",
        "countryCode": "US",
        "regionName": "Virginia",
        "city": "Ashburn",
        "zip": "20149",
        "lat": 39.03,
        "lon": -77.5,
        "timezone": "America/New_York",
        "isp": "Google LLC",
        "org": "Google Public DNS",
        "as": "AS15169 Google LLC",
        "asname": "GOOGLE",
        "hosting": True,
        "query": "8.8.8.8"
    }
    fake_response.content = json.dumps(fake_payload).encode("utf-8")
    fake_response.json.return_value = fake_payload
    mock_requests.return_value = fake_response

    res = run("8.8.8.8", passive_only=True)

    assert res["ok"] is True
    assert res["ip"] == "8.8.8.8"
    assert res["country"] == "United States"
    assert res["country_code"] == "US"
    assert res["city"] == "Ashburn"
    assert res["isp"] == "Google LLC"
    assert res["asn"] == "AS15169"
    assert res["hostname"] == "dns.google"
    assert res["is_bogon"] is False
    assert res["is_private"] is False
    assert res["is_cloud"] is True
    assert len(res["evidence"]) >= 2
    for ev in res["evidence"]:
        assert "source" in ev
        assert "query" in ev
        assert "timestamp" in ev
        assert "response_sha256" in ev


@freeze_time("2026-11-06 12:00:00")
@patch("requests.get")
@patch("ip_geolocation_osint.resolve_reverse_dns")
def test_ip_public_ipv6_mocked(mock_rdns, mock_requests):
    mock_rdns.return_value = (["one.one.one.one"], None)

    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_payload = {
        "success": True,
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "San Francisco",
        "postal": "94107",
        "latitude": 37.7749,
        "longitude": -122.4194,
        "timezone": {"id": "America/Los_Angeles"},
        "connection": {
            "asn": 13335,
            "org": "Cloudflare, Inc.",
            "isp": "Cloudflare, Inc."
        }
    }
    fake_response.content = json.dumps(fake_payload).encode("utf-8")
    fake_response.json.return_value = fake_payload
    mock_requests.return_value = fake_response

    # Force Tier 1B by passing an IPv6 address where ip-api returns None or by patch
    with patch("ip_geolocation_osint._fetch_ip_api", return_value=(None, None)):
        res = run("2606:4700:4700::1111", passive_only=True)

    assert res["ok"] is True
    assert res["ip"] == "2606:4700:4700::1111"
    assert res["country"] == "United States"
    assert res["asn"] == "AS13335"
    assert res["isp"] == "Cloudflare, Inc."
    assert res["is_cloud"] is True


@patch("ip_geolocation_osint._fetch_ip_api", return_value=(None, None))
@patch("ip_geolocation_osint._fetch_ipwhois")
@patch("ip_geolocation_osint.resolve_reverse_dns", return_value=([], None))
def test_ip_api_failover_mocked(mock_rdns, mock_ipwho, mock_ip_api):
    mock_ipwho.return_value = (
        {
            "country": "Japan",
            "country_code": "JP",
            "city": "Tokyo",
            "region": "Kanto",
            "postal": "100-0001",
            "latitude": 35.68,
            "longitude": 139.76,
            "timezone": "Asia/Tokyo",
            "isp": "SoftBank Corp.",
            "org": "SoftBank Corp.",
            "asn": "AS17676",
            "as_name": "SoftBank Corp.",
            "is_datacenter": False,
        },
        {
            "claim": "ip_geolocation_lookup_ipwhois",
            "source": "https://ipwho.is/1.1.1.1",
            "query": "1.1.1.1",
            "timestamp": "2026-11-06T12:00:00Z",
            "retrieved_at": "2026-11-06T12:00:00Z",
            "response_sha256": "fff111",
            "raw_response_sha256": "fff111"
        }
    )

    res = run("1.1.1.1", passive_only=True)
    assert res["ok"] is True
    assert res["country"] == "Japan"
    assert res["city"] == "Tokyo"
    assert res["asn"] == "AS17676"
    assert len(res["evidence"]) == 1
    assert res["evidence"][0]["source"] == "https://ipwho.is/1.1.1.1"


@patch("ip_geolocation_osint.check_tor_exit_node", return_value=True)
@patch("ip_geolocation_osint._fetch_ip_api")
@patch("ip_geolocation_osint.resolve_reverse_dns", return_value=(["tor-exit.test.org"], None))
def test_ip_tor_exit_node_heuristic(mock_rdns, mock_ip_api, mock_tor):
    mock_ip_api.return_value = (
        {
            "status": "success",
            "country": "Germany",
            "countryCode": "DE",
            "city": "Frankfurt",
            "as": "AS60729 Zwiebelfreunde",
            "isp": "Zwiebelfreunde e.V.",
            "org": "Tor Exit Node",
            "hosting": True
        },
        {"claim": "test", "source": "test", "query": "185.220.101.5", "timestamp": "2026-11-06T12:00:00Z", "response_sha256": "123"}
    )

    res = run("185.220.101.5", passive_only=True)
    assert res["ok"] is True
    assert res["is_tor"] is True
    assert res["is_vpn"] is True


@patch("ip_geolocation_osint.resolve_reverse_dns")
@patch("ip_geolocation_osint._fetch_ip_api", return_value=(None, None))
@patch("ip_geolocation_osint._fetch_ipwhois", return_value=(None, None))
@patch("ip_geolocation_osint._fetch_rdap")
def test_ip_rdap_fallback_mocked(mock_rdap, mock_ipwho, mock_ip_api, mock_rdns):
    mock_rdns.return_value = ([], None)
    mock_rdap.return_value = (
        {
            "country": "US",
            "name": "ARIN-NET",
        },
        {"claim": "rdap", "source": "https://rdap.arin.net", "query": "199.7.83.42", "timestamp": "2026-11-06T12:00:00Z", "response_sha256": "456"}
    )

    res = run("199.7.83.42", passive_only=True)
    assert res["ok"] is True
    assert res["country"] == "US"
    assert res["isp"] == "ARIN-NET"


# =====================================================================
# Group 3: Cross-Skill Invocability & Executor Conformance
# =====================================================================

def test_executor_runs_ip_geolocation():
    from core.registry import Registry
    from core.executor import Executor

    reg = Registry(ROOT / "skills")
    skill = reg.get("ip-geolocation-osint")
    assert skill is not None
    assert skill.status == "runnable"

    res = Executor().run(skill, {"ip": "127.0.0.1", "passive_only": True})
    assert res["ok"] is True
    assert res["is_bogon"] is True
    assert res["is_private"] is True
