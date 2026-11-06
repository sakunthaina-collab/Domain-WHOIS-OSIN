"""
Unit & Integration Tests for Domain & WHOIS OSINT Skill v1.7.0
Deterministic tests with frozen time, mocked external interfaces, and zero network flakiness.
"""

import sys
import json
import pathlib
import pytest
import importlib.util
from datetime import datetime, timezone
from freezegun import freeze_time
from unittest.mock import patch, MagicMock

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Dynamically load domain-whois-osint module
skill_file = ROOT / "skills" / "investigation" / "domain-whois-osint" / "run.py"
spec = importlib.util.spec_from_file_location("domain_whois_osint", str(skill_file))
domain_mod = importlib.util.module_from_spec(spec)
sys.modules["domain_whois_osint"] = domain_mod
spec.loader.exec_module(domain_mod)

normalize_domain = domain_mod.normalize_domain
calculate_scam_score = domain_mod.calculate_scam_score
_resolve_dns = domain_mod._resolve_dns
_lookup_rdap = domain_mod._lookup_rdap
_fetch_cert_transparency = domain_mod._fetch_cert_transparency
_enrich_ip_intel = domain_mod._enrich_ip_intel
run = domain_mod.run


# =====================================================================
# Group 1: Input Validation & Normalization Tests
# =====================================================================

def test_normalize_valid_simple_domain():
    assert normalize_domain("example.com") == "example.com"
    assert normalize_domain("EXAMPLE.COM") == "example.com"
    assert normalize_domain("  sub.domain.co.th  ") == "sub.domain.co.th"


def test_normalize_strip_schemes_and_paths():
    assert normalize_domain("https://phishing-site.xyz/login/verify") == "phishing-site.xyz"
    assert normalize_domain("http://banking-portal.top:8080/index.php") == "banking-portal.top"
    assert normalize_domain("user:pass@scam-hub.tk:443/auth") == "scam-hub.tk"


def test_normalize_reject_forbidden_characters():
    with pytest.raises(ValueError, match="Forbidden characters"):
        normalize_domain("../../etc/passwd")

    with pytest.raises(ValueError, match="Forbidden characters"):
        normalize_domain("evil.com\\payload")

    with pytest.raises(ValueError, match="Forbidden characters"):
        normalize_domain("scam.com\x00extra")

    with pytest.raises(ValueError, match="Forbidden characters"):
        normalize_domain("invalid domain with spaces.com")


def test_normalize_reject_invalid_syntax():
    with pytest.raises(ValueError):
        normalize_domain("")

    with pytest.raises(ValueError):
        normalize_domain("-invalid-start.com")

    with pytest.raises(ValueError):
        normalize_domain("nodotstld")


# =====================================================================
# Group 2: Explainable Scam Scoring Heuristic Tests (Deterministic with Freeze Time)
# =====================================================================

@freeze_time("2026-11-06 12:00:00")
def test_mature_domain_scores_low_risk():
    """Mature domains like google.com with established history should score low risk."""
    dns_data = {
        "A": ["142.250.190.46"],
        "MX": ["10 smtp.google.com"],
        "NS": ["ns1.google.com"],
    }
    whois_data = {
        "creation_date": "1997-09-15T04:00:00Z",
        "registrar": "MarkMonitor Inc.",
        "privacy_guard": False,
    }
    cert_data = {"cert_count": 45, "subdomains": ["mail.google.com"]}
    ip_intel = [{"ip": "142.250.190.46", "is_tor": False, "is_vpn": False}]

    res = calculate_scam_score("google.com", dns_data, whois_data, cert_data, ip_intel)

    assert res["scam_risk_score"] == 0
    assert res["confidence"] == "high"
    assert len(res["signals"]) == 0
    assert "ความเสี่ยงต่ำ" in res["top_reason_th"]
    assert "Low Risk" in res["top_reason_en"]
    assert res["domain_age_days"] > 10000


@freeze_time("2026-11-06 12:00:00")
def test_young_domain_scores_high():
    """Domains registered 10 days ago should trigger high-risk domain age penalty (+25)."""
    dns_data = {"A": ["1.2.3.4"], "MX": ["10 mail.sample.com"]}
    whois_data = {
        "creation_date": "2026-10-27T00:00:00Z",  # 10 days ago
        "privacy_guard": False,
    }
    res = calculate_scam_score("sample.com", dns_data, whois_data, {}, [])

    assert res["scam_risk_score"] >= 25
    factors = [s["factor"] for s in res["signals"]]
    assert "domain_age" in factors
    assert res["domain_age_days"] == 10


@freeze_time("2026-11-06 12:00:00")
def test_suspicious_tld_and_privacy_guard_additive_scoring():
    """High-abuse TLD (.tk) + Privacy Guard should accumulate weights."""
    dns_data = {"A": ["1.2.3.4"], "MX": ["10 mx.test.tk"]}
    whois_data = {
        "creation_date": "2025-01-01T00:00:00Z",
        "privacy_guard": True,  # +15
    }
    res = calculate_scam_score("cryptos-portal.tk", dns_data, whois_data, {}, [])

    assert res["scam_risk_score"] == 35  # 15 + 20
    factors = {s["factor"]: s["weight"] for s in res["signals"]}
    assert factors["privacy_guard"] == 15
    assert factors["suspicious_tld"] == 20


@freeze_time("2026-11-06 12:00:00")
def test_missing_mx_records_penalty():
    """Active web server without Mail Exchanger (MX) receives +15 penalty."""
    dns_data = {
        "A": ["104.21.5.12"],
        "MX": [],  # Missing MX
    }
    whois_data = {"creation_date": "2020-01-01T00:00:00Z"}
    res = calculate_scam_score("landing-scam.com", dns_data, whois_data, {}, [])

    factors = {s["factor"]: s["weight"] for s in res["signals"]}
    assert "no_mx_records" in factors
    assert factors["no_mx_records"] == 15


@freeze_time("2026-11-06 12:00:00")
def test_suspicious_brand_keywords_with_hyphen():
    """Domain with phishing keywords and hyphenation gets penalized."""
    dns_data = {"A": ["1.2.3.4"], "MX": ["10 mail.com"]}
    whois_data = {"creation_date": "2020-01-01T00:00:00Z"}
    res = calculate_scam_score("kbank-verify-account.com", dns_data, whois_data, {}, [])

    factors = {s["factor"]: s["weight"] for s in res["signals"]}
    assert "suspicious_keywords" in factors
    assert factors["suspicious_keywords"] == 15


@freeze_time("2026-11-06 12:00:00")
def test_bulletproof_hosting_ip_flag():
    """Tor / Bulletproof VPN flag in IP intelligence adds +20 penalty."""
    dns_data = {"A": ["185.220.101.5"]}
    whois_data = {"creation_date": "2020-01-01T00:00:00Z"}
    ip_intel = [{"ip": "185.220.101.5", "is_tor": True}]

    res = calculate_scam_score("dark-portal.org", dns_data, whois_data, {}, ip_intel)

    factors = {s["factor"]: s["weight"] for s in res["signals"]}
    assert "bulletproof_hosting" in factors
    assert factors["bulletproof_hosting"] == 20


@freeze_time("2026-11-06 12:00:00")
def test_high_scam_score_triggers_high_risk_bilingual_reason():
    """Composite scam pattern (ultra-new + .tk + privacy + no-MX + keywords) scores >= 80."""
    dns_data = {"A": ["1.2.3.4"], "MX": []}
    whois_data = {
        "creation_date": "2026-11-01T00:00:00Z",  # 5 days ago (+25)
        "privacy_guard": True,                     # (+15)
    }
    # .tk (+20), no_mx (+15), verify-secure (+15) -> total = 90
    res = calculate_scam_score("scb-verify-secure.tk", dns_data, whois_data, {}, [])

    assert res["scam_risk_score"] >= 80
    assert "ความเสี่ยงสูง" in res["top_reason_th"]
    assert "High Risk" in res["top_reason_en"]


# =====================================================================
# Group 3: Mocked Subsystem Resolution & Evidence Tests
# =====================================================================

@patch("requests.get")
def test_lookup_rdap_mocked_success(mock_get):
    """RDAP query parses registration events and privacy guard correctly."""
    mock_payload = {
        "handle": "DOMAIN-1234",
        "ldhName": "TARGET.COM",
        "events": [
            {"eventAction": "registration", "eventDate": "2024-05-10T12:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-05-10T12:00:00Z"}
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "NameCheap Inc."]]]
            }
        ]
    }
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = json.dumps(mock_payload).encode("utf-8")
    mock_response.text = json.dumps(mock_payload)
    mock_response.json.return_value = mock_payload
    mock_get.return_value = mock_response

    data, evidence = _lookup_rdap("target.com", timeout=3.0)

    assert data["handle"] == "DOMAIN-1234"
    assert data["creation_date"] == "2024-05-10T12:00:00Z"
    assert data["registrar"] == "NameCheap Inc."
    assert len(evidence) == 1
    assert evidence[0]["claim"] == "rdap_registration_record"
    assert "raw_response_sha256" in evidence[0]


@patch("requests.get")
def test_fetch_cert_transparency_mocked(mock_get):
    """crt.sh CT log parser extracts subdomains and latest certificate dates."""
    mock_ct = [
        {
            "name_value": "api.target.com\nmail.target.com",
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "entry_timestamp": "2026-08-01T10:00:00",
        }
    ]
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = json.dumps(mock_ct).encode("utf-8")
    mock_resp.json.return_value = mock_ct
    mock_get.return_value = mock_resp

    data, evidence = _fetch_cert_transparency("target.com", timeout=2.5)

    assert data["cert_count"] == 1
    assert "api.target.com" in data["subdomains"]
    assert "mail.target.com" in data["subdomains"]
    assert len(evidence) == 1
    assert evidence[0]["claim"] == "certificate_transparency_logs"


def test_cross_skill_ip_enrichment_private_ip():
    """Private IP ranges are immediately flagged as private without external query."""
    intel, ev = _enrich_ip_intel(["192.168.1.1", "10.0.0.1"])
    assert len(intel) == 2
    assert intel[0]["is_private"] is True
    assert intel[1]["is_private"] is True


# =====================================================================
# Group 4: End-to-End Skill Workflow (Mocked)
# =====================================================================

@freeze_time("2026-11-06 12:00:00")
@patch("domain_whois_osint._resolve_dns")
@patch("domain_whois_osint._lookup_rdap")
@patch("domain_whois_osint._fetch_cert_transparency")
def test_full_run_workflow_mocked(mock_ct, mock_rdap, mock_dns):
    """Full workflow execution aggregates DNS, WHOIS, CT, Evidence, and Scoring."""
    mock_dns.return_value = (
        {"A": ["93.184.216.34"], "MX": ["10 mail.example.com"], "NS": ["a.iana-servers.net"]},
        [{"claim": "dns_a", "source": "dns", "retrieved_at": "2026-11-06T12:00:00Z", "raw_response_sha256": "111"}]
    )
    mock_rdap.return_value = (
        {"creation_date": "2000-01-01T00:00:00Z", "registrar": "IANA", "privacy_guard": False},
        [{"claim": "rdap", "source": "rdap", "retrieved_at": "2026-11-06T12:00:00Z", "raw_response_sha256": "222"}]
    )
    mock_ct.return_value = (
        {"cert_count": 5, "subdomains": []},
        [{"claim": "ct", "source": "crt.sh", "retrieved_at": "2026-11-06T12:00:00Z", "raw_response_sha256": "333"}]
    )

    out = run("https://example.com/login", passive_only=True)

    assert out["ok"] is True
    assert out["domain"] == "example.com"
    assert out["target_type"] == "domain"
    assert out["passive_only"] is True
    assert "scam_assessment" in out
    assert out["scam_assessment"]["scam_risk_score"] == 0
    assert len(out["evidence"]) >= 3
    for ev in out["evidence"]:
        assert "claim" in ev
        assert "source" in ev
        assert "retrieved_at" in ev
        assert "raw_response_sha256" in ev


def test_opsec_active_scan_rejection():
    """Active scan mode must raise ValueError per OPSEC rules."""
    with pytest.raises(ValueError, match="OPSEC violation"):
        run("example.com", passive_only=False)


# =====================================================================
# Group 5: Controlled Live Integration Test (< 10s budget)
# =====================================================================

def test_controlled_live_domain_integration():
    """Verify live DNS + RDAP query against google.com finishes under 10 seconds."""
    import time
    t0 = time.time()
    out = run("google.com", passive_only=True, timeout=10.0)
    elapsed = time.time() - t0

    assert out["ok"] is True
    assert out["domain"] == "google.com"
    assert elapsed < 10.0, f"Query took too long: {elapsed:.2f}s"
    assert len(out["dns"]["A"]) > 0
    assert out["scam_assessment"]["scam_risk_score"] <= 20


# =====================================================================
# Group 6: Enterprise UI Mockup Schema Validation & Conformance Tests
# =====================================================================

def test_schema_json_conformance_mocked():
    """Verify that mocked run output validates strictly against schema.json."""
    import jsonschema
    schema_file = ROOT / "skills" / "investigation" / "domain-whois-osint" / "schema.json"
    schema = json.loads(schema_file.read_text(encoding="utf-8"))

    with patch("domain_whois_osint._resolve_dns") as mock_dns, \
         patch("domain_whois_osint._lookup_rdap") as mock_rdap, \
         patch("domain_whois_osint._fetch_cert_transparency") as mock_ct:

        mock_dns.return_value = (
            {"A": ["185.199.110.153"], "MX": [], "NS": ["ns1.namecheap.com", "ns2.namecheap.com"]},
            [{"claim": "dns_a", "source": "dns", "retrieved_at": "2026-11-06T12:00:00Z", "raw_response_sha256": "aaa"}]
        )
        mock_rdap.return_value = (
            {
                "creation_date": "2024-10-02T10:12:00Z",
                "expiration_date": "2025-10-02T10:12:00Z",
                "registrar": "NameCheap, Inc.",
                "status": ["clientTransferProhibited"],
                "privacy_guard": True
            },
            [{"claim": "rdap", "source": "rdap", "retrieved_at": "2026-11-06T12:00:00Z", "raw_response_sha256": "bbb"}]
        )
        mock_ct.return_value = (
            {"cert_count": 1, "subdomains": [], "issuers": ["Let's Encrypt"], "latest_logged_date": "2024-10-03T08:42:00"},
            [{"claim": "ct", "source": "crt.sh", "retrieved_at": "2026-11-06T12:00:00Z", "raw_response_sha256": "ccc"}]
        )

        out = run("example-suspicious.com", passive_only=True)
        # Strictly validate with JSON Schema
        jsonschema.validate(instance=out, schema=schema)

        assert out["ok"] is True
        assert out["domain"] == "example-suspicious.com"
        assert out["whois"]["registrar"] == "NameCheap, Inc."
        assert out["whois"]["privacy_guard"] == "Enabled"
        assert out["whois"]["status"] == "clientTransferProhibited"
        assert len(out["evidence_timeline"]) >= 3
        assert len(out["audit_trail"]) >= 5


def test_schema_json_conformance_live():
    """Verify that live query output for google.com validates strictly against schema.json."""
    import jsonschema
    schema_file = ROOT / "skills" / "investigation" / "domain-whois-osint" / "schema.json"
    schema = json.loads(schema_file.read_text(encoding="utf-8"))

    out = run("google.com", passive_only=True, timeout=10.0)
    jsonschema.validate(instance=out, schema=schema)

    assert out["ok"] is True
    assert out["risk_level"] in ["Low Risk", "Moderate Risk", "High Risk"]
    assert out["confidence"] in ["Low", "Medium", "High"]
    assert isinstance(out["response_time_sec"], float)
    assert len(out["whois"]["name_servers"]) > 0

