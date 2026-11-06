"""
Deterministic Unit & Integration Tests for Email OSINT Skill v1.5.0
Mocked DNS and HTTP interfaces with frozen time testing. Zero network flakiness.
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

# Dynamically load email-osint run.py module
skill_file = ROOT / "skills" / "investigation" / "email-osint" / "run.py"
spec = importlib.util.spec_from_file_location("email_osint", str(skill_file))
email_mod = importlib.util.module_from_spec(spec)
sys.modules["email_osint"] = email_mod
spec.loader.exec_module(email_mod)

run = email_mod.run
normalize_email = email_mod.normalize_email
validate_email_syntax = email_mod.validate_email_syntax
resolve_mx_records = email_mod.resolve_mx_records
classify_provider = email_mod.classify_provider
lookup_gravatar = email_mod.lookup_gravatar


# =====================================================================
# Group 1: Syntax Validation & Decomposition Tests (Zero Network)
# =====================================================================

def test_email_valid_syntax():
    valid_emails = [
        "investigate.target@gmail.com",
        "user.name+tag@sub.example.co.th",
        "simple@domain.org",
        "user_name-123@company.co",
    ]
    for em in valid_emails:
        is_valid, local, domain, base, tag = validate_email_syntax(normalize_email(em))
        assert is_valid is True
        assert len(domain) > 0
        assert len(local) > 0


def test_email_subaddress_extraction():
    em = "alice+investigation01@proton.me"
    is_valid, local, domain, base, tag = validate_email_syntax(normalize_email(em))
    assert is_valid is True
    assert local == "alice+investigation01"
    assert base == "alice"
    assert tag == "investigation01"
    assert domain == "proton.me"


def test_email_invalid_syntax_rejection():
    invalid_cases = [
        "not_an_email",
        "@domain.com",
        "user@",
        "user@@domain.com",
        "user@domain..com",
        ".user@domain.com",
        "user.@domain.com",
        "user@.domain.com",
        "",
        "a" * 250 + "@domain.com",  # Exceeds total length
    ]
    for inv in invalid_cases:
        res = run(inv, passive_only=True)
        assert res["ok"] is True
        assert res["valid_format"] is False
        assert len(res["mx_records"]) == 0
        assert res["has_gravatar"] is False


def test_email_opsec_passive_only_violation():
    with pytest.raises(ValueError, match="OPSEC violation"):
        run("target@example.com", passive_only=False)


# =====================================================================
# Group 2: Disposable Domain & Provider Classification Tests
# =====================================================================

def test_email_disposable_domain_detection():
    disposable_cases = [
        "victim@10minutemail.com",
        "scammer@mailinator.com",
        "bot@guerrillamail.com",
        "burner@trashmail.com",
        "temp@temp-mail.org",
        "fake@yopmail.com",
    ]
    for disp in disposable_cases:
        res = run(disp, passive_only=True)
        assert res["ok"] is True
        assert res["valid_format"] is True
        assert res["is_disposable"] is True
        assert res["classification"]["provider_type"] == "disposable"


def test_email_free_provider_classification():
    webmail_cases = [
        ("user@gmail.com", "Google Workspace / Gmail"),
        ("user@outlook.com", "Microsoft Outlook / Hotmail"),
        ("user@yahoo.com", "Yahoo Mail"),
        ("user@proton.me", "ProtonMail (End-to-End Encrypted)"),
        ("user@icloud.com", "Apple iCloud Mail"),
    ]
    for em, expected_infra in webmail_cases:
        res = run(em, passive_only=True)
        assert res["ok"] is True
        assert res["valid_format"] is True
        assert res["is_disposable"] is False
        assert res["is_free_provider"] is True
        assert res["provider_type"] == "consumer_webmail"
        assert res["infrastructure"] == expected_infra


# =====================================================================
# Group 3: Mocked DNS MX Resolution Tests
# =====================================================================

@freeze_time("2026-11-06 12:00:00")
@patch("dns.resolver.Resolver.resolve")
@patch("requests.get")
def test_email_mx_lookup_mocked(mock_requests, mock_resolve):
    # Mock Gravatar 404
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_requests.return_value = mock_resp

    # Mock MX resolution with unordered preferences
    mock_mx1 = MagicMock()
    mock_mx1.preference = 20
    mock_mx1.exchange.to_text.return_value = "alt.mail.example.com."

    mock_mx2 = MagicMock()
    mock_mx2.preference = 10
    mock_mx2.exchange.to_text.return_value = "mail.example.com."

    mock_resolve.return_value = [mock_mx1, mock_mx2]

    res = run("officer@example.com", passive_only=True)

    assert res["ok"] is True
    assert res["valid_format"] is True
    assert res["has_mx_records"] is True
    assert res["domain_exists"] is True
    assert len(res["mx_records"]) == 2
    # Verify sorted preference
    assert res["mx_records"][0] == "10 mail.example.com"
    assert res["mx_records"][1] == "20 alt.mail.example.com"
    assert res["mx_servers"][0]["preference"] == 10
    assert res["mx_servers"][0]["exchange"] == "mail.example.com"


@freeze_time("2026-11-06 12:00:00")
@patch("dns.resolver.Resolver.resolve")
@patch("requests.get")
def test_email_mx_nxdomain_mocked(mock_requests, mock_resolve):
    import dns.resolver
    mock_resolve.side_effect = dns.resolver.NXDOMAIN()

    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_requests.return_value = mock_resp

    res = run("target@nonexistent-fake-domain-123456.org", passive_only=True)

    assert res["ok"] is True
    assert res["valid_format"] is True
    assert res["has_mx_records"] is False
    assert res["domain_exists"] is False
    assert len(res["mx_records"]) == 0


@freeze_time("2026-11-06 12:00:00")
@patch("dns.resolver.Resolver.resolve")
@patch("requests.get")
def test_email_implicit_a_fallback_mocked(mock_requests, mock_resolve):
    import dns.resolver

    # MX query raises NoAnswer, A query returns IP
    def side_effect(domain, rtype):
        if rtype == "MX":
            raise dns.resolver.NoAnswer()
        elif rtype == "A":
            mock_a = MagicMock()
            mock_a.to_text.return_value = "93.184.216.34"
            return [mock_a]
        raise dns.resolver.NXDOMAIN()

    mock_resolve.side_effect = side_effect

    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_requests.return_value = mock_resp

    res = run("target@custom-mail-server.com", passive_only=True)

    assert res["ok"] is True
    assert res["has_mx_records"] is True
    assert len(res["mx_records"]) == 1
    assert "0 custom-mail-server.com" in res["mx_records"][0]
    assert "implicit" in res["mx_servers"][0].get("note", "").lower()


@patch("dns.resolver.Resolver.resolve")
@patch("requests.get")
def test_email_corporate_infrastructure_detection(mock_requests, mock_resolve):
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_requests.return_value = mock_resp

    mock_mx = MagicMock()
    mock_mx.preference = 1
    mock_mx.exchange.to_text.return_value = "enterprise-domain.mail.protection.outlook.com."
    mock_resolve.return_value = [mock_mx]

    res = run("ceo@enterprise-corp.com", passive_only=True)

    assert res["ok"] is True
    assert res["is_disposable"] is False
    assert res["is_free_provider"] is False
    assert res["provider_type"] == "corporate_custom"
    assert "Microsoft 365" in res["infrastructure"]


@patch("dns.resolver.Resolver.resolve")
@patch("requests.get")
def test_email_disposable_mx_routing(mock_requests, mock_resolve):
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_requests.return_value = mock_resp

    mock_mx = MagicMock()
    mock_mx.preference = 10
    mock_mx.exchange.to_text.return_value = "mail.mailinator.com."
    mock_resolve.return_value = [mock_mx]

    res = run("scam@obscure-custom-domain.xyz", passive_only=True)

    assert res["ok"] is True
    assert res["is_disposable"] is True
    assert res["classification"]["provider_type"] == "disposable"


# =====================================================================
# Group 4: Mocked Gravatar Profile & Avatar Tests
# =====================================================================

@freeze_time("2026-11-06 12:00:00")
@patch("requests.get")
@patch("email_osint.resolve_mx_records")
def test_email_gravatar_found_mocked(mock_mx, mock_requests):
    mock_mx.return_value = (["10 mail.example.com"], [{"preference": 10, "exchange": "mail.example.com"}], True, True, [])

    def mock_get(url, **kwargs):
        resp = MagicMock()
        if "/avatar/" in url:
            resp.status_code = 200
            resp.content = b"FAKE_AVATAR_PNG_BYTES"
            return resp
        elif ".json" in url:
            resp.status_code = 200
            resp.content = json.dumps({
                "entry": [{
                    "preferredUsername": "targetuser",
                    "displayName": "Target Investigator",
                    "profileUrl": "https://gravatar.com/targetuser"
                }]
            }).encode("utf-8")
            resp.json.return_value = {
                "entry": [{
                    "preferredUsername": "targetuser",
                    "displayName": "Target Investigator",
                    "profileUrl": "https://gravatar.com/targetuser"
                }]
            }
            return resp
        resp.status_code = 404
        return resp

    mock_requests.side_effect = mock_get

    res = run("targetuser@example.com", passive_only=True)

    assert res["ok"] is True
    assert res["has_gravatar"] is True
    assert len(res["gravatar_hash"]) == 64
    assert res["gravatar_profile"]["profile_exists"] is True
    assert res["gravatar_profile"]["display_name"] == "Target Investigator"
    assert res["gravatar_profile"]["username"] == "targetuser"


@freeze_time("2026-11-06 12:00:00")
@patch("requests.get")
@patch("email_osint.resolve_mx_records")
def test_email_gravatar_404_clean_mocked(mock_mx, mock_requests):
    mock_mx.return_value = (["10 mail.example.com"], [{"preference": 10, "exchange": "mail.example.com"}], True, True, [])

    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_requests.return_value = mock_resp

    res = run("unknown_user_clean_404@example.com", passive_only=True)

    assert res["ok"] is True
    assert res["has_gravatar"] is False
    assert res["gravatar_profile"]["profile_exists"] is False
    assert res["gravatar_profile"]["avatar_exists"] is False


# =====================================================================
# Group 5: Evidence & Executor Conformance
# =====================================================================

@freeze_time("2026-11-06 12:00:00")
@patch("requests.get")
@patch("dns.resolver.Resolver.resolve")
def test_email_evidence_envelope_and_frozen_time(mock_resolve, mock_requests):
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_requests.return_value = mock_resp

    mock_mx = MagicMock()
    mock_mx.preference = 10
    mock_mx.exchange.to_text.return_value = "mail.test.com."
    mock_resolve.return_value = [mock_mx]

    res = run("case.officer@test.com", passive_only=True)

    assert res["ok"] is True
    assert res["timestamp_utc"] == "2026-11-06T12:00:00Z"
    assert len(res["evidence"]) >= 3

    for ev in res["evidence"]:
        assert "claim" in ev
        assert "source" in ev
        assert "query" in ev
        assert "timestamp" in ev
        assert "retrieved_at" in ev
        assert "response_sha256" in ev
        assert "raw_response_sha256" in ev
        assert len(ev["response_sha256"]) == 64


def test_executor_runs_email_osint():
    from core.registry import Registry
    from core.executor import Executor

    reg = Registry(ROOT / "skills")
    skill = reg.get("email-osint")
    assert skill is not None
    assert skill.status == "runnable"

    res = Executor().run(skill, {"email": "invalid_email_format", "passive_only": True})
    assert res["ok"] is True
    assert res["valid_format"] is False
