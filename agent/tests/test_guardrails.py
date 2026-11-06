from __future__ import annotations
import json
import pathlib
import sys
import pytest

AGENT_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

from core.guardrails import Guardrails
from core.registry import Profile, Registry
from skills.investigation.phone_email_osint_entry import phone_email_osint


@pytest.fixture
def registry():
    return Registry(AGENT_DIR / "skills")


@pytest.fixture
def guard(tmp_path):
    return Guardrails(log_path=tmp_path / "audit.jsonl")


@pytest.fixture
def profile():
    return Profile.from_yaml(AGENT_DIR / "profiles" / "investigator.yaml")


def test_passive_only_enforced(guard, profile, registry):
    # 1. Direct skill call raises ValueError when passive_only=False
    with pytest.raises(ValueError, match="passive_only"):
        phone_email_osint(target="+66942638165", target_type="phone", passive_only=False)

    # 2. Guardrail gate also blocks passive_only=False before execution
    skill = registry.get("phone-email-osint")
    assert guard.allow(skill, {"target": "+66942638165", "passive_only": False}, profile) is False


def test_high_risk_blocked_without_confirm(guard, profile, registry):
    skill = registry.get("counter-fraud-disruption")
    assert guard.allow(skill, {"case_id": "CASE-001"}, profile) is False
    # Allowed only when explicit _confirmed=True is provided
    assert guard.allow(skill, {"case_id": "CASE-001", "_confirmed": True}, profile) is True


def test_deny_actions_blocked(guard, profile, registry):
    profile["guardrails"]["deny_actions"] = ["phone-email-osint"]
    skill = registry.get("phone-email-osint")
    assert guard.allow(skill, {"target": "+66942638165", "passive_only": True}, profile) is False


def test_audit_log_chain_of_custody_and_result_hash(guard, registry):
    skill = registry.get("phone-email-osint")
    rec = guard.audit(
        skill,
        {"target": "+66942638165", "passive_only": True},
        step=2,
        case_id="CASE-TEST",
        result={"ok": True, "carrier": "TrueMove H"},
        latency_ms=42.5,
        parent_step=1,
    )
    assert rec["status"] == "ok"
    assert rec["parent_step"] == 1
    assert rec["latency_ms"] == 42.5
    assert len(rec["args_sha256"]) == 64
    assert len(rec["result_sha256"]) == 64
    assert "TrueMove H" in str(rec["result_summary"])
    lines = guard.log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    saved = json.loads(lines[0])
    assert saved["result_sha256"] == rec["result_sha256"]
