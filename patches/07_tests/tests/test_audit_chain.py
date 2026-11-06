from __future__ import annotations
import json
import pathlib
import sys
import pytest

# Ensure parent directory of tests is importable
AGENT_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

from core.guardrails import Guardrails
from core.registry import Registry
from scripts.verify_audit import verify as verify_audit_log


def test_hash_chain_genesis_and_sequential_linking(tmp_path):
    log_file = tmp_path / "audit_chain.jsonl"
    guard = Guardrails(log_path=log_file)

    class DummySkill:
        name = "test-skill"
        risk = "low"

    skill = DummySkill()

    # Log 3 sequential actions
    r1 = guard.audit(skill, {"arg": 1}, step=1, case_id="C1", result={"status": "ok"})
    r2 = guard.audit(skill, {"arg": 2}, step=2, case_id="C1", result={"status": "ok"}, parent_step=1)
    r3 = guard.audit(skill, {"arg": 3}, step=3, case_id="C1", result={"status": "ok"}, parent_step=2)

    # Check headers
    assert r1["prev_hash"] == "0" * 64
    assert r2["prev_hash"] == r1["entry_hash"]
    assert r3["prev_hash"] == r2["entry_hash"]

    ok, msg = verify_audit_log(log_file)
    assert ok is True
    assert "3 audit entries cryptographically verified" in msg


def test_hash_chain_detects_content_tampering(tmp_path):
    log_file = tmp_path / "audit_chain.jsonl"
    guard = Guardrails(log_path=log_file)

    class DummySkill:
        name = "test-skill"
        risk = "low"

    skill = DummySkill()

    guard.audit(skill, {"arg": 1}, step=1, case_id="C1", result={"status": "ok"})
    guard.audit(skill, {"arg": 2}, step=2, case_id="C1", result={"status": "ok"})

    # Tamper with entry 1
    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    entry = json.loads(lines[0])
    entry["status"] = "tampered"
    lines[0] = json.dumps(entry)
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, msg = verify_audit_log(log_file)
    assert ok is False
    assert "tampered" in msg.lower() or "mismatch" in msg.lower()


def test_hash_chain_detects_entry_deletion(tmp_path):
    log_file = tmp_path / "audit_chain.jsonl"
    guard = Guardrails(log_path=log_file)

    class DummySkill:
        name = "test-skill"
        risk = "low"

    skill = DummySkill()

    guard.audit(skill, {"arg": 1}, step=1, case_id="C1", result={"status": "ok"})
    guard.audit(skill, {"arg": 2}, step=2, case_id="C1", result={"status": "ok"})
    guard.audit(skill, {"arg": 3}, step=3, case_id="C1", result={"status": "ok"})

    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    lines.pop(1)  # Delete middle line
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, msg = verify_audit_log(log_file)
    assert ok is False
    assert "prev_hash mismatch" in msg
