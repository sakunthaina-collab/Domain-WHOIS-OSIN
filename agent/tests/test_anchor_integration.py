"""End-to-end: Guardrails → Anchor → verify_audit.py."""
import json
import pathlib
import subprocess
import sys
import pytest

AGENT_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

from core.guardrails import Guardrails
from core.anchor import Anchor

VERIFY_SCRIPT = (
    pathlib.Path("scripts/verify_audit.py")
    if pathlib.Path("scripts/verify_audit.py").exists()
    else AGENT_DIR / "scripts" / "verify_audit.py"
)


class FakeSkill:
    name, risk, category = "x", "low", "test"


def test_full_anchor_roundtrip(tmp_path):
    audit = tmp_path / "audit.jsonl"
    ledger = tmp_path / "ledger.json"
    g = Guardrails(str(audit))
    for i in range(3):
        g.audit(FakeSkill(), {"i": i}, step=i, case_id="c1")
    a = Anchor(
        adapter="file",
        ledger_path=str(ledger),
        path=str(tmp_path / "anchors"),
    )
    a.anchor("c1", str(audit))

    rc = subprocess.run(
        [
            sys.executable,
            str(VERIFY_SCRIPT),
            str(audit),
            "c1",
            str(ledger),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert rc.returncode == 0, rc.stdout + rc.stderr
    assert "matches anchor" in rc.stdout


def test_anchor_updated_after_new_entries(tmp_path):
    audit = tmp_path / "audit.jsonl"
    ledger = tmp_path / "ledger.json"
    g = Guardrails(str(audit))
    for i in range(2):
        g.audit(FakeSkill(), {"i": i}, step=i, case_id="c1")
    a = Anchor(
        adapter="file",
        ledger_path=str(ledger),
        path=str(tmp_path / "anchors"),
    )
    a.anchor("c1", str(audit))

    # add more entries — old anchor must now mismatch
    for i in range(2, 5):
        g.audit(FakeSkill(), {"i": i}, step=i, case_id="c1")
    rc = subprocess.run(
        [
            sys.executable,
            str(VERIFY_SCRIPT),
            str(audit),
            "c1",
            str(ledger),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert rc.returncode == 2
    assert "TRUNCATION" in rc.stdout or "HEAD MISMATCH" in rc.stdout
