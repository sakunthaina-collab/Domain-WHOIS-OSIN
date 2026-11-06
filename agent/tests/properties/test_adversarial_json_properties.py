"""Adversarial JSON properties (FIND-08 + FIND-04 anchored proof)."""
import json
import pathlib
import subprocess
import sys
import uuid
import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from core.anchor import Anchor
from core.guardrails import Guardrails, verify_audit_chain

AGENT_DIR = pathlib.Path(__file__).resolve().parents[2]
VERIFY_SCRIPT = (
    pathlib.Path("scripts/verify_audit.py")
    if pathlib.Path("scripts/verify_audit.py").exists()
    else AGENT_DIR / "scripts" / "verify_audit.py"
)

_COMMON_SETTINGS = dict(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)


class _FakeSkill:
    name, risk, category = "x", "low", "test"


# ══════════════════════════════════════════════════════════
# Property 1 (FIND-08): corrupted bytes never crash verifier
# ══════════════════════════════════════════════════════════
@settings(**_COMMON_SETTINGS)
@given(blob=st.binary(min_size=1, max_size=500))
def test_corrupted_bytes_never_crash_verifier(tmp_path, blob):
    path = tmp_path / f"a_{uuid.uuid4().hex[:8]}.jsonl"
    path.write_bytes(blob)
    # must return (False, reason) — never raise
    ok, msg = verify_audit_chain(str(path))
    assert isinstance(ok, bool)
    assert isinstance(msg, str)
    if ok:
        # only OK if blob happened to be valid UTF-8 whitespace (or BOM+whitespace)
        assert blob.decode("utf-8-sig", errors="ignore").strip() == ""


def test_utf8_bom_accepted(tmp_path):
    path = tmp_path / "a.jsonl"
    g = Guardrails(str(path))
    g.audit(_FakeSkill(), {}, step=0, case_id="c1")
    raw = path.read_bytes()
    path.write_bytes(b"\xef\xbb\xbf" + raw)  # prepend UTF-8 BOM
    ok, msg = verify_audit_chain(str(path))
    assert ok, f"BOM should be tolerated: {msg}"


def test_blank_lines_tolerated(tmp_path):
    path = tmp_path / "a.jsonl"
    g = Guardrails(str(path))
    g.audit(_FakeSkill(), {}, step=0, case_id="c1")
    g.audit(_FakeSkill(), {}, step=1, case_id="c1")
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n\n" + "\n\n".join(lines) + "\n\n", encoding="utf-8")
    ok, msg = verify_audit_chain(str(path))
    assert ok, f"blank lines should be tolerated: {msg}"


# ══════════════════════════════════════════════════════════
# Property 2 (FIND-04): anchored chain ALWAYS detects tail deletion
# ══════════════════════════════════════════════════════════
@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
@given(
    initial_n=st.integers(min_value=2, max_value=10),
    delete_k=st.integers(min_value=1, max_value=10),
)
def test_find04_anchored_detects_tail_deletion(tmp_path, initial_n, delete_k):
    if delete_k >= initial_n:
        return  # can't delete more than exist and still be a chain prefix
    sub = tmp_path / uuid.uuid4().hex[:8]
    sub.mkdir(parents=True, exist_ok=True)
    audit = sub / "a.jsonl"
    ledger = sub / "ledger.json"
    g = Guardrails(str(audit))
    for i in range(initial_n):
        g.audit(_FakeSkill(), {"i": i}, step=i, case_id="c1")
    Anchor(
        adapter="file",
        ledger_path=str(ledger),
        path=str(sub / "anchors"),
    ).anchor("c1", str(audit))

    # delete last k entries
    lines = audit.read_text(encoding="utf-8").splitlines()
    audit.write_text("\n".join(lines[:-delete_k]) + "\n", encoding="utf-8")

    rc = subprocess.run(
        [sys.executable, str(VERIFY_SCRIPT), str(audit), "c1", str(ledger)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert rc.returncode == 2, (
        f"tail deletion must be detected (got {rc.returncode}): {rc.stdout}"
    )


# ══════════════════════════════════════════════════════════
# Property 3: concurrent writes — no deadlock, no loss
# ══════════════════════════════════════════════════════════
@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
@given(
    n_threads=st.integers(min_value=1, max_value=5),
    n_each=st.integers(min_value=1, max_value=10),
)
def test_concurrent_lock_no_deadlock_or_loss(tmp_path, n_threads, n_each):
    import threading
    path = tmp_path / f"a_{uuid.uuid4().hex[:8]}.jsonl"
    errors = []

    def worker(k):
        try:
            g = Guardrails(str(path))
            for i in range(n_each):
                g.audit(_FakeSkill(), {"t": k, "i": i}, step=i, case_id="c1")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(k,)) for k in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not any(t.is_alive() for t in threads), "deadlock detected"
    assert not errors, f"worker errors: {errors}"
    total = len(path.read_text(encoding="utf-8").splitlines())
    assert total == n_threads * n_each
    ok, msg = verify_audit_chain(str(path))
    assert ok, msg


# ══════════════════════════════════════════════════════════
# Property 4: anchored chain detects ANY prefix truncation
# ══════════════════════════════════════════════════════════
@settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
@given(delete_k=st.integers(min_value=1, max_value=8))
def test_anchored_truncation_always_caught(tmp_path, delete_k):
    n = delete_k + 2  # always leave at least 2
    sub = tmp_path / uuid.uuid4().hex[:8]
    sub.mkdir(parents=True, exist_ok=True)
    audit = sub / "a.jsonl"
    ledger = sub / "ledger.json"
    g = Guardrails(str(audit))
    for i in range(n):
        g.audit(_FakeSkill(), {"i": i}, step=i, case_id="c1")
    Anchor(
        adapter="file",
        ledger_path=str(ledger),
        path=str(sub / "anchors"),
    ).anchor("c1", str(audit))

    lines = audit.read_text(encoding="utf-8").splitlines()
    audit.write_text("\n".join(lines[: n - delete_k]) + "\n", encoding="utf-8")
    rc = subprocess.run(
        [sys.executable, str(VERIFY_SCRIPT), str(audit), "c1", str(ledger)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert rc.returncode == 2, rc.stdout + rc.stderr
