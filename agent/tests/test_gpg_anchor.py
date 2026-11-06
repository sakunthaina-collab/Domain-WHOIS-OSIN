"""GPG-signed anchor tests (9)."""
from __future__ import annotations
import json
import os
import pathlib
import subprocess
import sys
import pytest

AGENT_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

from core.anchor import Anchor
from core.gpg_signer import GPGError, GPGSigner, _to_gpg_path
from core.guardrails import Guardrails
from conftest_gpg import _base_gpg_keyring, gpg_keyring, gpg_signer  # noqa: F401

VERIFY_SCRIPT = (
    pathlib.Path("scripts/verify_audit.py")
    if pathlib.Path("scripts/verify_audit.py").exists()
    else AGENT_DIR / "scripts" / "verify_audit.py"
)


class FakeSkill:
    name, risk, category = "test-skill", "low", "test"


# ── 1. sign + verify ledger ─────────────────────────────
def test_sign_and_verify_ledger(tmp_path, gpg_signer):
    audit = tmp_path / "audit.jsonl"
    ledger = tmp_path / "ledger.json"
    g = Guardrails(str(audit))
    for i in range(3):
        g.audit(FakeSkill(), {"i": i}, step=i, case_id="c1")

    a = Anchor(
        adapter="file",
        ledger_path=str(ledger),
        gpg_signer=gpg_signer,
        path=str(tmp_path / "anchors"),
    )
    rec = a.anchor("c1", str(audit))

    assert rec["signed"] is True
    assert rec["sig_path"] is not None
    assert pathlib.Path(rec["sig_path"]).exists()

    sig = ledger.with_suffix(ledger.suffix + ".asc")
    ok, msg = gpg_signer.verify_file(sig, ledger)
    assert ok, msg


# ── 2. tampered ledger detected ─────────────────────────
def test_tampered_ledger_detected(tmp_path, gpg_signer):
    audit = tmp_path / "audit.jsonl"
    ledger = tmp_path / "ledger.json"
    g = Guardrails(str(audit))
    g.audit(FakeSkill(), {}, step=0, case_id="c1")

    a = Anchor(
        adapter="file",
        ledger_path=str(ledger),
        gpg_signer=gpg_signer,
        path=str(tmp_path / "anchors"),
    )
    a.anchor("c1", str(audit))

    # tamper ledger
    entries = json.loads(ledger.read_text(encoding="utf-8"))
    entries[0]["head_hash"] = "f" * 64
    ledger.write_text(json.dumps(entries, indent=2), encoding="utf-8")

    sig = ledger.with_suffix(ledger.suffix + ".asc")
    ok, msg = gpg_signer.verify_file(sig, ledger)
    assert not ok
    assert "BAD" in msg or "error" in msg.lower()


# ── 3. verify_audit.py detects invalid signature ────────
def test_verify_audit_detects_bad_signature(tmp_path, gpg_signer):
    audit = tmp_path / "audit.jsonl"
    ledger = tmp_path / "ledger.json"
    g = Guardrails(str(audit))
    for i in range(2):
        g.audit(FakeSkill(), {}, step=i, case_id="c1")

    a = Anchor(
        adapter="file",
        ledger_path=str(ledger),
        gpg_signer=gpg_signer,
        path=str(tmp_path / "anchors"),
    )
    a.anchor("c1", str(audit))

    # tamper non-head field so step 4 passes and step 5 (GPG check) triggers exit 4
    entries = json.loads(ledger.read_text(encoding="utf-8"))
    entries[0]["anchored_iso"] = "1999-01-01T00:00:00Z"
    ledger.write_text(json.dumps(entries, indent=2), encoding="utf-8")

    env = os.environ.copy()
    if gpg_signer.gpg_home:
        env["GNUPGHOME"] = str(gpg_signer.gpg_home)

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
        env=env,
    )
    assert rc.returncode in (2, 4), rc.stdout + rc.stderr


# ── 4. strict mode fails if gpg unavailable ─────────────
def test_strict_mode_requires_gpg(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "")  # no gpg
    s = GPGSigner(strict=True)
    assert not s.is_available()
    with pytest.raises(GPGError):
        s.require()


# ── 5. non-strict fallback does not raise ───────────────
def test_non_strict_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "")
    s = GPGSigner(strict=False)
    assert not s.is_available()
    s.require()  # no-op in non-strict mode


# ── 6. unsigned ledger when non-strict + no gpg ─────────
def test_unsigned_ledger_non_strict(tmp_path):
    audit = tmp_path / "audit.jsonl"
    ledger = tmp_path / "ledger.json"
    g = Guardrails(str(audit))
    g.audit(FakeSkill(), {}, step=0, case_id="c1")

    s = GPGSigner(strict=False)
    s.gpg_bin = None

    a = Anchor(
        adapter="file",
        ledger_path=str(ledger),
        gpg_signer=s,
        path=str(tmp_path / "anchors"),
    )
    rec = a.anchor("c1", str(audit))
    assert rec["signed"] is False


# ── 7. git tag signed ───────────────────────────────────
def test_git_tag_signed(tmp_path, gpg_signer):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@e.org"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=repo, check=True)
    (repo / "README").write_text("test", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=repo, check=True)

    ledger = repo / "ledger.json"
    ledger.write_text('{"test": 1}', encoding="utf-8")
    subprocess.run(["git", "add", "ledger.json"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "ledger"], cwd=repo, check=True)

    ok = gpg_signer.sign_git_tag("anchor/c1/abcd1234", "test anchor", repo)
    assert ok, "git tag -s failed"

    verify_ok, detail = gpg_signer.verify_git_tag("anchor/c1/abcd1234", repo)
    assert verify_ok, detail
    assert "Good signature" in detail or "valid" in detail


# ── 8. verify_audit --strict-gpg with no signature ──────
def test_verify_audit_strict_gpg_no_sig(tmp_path):
    audit = tmp_path / "audit.jsonl"
    ledger = tmp_path / "ledger.json"
    g = Guardrails(str(audit))
    g.audit(FakeSkill(), {}, step=0, case_id="c1")

    a = Anchor(
        adapter="file",
        ledger_path=str(ledger),
        gpg_signer=None,
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
            "--strict-gpg",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert rc.returncode == 5, rc.stdout + rc.stderr


# ── 9. public key export/import ─────────────────────────
def test_export_import_public_key(tmp_path, gpg_keyring):
    import shutil
    import tempfile
    import uuid

    gpg_bin = gpg_keyring["gpg_bin"]
    pub = subprocess.run(
        [gpg_bin, "--armor", "--export", gpg_keyring["fingerprint"]],
        env=gpg_keyring["env"],
        capture_output=True,
        text=True,
        check=True,
    )
    pub_path = tmp_path / "pub.asc"
    pub_path.write_text(pub.stdout, encoding="utf-8")

    new_home = pathlib.Path(tempfile.gettempdir()) / f"gpg_imp_{uuid.uuid4().hex[:8]}"
    new_home.mkdir(mode=0o700, exist_ok=True)
    try:
        new_env = gpg_keyring["env"].copy()
        new_env["GNUPGHOME"] = _to_gpg_path(new_home, gpg_bin)
        subprocess.run(
            [gpg_bin, "--import", _to_gpg_path(pub_path, gpg_bin)],
            env=new_env,
            check=True,
            capture_output=True,
        )

        out = subprocess.run(
            [gpg_bin, "--list-keys", "--with-colons"],
            env=new_env,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        assert gpg_keyring["fingerprint"] in out
    finally:
        shutil.rmtree(new_home, ignore_errors=True)
