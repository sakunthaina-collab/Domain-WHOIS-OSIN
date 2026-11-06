"""Deterministic regressions for FIND-05..FIND-08."""
import json
import pathlib
import pytest

from core.executor import (
    Executor,
    _is_allowed_bin,
    _resolve_within,
    _validate_http_url,
)
from core.guardrails import Guardrails, verify_audit_chain


class _Skill:
    def __init__(self, runtime=None, dir=None, name="s"):
        self.name, self.risk, self.category = name, "low", "test"
        self.runtime = runtime or {}
        self.dir = dir


# ── FIND-05 ─────────────────────────────────────────────
@pytest.mark.parametrize(
    "name",
    [
        "rm.exe", "del.cmd", "cmd.exe", "powershell.exe", "pwsh.exe",
        "bash.exe", "sh.exe", "curl.exe", "wget.exe", "nc.exe",
        "npx", "npx.cmd", "uvx",
    ],
)
def test_find05_denied_bins(name):
    assert _is_allowed_bin(name) is False


@pytest.mark.parametrize(
    "name",
    [
        "python", "python3", "py", "node", "uv",
        "python.exe", "python3.EXE", "node.cmd",
    ],
)
def test_find05_allowed_bins(name):
    assert _is_allowed_bin(name) is True


def test_find05_interpreter_requires_script(tmp_path):
    skill_dir = tmp_path / "s"
    skill_dir.mkdir()
    ex = Executor()
    skill = _Skill(
        runtime={"type": "cli", "bin": "python", "args": []},
        dir=skill_dir,
    )
    r = ex.run(skill, {})
    assert r.get("blocked") is True
    assert "script" in r["error"].lower()


def test_find05_uv_requires_run_subcommand(tmp_path):
    skill_dir = tmp_path / "s"
    skill_dir.mkdir()
    (skill_dir / "x.py").write_text("", encoding="utf-8")
    ex = Executor()
    skill = _Skill(
        runtime={"type": "cli", "bin": "uv", "args": ["--from", "evil", "x.py"]},
        dir=skill_dir,
    )
    r = ex.run(skill, {})
    assert r.get("blocked") is True


# ── FIND-06 ─────────────────────────────────────────────
@pytest.mark.parametrize(
    "evil",
    [
        "../evil.py", "../../etc/passwd", "/etc/passwd",
        "..\\..\\win\\cmd.exe", "skills/../../../x",
    ],
)
def test_find06_traversal_blocked(tmp_path, evil):
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    with pytest.raises(ValueError, match="Path traversal"):
        _resolve_within(skill_dir, evil)


def test_find06_null_byte_blocked(tmp_path):
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    with pytest.raises(ValueError, match="Null byte"):
        _resolve_within(skill_dir, "ok\x00evil")


# ── FIND-07 ─────────────────────────────────────────────
@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/x",
        "gopher://example.com/x",
    ],
)
def test_find07_non_http_scheme(url):
    with pytest.raises(ValueError, match="Scheme"):
        _validate_http_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://100.100.100.200/",
    ],
)
def test_find07_metadata_always_blocked(url):
    with pytest.raises(ValueError, match="metadata"):
        _validate_http_url(url, allow_local=True)


def test_find07_loopback_default_blocked():
    with pytest.raises(ValueError, match="Blocked destination"):
        _validate_http_url("http://127.0.0.1:8000/")


# ── FIND-08 ─────────────────────────────────────────────
def test_find08_binary_garbage_no_crash(tmp_path):
    path = tmp_path / "a.jsonl"
    path.write_bytes(b"\xff\xfe\x00\x00garbage\x80\x81")
    ok, msg = verify_audit_chain(str(path))
    assert ok is False
    assert "UTF-8" in msg or "JSON" in msg


def test_find08_utf8_bom_ok(tmp_path):
    path = tmp_path / "a.jsonl"
    g = Guardrails(str(path))
    g.audit(_Skill(), {"a": 1}, step=0, case_id="c1")
    raw = path.read_bytes()
    path.write_bytes(b"\xef\xbb\xbf" + raw)
    ok, msg = verify_audit_chain(str(path))
    assert ok, msg


def test_find08_mid_file_corruption_detected(tmp_path):
    path = tmp_path / "a.jsonl"
    g = Guardrails(str(path))
    for i in range(3):
        g.audit(_Skill(), {"i": i}, step=i, case_id="c1")
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1][:10] + "\xff" + lines[1][10:]
    path.write_text("\n".join(lines), encoding="utf-8", errors="replace")
    ok, msg = verify_audit_chain(str(path))
    # must fail — either JSON parse error, entry_hash mismatch, or UTF-8 error
    assert not ok


@pytest.mark.parametrize("scalar_line", ["0", "null", "true", "[]", '"hello"'])
def test_find08_non_dict_json_line_no_crash(tmp_path, scalar_line):
    """Falsifying example from Hypothesis Round 2: blob=b'0'."""
    path = tmp_path / "a.jsonl"
    path.write_text(scalar_line + "\n", encoding="utf-8")
    ok, msg = verify_audit_chain(str(path))
    assert ok is False
    assert "object" in msg
