"""Regression tests for FIND-01 … FIND-04 (v1.4.1 hotfix).

Each test is a minimal counter-example captured by Hypothesis during
the v1.4 fuzzing round, now encoded as a deterministic test.
"""
import json, pathlib, re, subprocess, sys
import pytest

from core.guardrails import Guardrails, verify_audit_chain
from core.normalize import normalize_phone


class FakeSkill:
    name, risk, category = "test-skill", "low", "test"


# ══════════════════════════════════════════════════════════════
# FIND-01 — Unicode digits must convert to ASCII
# ══════════════════════════════════════════════════════════════

@pytest.mark.parametrize("raw,expected", [
    ("660\u0966",                "6600"),        # Devanagari 0
    ("\u0967\u0968\u0969",       "123"),         # Devanagari 1 2 3
    ("66\u0e50\u0e51",           "6601"),        # Thai 0 1
    ("+66\u0668\u0669\u0660",    "+66890"),      # Arabic-Indic 8 9 0
    ("\uff11\uff12\uff13",       "123"),         # Fullwidth 1 2 3 (NFKC)
    ("+66\u06f8\u06f9",          "+6689"),       # Extended Arabic-Indic
])
def test_find01_unicode_digits_to_ascii(raw, expected):
    result = normalize_phone(raw)
    assert result == expected
    assert re.fullmatch(r"\+?[0-9]+", result), \
        f"shape invariant broken: {result!r}"
    assert all(ord(c) < 128 for c in result), \
        f"non-ASCII leaked: {[hex(ord(c)) for c in result]}"


def test_find01_original_counter_example():
    """Exact counter-example from fuzzing: '660०'."""
    raw = "660\u0966"
    result = normalize_phone(raw)
    assert result == "6600"
    assert re.fullmatch(r"\+?[0-9]+", result)


# ══════════════════════════════════════════════════════════════
# FIND-02 — embedded '+' must be removed
# ══════════════════════════════════════════════════════════════

@pytest.mark.parametrize("raw,expected", [
    ("123+456",      "123456"),
    ("+66+89",       "+6689"),
    ("66+89+12",     "668912"),
    ("+66+89+12+34", "+66891234"),
    ("++66",         "+66"),
    ("+",            "+"),
    ("",             ""),
])
def test_find02_embedded_plus_removed(raw, expected):
    assert normalize_phone(raw) == expected


def test_find02_original_counter_example():
    """Exact counter-example from fuzzing: '123+456'."""
    assert normalize_phone("123+456") == "123456"


# ══════════════════════════════════════════════════════════════
# FIND-03 — Unicode line separators must be escaped in JSONL
# ══════════════════════════════════════════════════════════════

@pytest.mark.parametrize("bad_char,name", [
    ("\u0085", "NEL (U+0085)"),
    ("\u2028", "LINE SEPARATOR (U+2028)"),
    ("\u2029", "PARAGRAPH SEPARATOR (U+2029)"),
])
def test_find03_line_separator_in_value(tmp_path, bad_char, name):
    path = tmp_path / "audit.jsonl"
    g = Guardrails(str(path))
    g.audit(FakeSkill(), {"x": f"a{bad_char}b"}, step=0, case_id="c1")
    g.audit(FakeSkill(), {"y": 1}, step=1, case_id="c1")

    content = path.read_text(encoding="utf-8")
    # Critical test: splitlines() must NOT split inside JSON record
    lines = content.splitlines()
    assert len(lines) == 2, \
        f"{name} broke splitlines: got {len(lines)} lines"
    for line in lines:
        json.loads(line)

    # Chain still verifies
    ok, msg = verify_audit_chain(str(path))
    assert ok, msg


def test_find03_original_counter_example(tmp_path):
    """Exact counter-example: args = {'\\x85': None}."""
    path = tmp_path / "audit.jsonl"
    g = Guardrails(str(path))
    g.audit(FakeSkill(), {"\u0085": None}, step=0, case_id="c1")

    content = path.read_text(encoding="utf-8")
    lines = content.splitlines()
    assert len(lines) == 1, f"expected 1 line, got {len(lines)}"
    rec = json.loads(lines[0])
    assert rec["args_sha256"]  # hash computed on original dict


def test_find03_original_data_roundtrips(tmp_path):
    """After escaping, json.loads must recover the original characters."""
    path = tmp_path / "audit.jsonl"
    g = Guardrails(str(path))
    original = {"x": "a\u0085b\u2028c\u2029d"}
    g.audit(FakeSkill(), original, step=0, case_id="c1")

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    import hashlib
    expected_hash = hashlib.sha256(
        json.dumps(original, sort_keys=True, default=str).encode()
    ).hexdigest()
    assert rec["args_sha256"] == expected_hash


# ══════════════════════════════════════════════════════════════
# FIND-04 — pure chain cannot detect tail deletion (by design)
# This test DOCUMENTS the architectural necessity of v1.2 anchor.
# ══════════════════════════════════════════════════════════════

def test_find04_pure_chain_cannot_detect_tail_deletion(tmp_path):
    """Pure hash chain CANNOT detect removal of the last entry.

    Proof: a prefix of a valid chain is still a valid chain.
    This is exactly why v1.2 added external anchoring (Zero-Entry Trap
    + head-hash match). Without an anchor, tail deletion is undetectable.
    """
    path = tmp_path / "a.jsonl"
    g = Guardrails(str(path))
    for i in range(5):
        g.audit(FakeSkill(), {"i": i}, step=i, case_id="c1")

    # Delete last line
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n")

    # EXPECTED: pure chain still verifies (this is the architectural insight)
    ok, _ = verify_audit_chain(str(path))
    assert ok, "by design: pure chain cannot detect tail deletion"


def test_find04_internal_deletion_still_detected(tmp_path):
    """Deleting a MIDDLE entry MUST be detected by pure chain.

    Contrast with tail deletion: internal deletion breaks prev_hash chain.
    """
    path = tmp_path / "a.jsonl"
    g = Guardrails(str(path))
    for i in range(5):
        g.audit(FakeSkill(), {"i": i}, step=i, case_id="c1")

    lines = path.read_text().splitlines()
    del lines[2]  # remove middle entry
    path.write_text("\n".join(lines) + "\n")

    ok, msg = verify_audit_chain(str(path))
    assert not ok, "internal deletion MUST be detectable"
    assert "mismatch" in msg.lower() or "broken" in msg.lower()


# ══════════════════════════════════════════════════════════════
# Meta: all four findings have deterministic regression coverage
# ══════════════════════════════════════════════════════════════

def test_all_findings_have_regression_coverage():
    """Meta-test: ensures every FIND-XX has a corresponding test."""
    import inspect
    module_source = inspect.getsource(sys.modules[__name__])
    for fid in ("FIND-01", "FIND-02", "FIND-03", "FIND-04"):
        assert f"def test_{fid.lower().replace('-', '')}_" in module_source, \
            f"no regression test for {fid}"
