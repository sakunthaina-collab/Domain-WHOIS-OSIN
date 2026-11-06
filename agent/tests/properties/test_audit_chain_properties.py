# tests/properties/test_audit_chain_properties.py
"""Property-based tests for core/guardrails.py audit hash chain."""
from __future__ import annotations
import json
import pathlib
from types import SimpleNamespace
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from core.guardrails import Guardrails, verify_audit_chain
from tests.properties.strategies import strategy_audit_entries

def _make_dummy_skill(name: str):
    return SimpleNamespace(name=name, category="investigation", risk="low")

# ---------------------------------------------------------------------------
# Property 1: Any legitimately constructed chain passes verification
# ---------------------------------------------------------------------------
@given(entries=strategy_audit_entries(min_entries=1, max_entries=10))
def test_valid_chain_always_passes(tmp_path_factory, entries):
    tmp_dir = tmp_path_factory.mktemp("audit_prop1")
    log_file = tmp_dir / "audit.jsonl"
    guard = Guardrails(log_path=log_file, case_id="CASE-PROP-1")
    
    for step_num, (action, args, res) in enumerate(entries, start=1):
        guard.audit(skill=_make_dummy_skill(action), args=args, step=step_num, result=res)
        
    ok, msg = verify_audit_chain(str(log_file))
    assert ok is True, f"Legitimate audit chain failed verification: {msg}"


# ---------------------------------------------------------------------------
# Property 2: Tampering any single entry causes verification to fail
# ---------------------------------------------------------------------------
@given(
    entries=strategy_audit_entries(min_entries=1, max_entries=10),
    data=st.data(),
)
def test_tamper_any_entry_fails(tmp_path_factory, entries, data):
    tmp_dir = tmp_path_factory.mktemp("audit_prop2")
    log_file = tmp_dir / "audit.jsonl"
    guard = Guardrails(log_path=log_file, case_id="CASE-PROP-2")
    
    for step_num, (action, args, res) in enumerate(entries, start=1):
        guard.audit(skill=_make_dummy_skill(action), args=args, step=step_num, result=res)
        
    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == len(entries)
    
    # Pick a random entry to tamper
    tamper_idx = data.draw(st.integers(min_value=0, max_value=len(lines) - 1))
    target = json.loads(lines[tamper_idx])
    
    # Choose a field to mutate
    field_to_tamper = data.draw(st.sampled_from(["skill", "args_sha256", "result_summary", "ts", "prev_hash"]))
    if field_to_tamper == "skill":
        target["skill"] = target.get("skill", "") + "_TAMPERED"
    elif field_to_tamper == "args_sha256":
        target["args_sha256"] = "1" * 64 if target.get("args_sha256") == "0" * 64 else "0" * 64
    elif field_to_tamper == "result_summary":
        target["result_summary"] = "TAMPERED_RESULT"
    elif field_to_tamper == "ts":
        target["ts"] = (target.get("ts") or 0.0) + 999.0
    elif field_to_tamper == "prev_hash":
        target["prev_hash"] = "1" * 64 if target.get("prev_hash") == "0" * 64 else "0" * 64
        
    lines[tamper_idx] = json.dumps(target)
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    
    ok, msg = verify_audit_chain(str(log_file))
    assert ok is False, f"Tampered entry at idx {tamper_idx} was not detected!"


# ---------------------------------------------------------------------------
# Property 3: Deletion of any internal entry in chain (N >= 3) causes verification to fail
# Note (FIND-04): Pure chain cannot detect tail deletion by design (prefix is valid).
# Tail deletion is caught by external anchor (verify_audit.py).
# ---------------------------------------------------------------------------
@given(
    entries=strategy_audit_entries(min_entries=3, max_entries=10),
    data=st.data(),
)
def test_delete_any_internal_entry_fails(tmp_path_factory, entries, data):
    tmp_dir = tmp_path_factory.mktemp("audit_prop3")
    log_file = tmp_dir / "audit.jsonl"
    guard = Guardrails(log_path=log_file, case_id="CASE-PROP-3")
    
    for step_num, (action, args, res) in enumerate(entries, start=1):
        guard.audit(skill=_make_dummy_skill(action), args=args, step=step_num, result=res)
        
    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    # Delete an internal entry: not the tail (0 <= delete_idx < len(lines) - 1)
    delete_idx = data.draw(st.integers(min_value=0, max_value=len(lines) - 2))
    
    remaining = [line for i, line in enumerate(lines) if i != delete_idx]
    log_file.write_text("\n".join(remaining) + "\n", encoding="utf-8")
    
    ok, msg = verify_audit_chain(str(log_file))
    assert ok is False, f"Deleted internal entry at index {delete_idx} was not detected!"


# ---------------------------------------------------------------------------
# Property 4: Swapping any two entries in chain (N >= 2) causes verification to fail
# ---------------------------------------------------------------------------
@given(
    entries=strategy_audit_entries(min_entries=2, max_entries=8),
    data=st.data(),
)
def test_swap_entries_fails(tmp_path_factory, entries, data):
    tmp_dir = tmp_path_factory.mktemp("audit_prop4")
    log_file = tmp_dir / "audit.jsonl"
    guard = Guardrails(log_path=log_file, case_id="CASE-PROP-4")
    
    for step_num, (action, args, res) in enumerate(entries, start=1):
        guard.audit(skill=_make_dummy_skill(action), args=args, step=step_num, result=res)
        
    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    idx1 = data.draw(st.integers(min_value=0, max_value=len(lines) - 2))
    idx2 = data.draw(st.integers(min_value=idx1 + 1, max_value=len(lines) - 1))
    
    lines[idx1], lines[idx2] = lines[idx2], lines[idx1]
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    
    ok, msg = verify_audit_chain(str(log_file))
    assert ok is False, f"Swapping entries {idx1} and {idx2} was not detected!"
