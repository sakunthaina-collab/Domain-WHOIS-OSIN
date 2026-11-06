#!/usr/bin/env python3
"""Verify hash chain AND external anchor.

Exit codes:
  0  OK
  1  chain broken / tampered
  2  truncated / deleted (anchor mismatch or zero-entry trap)
  3  usage error
"""
from __future__ import annotations
import json
import pathlib
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from core.guardrails import verify_audit_chain


def _load_last_anchor(ledger_path: pathlib.Path, case_id: str):
    if not ledger_path.exists():
        return None
    try:
        entries = json.loads(ledger_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    matches = [e for e in entries if e.get("case_id") == case_id]
    return matches[-1] if matches else None


def _read_chain_head(audit_path: pathlib.Path) -> tuple[str, int]:
    if not audit_path.exists() or audit_path.stat().st_size == 0:
        return "0" * 64, 0
    count, last = 0, "0" * 64
    with audit_path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                last = json.loads(line)["entry_hash"]
                count += 1
            except (json.JSONDecodeError, KeyError):
                continue
    return last, count


def _verify_internal(audit_path: str, ledger_path: str | None = None, case_id: str | None = None) -> tuple[bool, str, int]:
    ap = pathlib.Path(audit_path)

    # If no case_id supplied, run chain verification only
    if not case_id:
        ok, msg = verify_audit_chain(str(ap))
        return ok, msg, (0 if ok else 1)

    lp = pathlib.Path(ledger_path or "logs/anchor_ledger.json")

    # ── 1) anchor lookup ─────────────────────────────────
    anchor = _load_last_anchor(lp, case_id)
    if anchor is None:
        ok, msg = verify_audit_chain(str(ap))
        return ok, f"ℹ️  no anchor for case {case_id} (chain-only verification): {msg}", (0 if ok else 1)

    # ── 2) ZERO-ENTRY TRAP: audit missing/empty but anchor exists ──
    head, count = _read_chain_head(ap)
    if count == 0:
        msg = (
            f"🚨 ZERO-ENTRY TRAP: audit log empty/missing "
            f"but anchor exists (expected n={anchor['entry_count']}, "
            f"head={anchor['head_hash'][:16]}...)"
        )
        return False, msg, 2

    # ── 3) hash-chain integrity ──────────────────────────
    ok, msg = verify_audit_chain(str(ap))
    if not ok:
        return False, f"❌ CHAIN BROKEN: {msg}", 1

    # ── 4) entry count match (truncation detection) ──────
    if count != anchor["entry_count"]:
        msg = (
            f"🚨 TRUNCATION: chain has {count} entries, "
            f"anchor expected {anchor['entry_count']}"
        )
        return False, msg, 2

    # ── 5) head hash match ───────────────────────────────
    if head != anchor["head_hash"]:
        msg = (
            f"🚨 HEAD MISMATCH: chain head={head[:16]}..., "
            f"anchor={anchor['head_hash'][:16]}..."
        )
        return False, msg, 2

    return True, (
        f"✅ OK — {count} entries verified, "
        f"head matches anchor ({anchor.get('adapter', 'unknown')}, "
        f"{anchor.get('anchored_iso', '')})"
    ), 0


def verify(audit_path: str, ledger_path: str | None = None, case_id: str | None = None) -> tuple[bool, str]:
    ok, msg, _ = _verify_internal(audit_path, ledger_path, case_id)
    return ok, msg


def main(audit_path: str, ledger_path: str, case_id: str | None = None) -> int:
    ok, msg, code = _verify_internal(audit_path, ledger_path, case_id)
    print(msg)
    return code


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(
            "usage: verify_audit.py <audit.jsonl> [case_id] [ledger=logs/anchor_ledger.json]",
            file=sys.stderr,
        )
        sys.exit(3)

    audit_file = sys.argv[1]
    case = sys.argv[2] if len(sys.argv) > 2 else None
    ledger_file = sys.argv[3] if len(sys.argv) > 3 else "logs/anchor_ledger.json"

    sys.exit(main(audit_file, ledger_file, case))
