#!/usr/bin/env python3
"""Verify hash chain + anchor + GPG signatures.

Exit codes:
  0  OK — chain, anchor, and GPG signature all valid
  1  chain broken / tampered
  2  truncated / deleted (anchor mismatch)
  3  usage error
  4  GPG signature INVALID (BADSIG / wrong key)
  5  GPG signature expected but missing (strict mode)
"""
from __future__ import annotations
import json
import pathlib
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from core.gpg_signer import GPGSigner
from core.guardrails import verify_audit_chain


def _load_last_anchor(ledger: pathlib.Path, case_id: str):
    if not ledger.exists():
        return None
    try:
        entries = json.loads(ledger.read_text(encoding="utf-8"))
    except Exception:
        return None
    matches = [e for e in entries if e.get("case_id") == case_id]
    return matches[-1] if matches else None


def _read_head(audit: pathlib.Path) -> tuple[str, int]:
    if not audit.exists() or audit.stat().st_size == 0:
        return "0" * 64, 0
    count, last = 0, "0" * 64
    with audit.open(encoding="utf-8", errors="replace") as f:
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


def _verify_internal(
    audit_path: str,
    ledger_path: str | None = None,
    case_id: str | None = None,
    strict_gpg: bool = False,
) -> tuple[bool, str, int]:
    ap = pathlib.Path(audit_path)

    if not case_id:
        ok, msg = verify_audit_chain(str(ap))
        return ok, msg, (0 if ok else 1)

    lp = pathlib.Path(ledger_path or "logs/anchor_ledger.json")

    # ── 1) anchor lookup ─────────────────────────────────
    anchor = _load_last_anchor(lp, case_id)
    if anchor is None:
        ok, msg = verify_audit_chain(str(ap))
        prefix = "✅ " if ok else "❌ "
        return ok, f"ℹ️  no anchor for case {case_id} (chain-only)\n{prefix}{msg}", (0 if ok else 1)

    # ── 2) zero-entry trap ──────────────────────────────
    head, count = _read_head(ap)
    if count == 0:
        msg = (
            f"🚨 ZERO-ENTRY TRAP: audit empty/missing "
            f"but anchor exists (n={anchor['entry_count']}, "
            f"head={anchor['head_hash'][:16]}...)"
        )
        return False, msg, 2

    # ── 3) hash chain ───────────────────────────────────
    ok, msg = verify_audit_chain(str(ap))
    if not ok:
        return False, f"❌ CHAIN BROKEN: {msg}", 1

    # ── 4) entry count / head match ─────────────────────
    if count != anchor["entry_count"]:
        return False, f"🚨 TRUNCATION: chain={count}, anchor={anchor['entry_count']}", 2
    if head != anchor["head_hash"]:
        return (
            False,
            f"🚨 HEAD MISMATCH: chain={head[:16]}..., anchor={anchor['head_hash'][:16]}...",
            2,
        )

    base_ok_msg = (
        f"✅ OK — {count} entries verified, head matches anchor "
        f"({anchor.get('adapter', 'unknown')}, {anchor.get('anchored_iso', '')})"
    )

    # ── 5) GPG signature on ledger ──────────────────────
    sig_path = lp.with_suffix(lp.suffix + ".asc")
    if not sig_path.exists():
        if strict_gpg:
            return False, f"{base_ok_msg}\n❌ GPG signature missing (strict mode): {sig_path}", 5
        return True, f"{base_ok_msg}\n⚠️  ledger not signed (non-strict)", 0

    gpg = GPGSigner()
    if not gpg.is_available():
        if strict_gpg:
            return False, f"{base_ok_msg}\n❌ gpg not available (strict mode)", 4
        return True, f"{base_ok_msg}\n⚠️  gpg not available — cannot verify signature", 0

    sig_ok, sig_msg = gpg.verify_file(sig_path, lp)
    if not sig_ok:
        return False, f"{base_ok_msg}\n🚨 GPG SIGNATURE INVALID: {sig_msg}", 4

    fpr = (anchor.get("fingerprint") or "?")[:16]
    return True, f"{base_ok_msg}\n✅ GPG signature valid ({fpr}...)", 0


def verify(
    audit_path: str,
    ledger_path: str | None = None,
    case_id: str | None = None,
    strict_gpg: bool = False,
) -> tuple[bool, str]:
    ok, msg, _ = _verify_internal(audit_path, ledger_path, case_id, strict_gpg=strict_gpg)
    return ok, msg


def main(
    audit_path: str,
    ledger_path: str,
    case_id: str | None = None,
    strict_gpg: bool = False,
) -> int:
    ok, msg, code = _verify_internal(audit_path, ledger_path, case_id, strict_gpg=strict_gpg)
    print(msg)
    return code


if __name__ == "__main__":
    raw_args = sys.argv[1:]
    strict = "--strict-gpg" in raw_args
    pos_args = [a for a in raw_args if not a.startswith("--")]
    if len(pos_args) < 1:
        print(
            "usage: verify_audit.py <audit.jsonl> [case_id] "
            "[ledger=logs/anchor_ledger.json] [--strict-gpg]",
            file=sys.stderr,
        )
        sys.exit(3)
    audit_arg = pos_args[0]
    case_arg = pos_args[1] if len(pos_args) > 1 else None
    ledger_arg = pos_args[2] if len(pos_args) > 2 else "logs/anchor_ledger.json"
    sys.exit(main(audit_arg, ledger_arg, case_arg, strict_gpg=strict))
