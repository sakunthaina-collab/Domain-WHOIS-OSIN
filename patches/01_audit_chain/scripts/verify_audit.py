#!/usr/bin/env python3
"""
Tamper-Evident Audit Log Verifier (Hash Chain Verification)
Validates cryptographic integrity and sequence across every entry in audit.jsonl.
"""
from __future__ import annotations
import hashlib
import json
import pathlib
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def verify(log_path: str | pathlib.Path) -> tuple[bool, str]:
    path = pathlib.Path(log_path)
    if not path.exists():
        return False, f"Audit log file not found: {path}"
    if path.stat().st_size == 0:
        return True, "Audit log is empty (0 entries, valid genesis state)"

    prev = "0" * 64
    line_no = 0

    with path.open("r", encoding="utf-8") as f:
        for raw_line in f:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            line_no += 1
            try:
                rec = json.loads(raw_line)
            except Exception as e:
                return False, f"line {line_no}: invalid JSON syntax ({e})"

            if "prev_hash" not in rec or "entry_hash" not in rec:
                return False, f"line {line_no}: missing hash chain headers"

            if rec["prev_hash"] != prev:
                return (
                    False,
                    f"line {line_no}: prev_hash mismatch (found {rec['prev_hash'][:12]}..., expected {prev[:12]}...)",
                )

            stored_hash = rec.pop("entry_hash")
            expected_payload = json.dumps(rec, sort_keys=True, ensure_ascii=False) + prev
            expected_hash = hashlib.sha256(expected_payload.encode("utf-8")).hexdigest()

            if stored_hash != expected_hash:
                return (
                    False,
                    f"line {line_no}: entry_hash tampered (stored {stored_hash[:12]}... != computed {expected_hash[:12]}...)",
                )

            prev = stored_hash

    return True, f"OK - {line_no} audit entries cryptographically verified (Chain unbroken)"


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "logs/audit.jsonl"
    ok, msg = verify(target)
    print(("[PASS] " if ok else "[FAIL] ") + msg)
    sys.exit(0 if ok else 1)
