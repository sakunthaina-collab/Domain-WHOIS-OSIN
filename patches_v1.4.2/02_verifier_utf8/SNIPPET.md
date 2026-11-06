# Snippet: `verify_audit_chain` in `core/guardrails.py` (FIND-08)

```python
def verify_audit_chain(log_path: str) -> tuple[bool, str]:
    path = pathlib.Path(log_path)
    if not path.exists():
        return True, "log file not found (nothing to verify)"
    prev = GENESIS_HASH
    n = 0
    try:
        # encoding="utf-8-sig" strips BOM if present (FIND-08)
        with path.open(encoding="utf-8-sig") as f:
            for n, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as e:
                    return False, f"line {n}: invalid JSON ({e})"
                if rec.get("prev_hash") != prev:
                    return False, f"line {n}: prev_hash mismatch (chain broken)"
                stored = rec.pop("entry_hash", None)
                if not stored:
                    return False, f"line {n}: missing entry_hash"
                expected = hashlib.sha256(
                    (json.dumps(rec, sort_keys=True, ensure_ascii=False, default=str) + prev).encode("utf-8")
                ).hexdigest()
                if stored != expected:
                    return False, f"line {n}: entry_hash mismatch (tampered)"
                prev = stored
    except UnicodeDecodeError as e:
        return False, f"line {n}: invalid UTF-8 encoding ({e})"
    return True, f"OK - {n} audit entries cryptographically verified (Chain unbroken)"
```
