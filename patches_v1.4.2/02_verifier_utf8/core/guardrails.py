# core/guardrails.py (v1.4.2 — safe JSONL write + UTF-8/BOM-resilient verifier)
"""Tamper-evident, race-safe, Unicode-safe hash-chain audit logger.

v1.4.1 fixes:
  FIND-03: Unicode line separators (U+0085, U+2028, U+2029) are escaped
           before writing JSONL.
v1.4.2 fixes:
  FIND-08: verify_audit_chain uses encoding="utf-8-sig" (strips BOM) and
           catches UnicodeDecodeError cleanly without crashing.
"""
from __future__ import annotations
import hashlib
import json
import os
import pathlib
import time
from typing import Any, Optional

from core.file_lock import file_lock

GENESIS_HASH = "0" * 64

_LINE_SEP_ESCAPES = (
    ("\u0085", "\\u0085"),   # NEL
    ("\u2028", "\\u2028"),   # LINE SEPARATOR
    ("\u2029", "\\u2029"),   # PARAGRAPH SEPARATOR
)


def _safe_json_line(rec: dict) -> str:
    """Serialize to JSON, escaping chars that break JSONL line boundaries."""
    s = json.dumps(rec, ensure_ascii=False)
    for bad, esc in _LINE_SEP_ESCAPES:
        s = s.replace(bad, esc)
    return s


class Guardrails:
    def __init__(
        self,
        log_path: str = "logs/audit.jsonl",
        case_id: Optional[str] = None,
        artifacts_root: str = "artifacts",
    ):
        self.log_path = pathlib.Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        self.case_id = case_id
        self.case_audit_path: Optional[pathlib.Path] = None
        if case_id:
            root = pathlib.Path(artifacts_root).resolve()
            p = (pathlib.Path(artifacts_root) / case_id / "audit.jsonl").resolve()
            try:
                p.relative_to(root)
            except ValueError:
                raise ValueError(f"Path traversal detected in case_id: {case_id}")
            if ".." in case_id:
                raise ValueError(f"Path traversal detected in case_id: {case_id}")
            p.parent.mkdir(parents=True, exist_ok=True)
            self.case_audit_path = p

        self._last_global = self._read_last_hash_unlocked(self.log_path)
        self._last_case = (
            self._read_last_hash_unlocked(self.case_audit_path)
            if self.case_audit_path
            else GENESIS_HASH
        )

    def allow(self, skill, args: dict, profile: Any) -> bool:
        if hasattr(profile, "get"):
            g = profile.get("guardrails", {}) or {}
        elif hasattr(profile, "guardrails"):
            g = profile.guardrails or {}
        else:
            g = {}

        if skill.name in g.get("deny_actions", []):
            return False
        if skill.name in g.get("require_confirm", []):
            if not args.get("_confirmed"):
                return False
        if skill.risk == "high" and not g.get("allow_high_risk"):
            return False
        if args.get("passive_only") is False and g.get("passive_only_required", True):
            return False
        return True

    def audit(
        self,
        skill,
        args: dict,
        step: int,
        case_id: Optional[str] = None,
        result: Optional[Any] = None,
        status: str = "ok",
        latency_ms: float = 0,
        parent_step: Optional[int] = None,
        dry_run: bool = False,
    ) -> dict:
        case_id = case_id or self.case_id or "unknown"
        base = {
            "ts": time.time(),
            "iso_ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "case": case_id,
            "step": step,
            "parent_step": parent_step,
            "skill": skill.name,
            "category": getattr(skill, "category", "unknown"),
            "risk": getattr(skill, "risk", "low"),
            "args_sha256": _sha(args),
            "result_sha256": _sha(result) if result is not None else None,
            "result_summary": self._summarize(result),
            "status": "dry_run" if dry_run else status,
            "latency_ms": round(latency_ms, 2),
        }
        rec_global = self._append_chain(self.log_path, base)
        if self.case_audit_path is not None:
            self._append_chain(self.case_audit_path, base)
        return rec_global

    def _append_chain(self, path: pathlib.Path, base: dict) -> dict:
        with file_lock(path) as f:
            prev = _read_last_hash_from_file(f)
            rec = {**base, "prev_hash": prev}
            rec["entry_hash"] = hashlib.sha256(
                (json.dumps(rec, sort_keys=True, ensure_ascii=False, default=str) + prev).encode("utf-8")
            ).hexdigest()
            f.seek(0, 2)
            f.write((_safe_json_line(rec) + "\n").encode("utf-8"))
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
            return rec

    @staticmethod
    def _read_last_hash_unlocked(path: Optional[pathlib.Path]) -> str:
        if not path or not path.exists():
            return GENESIS_HASH
        try:
            if path.stat().st_size == 0:
                return GENESIS_HASH
            with path.open("rb") as f:
                return _read_last_hash_from_file(f)
        except (OSError, PermissionError):
            return GENESIS_HASH

    @staticmethod
    def _summarize(result: Any) -> Optional[dict]:
        if result is None:
            return None
        if isinstance(result, dict):
            out = {}
            for k, v in list(result.items())[:6]:
                if isinstance(v, (int, float, bool)) or v is None:
                    out[k] = v
                elif isinstance(v, str):
                    out[k] = v[:80]
                elif isinstance(v, (list, dict)):
                    out[k] = f"<{type(v).__name__} len={len(v)}>"
                else:
                    out[k] = str(v)[:80]
            return out
        return {"value": str(result)[:200]}


def _sha(obj: Any) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, default=str).encode()
    ).hexdigest()


def _read_last_hash_from_file(f) -> str:
    f.seek(0, 2)
    size = f.tell()
    if size == 0:
        return GENESIS_HASH
    f.seek(max(0, size - 8192))
    tail = f.read().decode("utf-8", errors="replace").strip().split("\n")
    for line in reversed(tail):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict) and isinstance(obj.get("entry_hash"), str):
                return obj["entry_hash"]
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
    return GENESIS_HASH


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
                if not isinstance(rec, dict):
                    return False, f"line {n}: JSON record must be object, got {type(rec).__name__}"
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
