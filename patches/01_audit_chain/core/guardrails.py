"""Guardrails with tamper-evident hash chain (v1.1)"""
import json, hashlib, time, pathlib
from typing import Any, Optional

GENESIS_HASH = "0" * 64


class Guardrails:
    def __init__(self, log_path: str = "logs/audit.jsonl"):
        self.log_path = pathlib.Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return GENESIS_HASH
        with self.log_path.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 8192))
            tail = f.read().decode("utf-8").strip().split("\n")
        if not tail or not tail[-1]:
            return GENESIS_HASH
        try:
            return json.loads(tail[-1])["entry_hash"]
        except (json.JSONDecodeError, KeyError):
            return GENESIS_HASH

    # ── permission gate ────────────────────────────────────
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

    # ── audit with hash chain ──────────────────────────────
    def audit(
        self, skill, args: dict, step: int, case_id: str,
        result: Optional[Any] = None, status: str = "ok",
        latency_ms: float = 0, parent_step: Optional[int] = None,
        dry_run: bool = False,
    ) -> dict:
        rec = {
            "ts": time.time(),
            "iso_ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "case": case_id,
            "step": step,
            "parent_step": parent_step,
            "skill": skill.name,
            "category": getattr(skill, "category", "unknown"),
            "risk": skill.risk,
            "args_sha256": hashlib.sha256(
                json.dumps(args, sort_keys=True, default=str).encode()
            ).hexdigest(),
            "result_sha256": (
                hashlib.sha256(
                    json.dumps(result, sort_keys=True, default=str).encode()
                ).hexdigest() if result is not None else None
            ),
            "result_summary": self._summarize(result),
            "status": "dry_run" if dry_run else status,
            "latency_ms": round(latency_ms, 2),
            "prev_hash": self._last_hash,
        }
        rec["entry_hash"] = hashlib.sha256(
            (json.dumps(rec, sort_keys=True, default=str) + self._last_hash).encode()
        ).hexdigest()
        self._last_hash = rec["entry_hash"]
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return rec

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


# ── standalone verifier (ใช้ได้ทั้งจาก CLI และ import) ──
def verify_audit_chain(log_path: str) -> tuple[bool, str]:
    prev = GENESIS_HASH
    line_no = 0
    path = pathlib.Path(log_path)
    if not path.exists():
        return True, "log file not found (nothing to verify)"
    with path.open(encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                return False, f"line {line_no}: invalid JSON ({e})"
            if rec.get("prev_hash") != prev:
                return False, f"line {line_no}: prev_hash mismatch (chain broken)"
            stored = rec.pop("entry_hash", None)
            if not stored:
                return False, f"line {line_no}: missing entry_hash"
            expected = hashlib.sha256(
                (json.dumps(rec, sort_keys=True, default=str) + prev).encode()
            ).hexdigest()
            if stored != expected:
                return False, f"line {line_no}: entry_hash mismatch (tampered)"
            prev = stored
    return True, f"OK — {line_no} entries verified"
