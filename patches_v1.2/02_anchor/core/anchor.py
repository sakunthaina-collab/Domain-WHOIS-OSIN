# core/anchor.py
"""External anchoring of audit-chain head hashes.

Adapters:
  • git   (default, zero-dependency, works offline/air-gapped)
  • s3    (S3 Object Lock / WORM bucket)
  • http  (generic webhook endpoint)
  • file  (copy to designated path, e.g. network share)

Usage:
    anchor = Anchor(adapter="git", ledger_path="logs/anchor_ledger.json")
    anchor.anchor(case_id="CASE-001", audit_path="logs/audit.jsonl")
"""
from __future__ import annotations
import json
import pathlib
import subprocess
import time
from typing import Optional


class Anchor:
    def __init__(
        self,
        adapter: str = "git",
        ledger_path: str = "logs/anchor_ledger.json",
        **adapter_cfg,
    ):
        self.adapter = adapter
        self.ledger_path = pathlib.Path(ledger_path)
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self.cfg = adapter_cfg

    def anchor(self, case_id: str, audit_path: str) -> dict:
        audit_path_obj = pathlib.Path(audit_path)
        head, count = _read_head(audit_path_obj)
        if count == 0:
            raise ValueError(f"cannot anchor empty audit log: {audit_path}")

        rec = {
            "case_id": case_id,
            "head_hash": head,
            "entry_count": count,
            "anchored_at": time.time(),
            "anchored_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "adapter": self.adapter,
        }
        self._append_ledger(rec)
        handler = getattr(self, f"_anchor_{self.adapter}", None)
        if handler:
            handler(rec)
        return rec

    # ── ledger ─────────────────────────────────────────────
    def _append_ledger(self, rec: dict) -> None:
        entries = []
        if self.ledger_path.exists():
            try:
                entries = json.loads(self.ledger_path.read_text(encoding="utf-8"))
            except Exception:
                entries = []
        entries.append(rec)
        self.ledger_path.write_text(
            json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    # ── adapters ───────────────────────────────────────────
    def _anchor_git(self, rec: dict) -> None:
        """Commit ledger + annotated tag. Skips silently if not a git repo."""
        try:
            subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                capture_output=True,
                check=True,
                timeout=10,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            return  # not a repo → local-only anchor
        msg = (
            f"audit-anchor: case={rec['case_id']} "
            f"n={rec['entry_count']} head={rec['head_hash'][:16]}"
        )
        try:
            subprocess.run(
                ["git", "add", str(self.ledger_path)],
                check=True,
                capture_output=True,
                timeout=30,
            )
            subprocess.run(
                ["git", "commit", "-m", msg, "--allow-empty"],
                check=True,
                capture_output=True,
                timeout=30,
            )
            tag = f"anchor/{rec['case_id']}/{rec['head_hash'][:12]}"
            subprocess.run(
                ["git", "tag", "-a", tag, "-m", msg],
                check=True,
                capture_output=True,
                timeout=30,
            )
        except subprocess.CalledProcessError:
            pass  # commit/tag might fail if no user config; ledger still written

    def _anchor_s3(self, rec: dict) -> None:
        import boto3
        bucket = self.cfg["bucket"]
        key = f"anchors/{rec['case_id']}/{rec['head_hash'][:16]}.json"
        boto3.client("s3").put_object(
            Bucket=bucket,
            Key=key,
            Body=json.dumps(rec).encode("utf-8"),
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 365 * 86400)
            ),
        )

    def _anchor_http(self, rec: dict) -> None:
        import urllib.request
        req = urllib.request.Request(
            self.cfg["url"],
            data=json.dumps(rec).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=30).read()

    def _anchor_file(self, rec: dict) -> None:
        target = pathlib.Path(self.cfg.get("path", "anchors")) / f"{rec['case_id']}.anchor.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")

    # ── read side ──────────────────────────────────────────
    def last_anchor(self, case_id: str) -> Optional[dict]:
        if not self.ledger_path.exists():
            return None
        try:
            entries = json.loads(self.ledger_path.read_text(encoding="utf-8"))
        except Exception:
            return None
        matching = [e for e in entries if e.get("case_id") == case_id]
        return matching[-1] if matching else None


def _read_head(audit_path: pathlib.Path) -> tuple[str, int]:
    """Return (head_hash, entry_count) from audit chain."""
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
