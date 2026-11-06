# core/anchor.py (v1.5 — GPG-signed ledger + signed git tags + S3 WORM Object Lock)
"""External anchoring with GPG signature support and S3 WORM (Object Lock).

Layer 1: anchor_ledger.json.asc  — detached sig over the ledger file
Layer 2: git tag -s / S3 Object Lock — immutable distributed anchor
"""
from __future__ import annotations
import json
import pathlib
import subprocess
import time
from typing import Optional

from core.gpg_signer import GPGError, GPGSigner
from core.s3_client import S3Client, S3Error


# ═══════════════════════════════════════════════════════════
# S3 WORM Adapter
# ═══════════════════════════════════════════════════════════
class S3WormAdapter:
    """Anchors to S3 Object Lock (COMPLIANCE or GOVERNANCE)."""

    def __init__(
        self,
        bucket: str,
        mode: str = "COMPLIANCE",
        retention_days: int = 2555,
        prefix: str = "anchors/",
        s3_client: Optional[S3Client] = None,
        region: str = "us-east-1",
    ):
        if mode not in ("COMPLIANCE", "GOVERNANCE"):
            raise ValueError(f"invalid mode: {mode!r}")
        if retention_days < 1:
            raise ValueError("retention_days must be >= 1")
        self.bucket = bucket
        self.mode = mode
        self.retention_days = retention_days
        self.prefix = prefix
        self.s3 = s3_client or S3Client(region=region)

    def anchor(self, rec: dict, sig_path: Optional[str] = None) -> dict:
        """Upload anchor record (and optionally .asc) with Object Lock.

        Returns dict with: bucket, key, version_id, sha256, retain_until.
        """
        key = f"{self.prefix}{rec['case_id']}/{rec['head_hash'][:16]}.json"

        payload = {"record": rec}
        if sig_path and pathlib.Path(sig_path).exists():
            payload["signature_asc"] = pathlib.Path(sig_path).read_text(encoding="utf-8")
        body = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")

        result = self.s3.put_worm(
            bucket=self.bucket,
            key=key,
            body=body,
            mode=self.mode,
            days=self.retention_days,
        )

        # Immediate read-back verification (defense in depth)
        ok_sha, msg_sha = self.s3.verify_checksum(self.bucket, key, result.sha256)
        if not ok_sha:
            raise S3Error(f"WORM write verification failed: {msg_sha}")

        ok_ret, msg_ret = self.s3.verify_retention(self.bucket, key)
        if not ok_ret:
            raise S3Error(f"retention verification failed: {msg_ret}")

        return {
            "bucket": result.bucket,
            "key": result.key,
            "version_id": result.version_id,
            "sha256": result.sha256,
            "retention_mode": result.retention_mode,
            "retain_until": result.retain_until,
            "adapter": f"s3-worm-{self.mode.lower()}",
        }

    def list_case_anchors(self, case_id: str) -> list[dict]:
        return self.s3.list_locked_objects(
            self.bucket, prefix=f"{self.prefix}{case_id}/"
        )


# ═══════════════════════════════════════════════════════════
# Anchor (v1.5)
# ═══════════════════════════════════════════════════════════
class Anchor:
    def __init__(
        self,
        adapter: str = "git",
        ledger_path: str = "logs/anchor_ledger.json",
        gpg_signer: Optional[GPGSigner] = None,
        **adapter_cfg,
    ):
        self.adapter = adapter
        self.ledger_path = pathlib.Path(ledger_path)
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        if gpg_signer is None and isinstance(adapter_cfg.get("gpg"), dict):
            gcfg = adapter_cfg.pop("gpg")
            if gcfg.get("enabled", False):
                gpg_signer = GPGSigner(
                    key_id=gcfg.get("key_id"),
                    gpg_home=gcfg.get("gpg_home"),
                    strict=gcfg.get("strict", False),
                )
        self.gpg = gpg_signer
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
            "fingerprint": self.gpg.key_fingerprint() if (self.gpg and self.gpg.is_available()) else None,
        }
        self._append_ledger(rec)

        # ── Layer 1: sign the ledger file (sidecar .asc) ──
        sig_info = self._sign_ledger()
        rec.update(sig_info)

        # ── Layer 2: adapter-specific anchoring ──
        handler = getattr(self, f"_anchor_{self.adapter}", None)
        if handler:
            handler(rec)

        return rec

    def _sign_ledger(self) -> dict:
        if self.gpg is None:
            return {
                "signed": False,
                "sig_path": None,
                "fingerprint": None,
                "sign_error": "no signer",
            }
        try:
            sig_path = self.gpg.sign_file(self.ledger_path)
        except GPGError as e:
            if self.gpg.strict:
                raise
            return {
                "signed": False,
                "sig_path": None,
                "fingerprint": None,
                "sign_error": str(e),
            }
        return {
            "signed": sig_path is not None,
            "sig_path": str(sig_path) if sig_path else None,
            "fingerprint": self.gpg.key_fingerprint() if sig_path else None,
            "sign_error": None,
        }

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
            json.dumps(entries, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    # ── adapters ───────────────────────────────────────────
    def _anchor_git(self, rec: dict) -> None:
        try:
            subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                capture_output=True,
                check=True,
                timeout=10,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            return

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
            asc_file = self.ledger_path.with_suffix(self.ledger_path.suffix + ".asc")
            if asc_file.exists():
                subprocess.run(
                    ["git", "add", str(asc_file)],
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
        except subprocess.CalledProcessError:
            pass

        tag = f"anchor/{rec['case_id']}/{rec['head_hash'][:12]}"
        if self.gpg and self.gpg.is_available():
            try:
                self.gpg.sign_git_tag(tag, msg)
                return
            except GPGError:
                if self.gpg.strict:
                    raise
        # fallback annotated (non-strict)
        try:
            subprocess.run(
                ["git", "tag", "-a", "-f", tag, "-m", msg + " [unsigned]"],
                check=True,
                capture_output=True,
                timeout=30,
            )
        except subprocess.CalledProcessError:
            pass

    def _anchor_s3(self, rec: dict) -> None:
        """S3 WORM adapter (v1.5)."""
        worm = S3WormAdapter(
            bucket=self.cfg["bucket"],
            mode=self.cfg.get("mode", "COMPLIANCE"),
            retention_days=self.cfg.get("retention_days", 2555),
            prefix=self.cfg.get("prefix", "anchors/"),
            region=self.cfg.get("region", "us-east-1"),
            s3_client=self.cfg.get("s3_client"),  # for tests / injection
        )
        result = worm.anchor(rec, sig_path=rec.get("sig_path"))
        rec["s3"] = result

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
        sig_path = rec.get("sig_path")
        if sig_path and pathlib.Path(sig_path).exists():
            (target.parent / (target.name + ".asc")).write_text(
                pathlib.Path(sig_path).read_text(encoding="utf-8"), encoding="utf-8"
            )

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

    def verify_ledger_signature(self) -> tuple[bool, str]:
        """Verify anchor_ledger.json.asc against anchor_ledger.json."""
        if self.gpg is None:
            return False, "no signer configured"
        sig = self.ledger_path.with_suffix(self.ledger_path.suffix + ".asc")
        if not sig.exists():
            return False, f"signature missing: {sig}"
        return self.gpg.verify_file(sig, self.ledger_path)


def _read_head(audit_path: pathlib.Path) -> tuple[str, int]:
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
